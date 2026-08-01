import { getCertificate, verifyCertificate } from "@/lib/api";
import { sha256Hex } from "@/lib/file-verification/hash";
import { resultState } from "@/lib/file-verification/verify-file";
import type {
  AudioLayerKey,
  LayerStatus,
  LensResult,
  VerificationLayer,
  VerificationProgress,
} from "@/lib/file-verification/types";
import {
  AUDIO_MIME_ALIASES,
  CANONICAL_AUDIO_MIME_TYPE,
  MAX_AUDIO_FILE_BYTES,
} from "@/lib/file-verification/types";
import type { CertificateLookup, VerificationRequest, VerificationResult } from "@/lib/types";
import { isCertificateId, isSha256 } from "@/lib/validation";

export { MAX_AUDIO_FILE_BYTES } from "@/lib/file-verification/types";

const AUDIO_LAYER_LABELS: Record<AudioLayerKey, string> = {
  local_processing: "Local processing",
  mp3_format: "MP3 format",
  public_certificate: "Public certificate",
  media_contract: "Media contract",
  byte_preserving_seal: "Byte-preserving seal",
  local_file_hash: "Local file hash",
  cryptographic_verification: "Cryptographic verification",
};

const AUDIO_LAYER_ORDER = Object.keys(AUDIO_LAYER_LABELS) as AudioLayerKey[];

type VerifyFunction = (
  request: VerificationRequest,
  signal?: AbortSignal,
) => Promise<VerificationResult>;
type CertificateFunction = (certId: string) => Promise<CertificateLookup>;

type LayerSpec = Partial<Record<AudioLayerKey, { status: LayerStatus; detail?: string }>>;

export function audioLayers(spec: LayerSpec): VerificationLayer[] {
  return AUDIO_LAYER_ORDER.map((key) => ({
    key,
    label: AUDIO_LAYER_LABELS[key],
    status: spec[key]?.status ?? "NOT CHECKED",
    detail: spec[key]?.detail,
  }));
}

/**
 * Accept a file the browser may label inconsistently. The byte check below is
 * the authority; this only avoids obviously wrong selections early.
 */
export function isAudioMimeAlias(mimeType: string): boolean {
  return (AUDIO_MIME_ALIASES as readonly string[]).includes(mimeType.toLowerCase());
}

/** Validate MP3 structure from the bytes themselves, never from the browser MIME. */
export function looksLikeMp3(bytes: Uint8Array): boolean {
  if (bytes.length >= 3 && bytes[0] === 0x49 && bytes[1] === 0x44 && bytes[2] === 0x33) {
    return true; // ID3v2 tag
  }
  // MPEG audio frame sync: eleven set bits, with a defined layer and bitrate.
  for (let index = 0; index + 1 < Math.min(bytes.length, 8192); index += 1) {
    if (bytes[index] !== 0xff || (bytes[index + 1] & 0xe0) !== 0xe0) continue;
    const layer = (bytes[index + 1] >> 1) & 0x03;
    const version = (bytes[index + 1] >> 3) & 0x03;
    if (layer === 0 || version === 1) continue; // reserved layer / version
    if (index + 2 >= bytes.length) return false;
    const bitrate = (bytes[index + 2] >> 4) & 0x0f;
    if (bitrate === 0x0f) continue; // bad bitrate index
    return true;
  }
  return false;
}

function base(file: File, certId: string): Pick<
  LensResult,
  "fileName" | "fileSize" | "mediaType" | "mimeType" | "certId"
> {
  return {
    fileName: file.name,
    fileSize: file.size,
    mediaType: "audio",
    mimeType: CANONICAL_AUDIO_MIME_TYPE,
    certId,
  };
}

/**
 * Verify a locally selected MP3 against its public FIREMARK certificate.
 *
 * The file bytes are read and hashed in browser memory only. Nothing beyond the
 * certificate ID and the locally computed SHA-256 is ever sent.
 */
export async function verifyLocalAudio(
  file: File,
  certId: string,
  options: {
    signal?: AbortSignal;
    onProgress?: (progress: VerificationProgress) => void;
    verify?: VerifyFunction;
    lookup?: CertificateFunction;
  } = {},
): Promise<LensResult> {
  const {
    signal,
    onProgress,
    verify = verifyCertificate,
    lookup = getCertificate,
  } = options;
  const normalizedCertId = certId.trim();
  const identity = base(file, normalizedCertId);

  if (!isCertificateId(normalizedCertId)) {
    return {
      ...identity,
      state: "invalid_file",
      layers: audioLayers({
        local_processing: { status: "PASS", detail: "file bytes remained on this device" },
        mp3_format: { status: "NOT CHECKED" },
        public_certificate: { status: "FAIL", detail: "a valid certificate ID is required" },
      }),
    };
  }

  const rejectFile = (detail: string): LensResult => ({
    ...identity,
    state: "invalid_file",
    layers: audioLayers({
      local_processing: { status: "PASS", detail: "file bytes remained on this device" },
      mp3_format: { status: "FAIL", detail },
    }),
  });

  if (file.type && !isAudioMimeAlias(file.type)) {
    return rejectFile("an MP3 file is expected");
  }
  if (file.size > MAX_AUDIO_FILE_BYTES) {
    return rejectFile("the file exceeds the 50 MiB local limit");
  }
  if (file.size === 0) return rejectFile("the file is empty");

  try {
    onProgress?.({ phase: "reading", percent: 12 });
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (signal?.aborted) throw new DOMException("Operation aborted", "AbortError");
    if (!looksLikeMp3(bytes)) return rejectFile("no MP3 structure was found in the bytes");

    onProgress?.({ phase: "hashing", percent: 45 });
    const localSha256 = await sha256Hex(bytes, signal);
    if (signal?.aborted) throw new DOMException("Operation aborted", "AbortError");

    const passedLocally: LayerSpec = {
      local_processing: { status: "PASS", detail: "file bytes remained on this device" },
      mp3_format: { status: "PASS", detail: "valid MP3 structure detected" },
    };

    onProgress?.({ phase: "verifying", percent: 65 });
    const found = await lookup(normalizedCertId);
    if (signal?.aborted) throw new DOMException("Operation aborted", "AbortError");
    if (found.state !== "found") {
      return {
        ...identity,
        state: found.state === "revoked" ? "revoked" : found.state === "error" ? "unavailable" : "not_found",
        sealedSha256: localSha256,
        layers: audioLayers({
          ...passedLocally,
          public_certificate: {
            status: "FAIL",
            detail:
              found.state === "revoked"
                ? "this certificate has been revoked"
                : found.state === "error"
                  ? "the certificate could not be retrieved"
                  : "no certificate matches this identifier",
          },
        }),
      };
    }

    const certificate = found.certificate;
    const withCertificate: LayerSpec = {
      ...passedLocally,
      public_certificate: { status: "PASS", detail: "certificate found" },
    };

    if (
      certificate.media_type !== "audio" ||
      certificate.mime_type !== CANONICAL_AUDIO_MIME_TYPE
    ) {
      return {
        ...identity,
        state: "invalid_file",
        sealedSha256: localSha256,
        certificate,
        layers: audioLayers({
          ...withCertificate,
          media_contract: {
            status: "FAIL",
            detail: `this certificate represents ${certificate.media_type} · ${certificate.mime_type}`,
          },
        }),
      };
    }

    const withContract: LayerSpec = {
      ...withCertificate,
      media_contract: { status: "PASS", detail: `certificate represents ${CANONICAL_AUDIO_MIME_TYPE}` },
    };

    if (!isSha256(certificate.source_sha256) || !isSha256(certificate.sealed_sha256)) {
      return {
        ...identity,
        state: "unverified",
        sealedSha256: localSha256,
        certificate,
        layers: audioLayers({
          ...withContract,
          byte_preserving_seal: { status: "FAIL", detail: "the certificate hashes are malformed" },
        }),
      };
    }
    if (certificate.source_sha256 !== certificate.sealed_sha256) {
      return {
        ...identity,
        state: "unverified",
        sealedSha256: localSha256,
        certificate,
        layers: audioLayers({
          ...withContract,
          byte_preserving_seal: {
            status: "FAIL",
            detail: "source and sealed hashes differ, so this is not the byte-preserving MP3 contract",
          },
        }),
      };
    }

    const withSeal: LayerSpec = {
      ...withContract,
      byte_preserving_seal: {
        status: "PASS",
        detail: "source SHA-256 equals sealed SHA-256",
      },
    };

    if (localSha256 !== certificate.sealed_sha256) {
      return {
        ...identity,
        state: "tampered",
        sealedSha256: localSha256,
        certificate,
        layers: audioLayers({
          ...withSeal,
          local_file_hash: {
            status: "FAIL",
            detail: "these bytes do not match the certificate",
          },
        }),
      };
    }

    const withHash: LayerSpec = {
      ...withSeal,
      local_file_hash: { status: "PASS", detail: "local SHA-256 matches the certificate" },
    };

    onProgress?.({ phase: "verifying", percent: 85 });
    const verification = await verify(
      { cert_id: normalizedCertId, presented_sha256: localSha256 },
      signal,
    );
    if (signal?.aborted) throw new DOMException("Operation aborted", "AbortError");
    if (verification.cert_id !== normalizedCertId || verification.media_type !== "audio") {
      throw new Error("CERTIFICATE_MISMATCH");
    }

    onProgress?.({ phase: "complete", percent: 100 });
    return {
      ...identity,
      state: resultState(verification),
      sealedSha256: localSha256,
      certificate,
      verification,
      layers: audioLayers({
        ...withHash,
        cryptographic_verification: {
          status: verification.verified ? "PASS" : "FAIL",
          detail: verification.verified
            ? "public Verify Gate accepted the evidence"
            : "the public Verify Gate did not accept this evidence",
        },
      }),
    };
  } catch (error) {
    if (signal?.aborted || (error instanceof DOMException && error.name === "AbortError")) {
      throw new DOMException("Operation aborted", "AbortError");
    }
    return {
      ...identity,
      state: "unavailable",
      layers: audioLayers({
        local_processing: { status: "PASS", detail: "file bytes remained on this device" },
        mp3_format: { status: "PASS", detail: "valid MP3 structure detected" },
        cryptographic_verification: {
          status: "FAIL",
          detail: "verification is temporarily unavailable",
        },
      }),
    };
  }
}
