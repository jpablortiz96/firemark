import { verifyCertificate } from "@/lib/api";
import { sha256Hex } from "@/lib/file-verification/hash";
import { backendLayers, layers, resultState } from "@/lib/file-verification/verify-file";
import type { LensResult, VerificationProgress } from "@/lib/file-verification/types";
import type { VerificationRequest, VerificationResult } from "@/lib/types";
import { isCertificateId } from "@/lib/validation";

export const MAX_AUDIO_FILE_BYTES = 50 * 1024 * 1024;

type VerifyFunction = (
  request: VerificationRequest,
  signal?: AbortSignal,
) => Promise<VerificationResult>;

function isMp3(bytes: Uint8Array): boolean {
  return (
    (bytes.length >= 3 && bytes[0] === 0x49 && bytes[1] === 0x44 && bytes[2] === 0x33) ||
    (bytes.length >= 2 && bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0)
  );
}

function invalid(file: File, certId: string): LensResult {
  return {
    state: "invalid_file",
    fileName: file.name,
    fileSize: file.size,
    mediaType: "audio",
    mimeType: "audio/mpeg",
    certId,
    layers: layers({ file_format: "FAIL", public_capsule: "NOT CHECKED" }),
  };
}

export async function verifyLocalAudio(
  file: File,
  certId: string,
  options: {
    signal?: AbortSignal;
    onProgress?: (progress: VerificationProgress) => void;
    verify?: VerifyFunction;
  } = {},
): Promise<LensResult> {
  const { signal, onProgress, verify = verifyCertificate } = options;
  const normalizedCertId = certId.trim();
  if (!isCertificateId(normalizedCertId)) return invalid(file, normalizedCertId);
  if (file.type !== "audio/mpeg" || !file.name.toLowerCase().endsWith(".mp3")) {
    return invalid(file, normalizedCertId);
  }
  if (file.size > MAX_AUDIO_FILE_BYTES) return invalid(file, normalizedCertId);
  try {
    onProgress?.({ phase: "reading", percent: 15 });
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (!isMp3(bytes)) return invalid(file, normalizedCertId);
    if (signal?.aborted) throw new DOMException("Operation aborted", "AbortError");
    onProgress?.({ phase: "hashing", percent: 55 });
    const sealedSha256 = await sha256Hex(bytes, signal);
    onProgress?.({ phase: "verifying", percent: 80 });
    const verification = await verify(
      { cert_id: normalizedCertId, presented_sha256: sealedSha256 },
      signal,
    );
    if (verification.cert_id !== normalizedCertId || verification.media_type !== "audio") {
      throw new Error("CERTIFICATE_MISMATCH");
    }
    onProgress?.({ phase: "complete", percent: 100 });
    return {
      state: resultState(verification),
      fileName: file.name,
      fileSize: file.size,
      mediaType: "audio",
      mimeType: "audio/mpeg",
      certId: normalizedCertId,
      sealedSha256,
      verification,
      layers: backendLayers(verification, "NOT CHECKED"),
    };
  } catch (error) {
    if (signal?.aborted || (error instanceof DOMException && error.name === "AbortError")) {
      throw new DOMException("Operation aborted", "AbortError");
    }
    return {
      state: "unavailable",
      fileName: file.name,
      fileSize: file.size,
      mediaType: "audio",
      mimeType: "audio/mpeg",
      certId: normalizedCertId,
      layers: layers({ file_format: "PASS", public_capsule: "NOT CHECKED" }),
    };
  }
}
