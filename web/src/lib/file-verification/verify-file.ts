import { verifyCertificate } from "@/lib/api";
import { LensVerificationError } from "@/lib/file-verification/errors";
import { sha256Hex } from "@/lib/file-verification/hash";
import { extractPublicCapsulePng } from "@/lib/file-verification/png";
import type {
  FiremarkPublicCapsuleV1,
  LayerStatus,
  LensResult,
  VerificationLayer,
  VerificationProgress,
} from "@/lib/file-verification/types";
import { MAX_FILE_BYTES } from "@/lib/file-verification/types";
import type { VerificationRequest, VerificationResult } from "@/lib/types";
import { isCertificateId } from "@/lib/validation";

const LAYER_LABELS = {
  file_format: "File format",
  public_capsule: "Embedded FIREMARK capsule",
  sealed_hash: "Sealed file hash",
  certificate_found: "Certificate found",
  signature: "Ed25519 signature",
  certificate_status: "Certificate status",
  custody_reference: "B2 custody reference",
  delivery_eligibility: "Delivery eligibility",
} as const;

type VerifyFunction = (
  request: VerificationRequest,
  signal?: AbortSignal,
) => Promise<VerificationResult>;

export function layers(statuses: Partial<Record<keyof typeof LAYER_LABELS, LayerStatus>>): VerificationLayer[] {
  return Object.entries(LAYER_LABELS).map(([key, label]) => ({
    key: key as keyof typeof LAYER_LABELS,
    label,
    status: statuses[key as keyof typeof LAYER_LABELS] ?? "NOT CHECKED",
  }));
}

function localFailure(file: File, error: LensVerificationError): LensResult {
  const state =
    error.kind === "no_capsule"
      ? "no_capsule"
      : error.kind === "malformed_capsule"
        ? "malformed_capsule"
        : "invalid_file";
  return {
    state,
    fileName: file.name,
    fileSize: file.size,
    mediaType: "image",
    mimeType: "image/png",
    layers: layers({
      file_format: error.kind === "no_capsule" || error.kind === "malformed_capsule" ? "PASS" : "FAIL",
      public_capsule: error.kind === "no_capsule" || error.kind === "malformed_capsule" ? "FAIL" : "NOT CHECKED",
    }),
  };
}

export function backendLayers(
  result: VerificationResult,
  capsuleStatus: LayerStatus = "PASS",
): VerificationLayer[] {
  const found = result.status !== "certificate_not_found";
  const statusChecked = !["certificate_not_found", "malformed_evidence"].includes(result.status);
  return layers({
    file_format: "PASS",
    public_capsule: capsuleStatus,
    sealed_hash: result.hash_match === null ? "NOT CHECKED" : result.hash_match ? "PASS" : "FAIL",
    certificate_found: found ? "PASS" : "FAIL",
    signature: found ? (result.signature_valid ? "PASS" : "FAIL") : "NOT CHECKED",
    certificate_status: statusChecked
      ? result.status === "certificate_revoked"
        ? "FAIL"
        : "PASS"
      : "NOT CHECKED",
    custody_reference: found
      ? result.custody_reference_valid
        ? "PASS"
        : "FAIL"
      : "NOT CHECKED",
    delivery_eligibility: result.verified ? "PASS" : "FAIL",
  });
}

export function resultState(result: VerificationResult): LensResult["state"] {
  if (result.status === "verified") return "verified";
  if (result.status === "hash_mismatch") return "tampered";
  if (result.status === "certificate_revoked") return "revoked";
  if (result.status === "certificate_not_found") return "not_found";
  return "unverified";
}

export async function verifyLocalPng(
  file: File,
  options: {
    signal?: AbortSignal;
    onProgress?: (progress: VerificationProgress) => void;
    verify?: VerifyFunction;
  } = {},
): Promise<LensResult> {
  const { signal, onProgress, verify = verifyCertificate } = options;
  const fail = (code: LensVerificationError["code"], kind: LensVerificationError["kind"]) =>
    localFailure(file, new LensVerificationError(code, kind));
  if (file.type !== "image/png") return fail("FILE_TYPE_INVALID", "file");
  if (!file.name.toLowerCase().endsWith(".png")) return fail("FILE_EXTENSION_INVALID", "file");
  if (file.size > MAX_FILE_BYTES) return fail("FILE_TOO_LARGE", "file");

  let capsule: FiremarkPublicCapsuleV1 | undefined;
  let sealedSha256: string | undefined;
  try {
    onProgress?.({ phase: "reading", percent: 10 });
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (signal?.aborted) throw new DOMException("Operation aborted", "AbortError");
    onProgress?.({ phase: "capsule", percent: 35 });
    capsule = extractPublicCapsulePng(bytes);
    if (!isCertificateId(capsule.cert_id)) {
      return fail("CAPSULE_IDENTIFIER_INVALID", "malformed_capsule");
    }
    onProgress?.({ phase: "hashing", percent: 55 });
    sealedSha256 = await sha256Hex(bytes, signal);
    onProgress?.({ phase: "verifying", percent: 80 });
    const verification = await verify(
      { cert_id: capsule.cert_id, presented_sha256: sealedSha256 },
      signal,
    );
    if (verification.cert_id !== capsule.cert_id || verification.media_type !== "image") {
      throw new Error("VERIFICATION_CERTIFICATE_MISMATCH");
    }
    if (signal?.aborted) throw new DOMException("Operation aborted", "AbortError");
    onProgress?.({ phase: "complete", percent: 100 });
    return {
      state: resultState(verification),
      fileName: file.name,
      fileSize: file.size,
      mediaType: "image",
      mimeType: "image/png",
      certId: capsule.cert_id,
      capsule,
      sealedSha256,
      verification,
      layers: backendLayers(verification),
    };
  } catch (error) {
    if (signal?.aborted) throw new DOMException("Operation aborted", "AbortError");
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    if (error instanceof LensVerificationError) {
      if (error.kind !== "hash") return localFailure(file, error);
    }
    return {
      state: "unavailable",
      fileName: file.name,
      fileSize: file.size,
      mediaType: "image",
      mimeType: "image/png",
      capsule,
      sealedSha256,
      layers: layers({
        file_format: "PASS",
        public_capsule: capsule ? "PASS" : "NOT CHECKED",
      }),
    };
  }
}
