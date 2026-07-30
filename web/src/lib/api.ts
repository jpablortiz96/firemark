import { SafeApiError } from "@/lib/errors";
import type {
  CertificateLookup,
  PublicCertificate,
  SafeErrorPayload,
  VerificationRequest,
  VerificationResult,
} from "@/lib/types";
import {
  containsPrivatePublicField,
  isCertificateId,
  isSha256,
  safeHttpUrl,
} from "@/lib/validation";

const REQUEST_TIMEOUT_MS = 8_000;
const CERTIFICATE_STATUSES = new Set(["active", "revoked", "invalid"]);
const VERIFICATION_STATUSES = new Set([
  "verified",
  "hash_mismatch",
  "signature_invalid",
  "certificate_revoked",
  "certificate_not_found",
  "malformed_evidence",
]);

function apiBaseUrl(): string {
  const configured = process.env.NEXT_PUBLIC_FIREMARK_API_BASE_URL ?? "http://127.0.0.1:8000";
  const normalized = safeHttpUrl(configured);
  if (!normalized) {
    throw new SafeApiError("configuration", "API_BASE_URL_INVALID");
  }
  return normalized.replace(/\/$/, "");
}

async function fetchWithTimeout(
  path: string,
  init?: RequestInit,
  externalSignal?: AbortSignal,
): Promise<Response> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  if (externalSignal?.aborted) controller.abort();
  externalSignal?.addEventListener("abort", cancel, { once: true });
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(`${apiBaseUrl()}${path}`, {
      ...init,
      headers: { Accept: "application/json", ...init?.headers },
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new SafeApiError("timeout", "REQUEST_TIMEOUT");
    }
    throw new SafeApiError("network", "NETWORK_FAILURE");
  } finally {
    clearTimeout(timeout);
    externalSignal?.removeEventListener("abort", cancel);
  }
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

async function safeErrorCode(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as SafeErrorPayload;
    return typeof body.error?.code === "string" ? body.error.code : "SAFE_BACKEND_ERROR";
  } catch {
    return "SAFE_BACKEND_ERROR";
  }
}

function parseCertificate(value: unknown): PublicCertificate {
  const body = objectValue(value);
  const manifest = objectValue(body?.public_manifest);
  const verifyUrl = safeHttpUrl(body?.verify_url);
  if (
    !body ||
    body.schema_version !== "1.0" ||
    !isCertificateId(String(body.cert_id ?? "")) ||
    !isCertificateId(String(body.asset_id ?? "")) ||
    !isCertificateId(String(body.run_id ?? "")) ||
    typeof body.provider !== "string" ||
    typeof body.model !== "string" ||
    !["image", "audio"].includes(String(body.media_type)) ||
    typeof body.mime_type !== "string" ||
    typeof body.byte_size !== "number" ||
    body.byte_size <= 0 ||
    typeof body.ai_generated !== "boolean" ||
    (body.width !== null && (typeof body.width !== "number" || body.width <= 0)) ||
    (body.height !== null && (typeof body.height !== "number" || body.height <= 0)) ||
    (body.duration_ms !== null &&
      (typeof body.duration_ms !== "number" || body.duration_ms <= 0)) ||
    !isSha256(String(body.source_sha256 ?? "")) ||
    !isSha256(String(body.sealed_sha256 ?? "")) ||
    !isSha256(String(body.canonical_hash ?? "")) ||
    typeof body.signer_key_id !== "string" ||
    typeof body.signer_public_key_b64 !== "string" ||
    typeof body.signature_b64 !== "string" ||
    typeof body.issued_at !== "string" ||
    !CERTIFICATE_STATUSES.has(String(body.certificate_status)) ||
    !manifest ||
    containsPrivatePublicField(manifest) ||
    !verifyUrl
  ) {
    throw new SafeApiError("malformed", "MALFORMED_CERTIFICATE_RESPONSE");
  }
  return {
    schema_version: "1.0",
    cert_id: String(body.cert_id),
    asset_id: String(body.asset_id),
    run_id: String(body.run_id),
    provider: body.provider,
    model: body.model,
    media_type: body.media_type as PublicCertificate["media_type"],
    mime_type: body.mime_type,
    byte_size: body.byte_size,
    ai_generated: body.ai_generated,
    width: body.width as number | null,
    height: body.height as number | null,
    duration_ms: body.duration_ms as number | null,
    source_sha256: String(body.source_sha256),
    sealed_sha256: String(body.sealed_sha256),
    canonical_hash: String(body.canonical_hash),
    signer_key_id: body.signer_key_id,
    signer_public_key_b64: body.signer_public_key_b64,
    signature_b64: body.signature_b64,
    public_manifest: manifest,
    certificate_status: body.certificate_status as PublicCertificate["certificate_status"],
    issued_at: body.issued_at,
    verify_url: verifyUrl,
  };
}

function parseVerification(value: unknown): VerificationResult {
  const body = objectValue(value);
  if (
    !body ||
    !isCertificateId(String(body.cert_id ?? "")) ||
    typeof body.verification_event_id !== "string" ||
    (body.media_type !== null && !["image", "audio"].includes(String(body.media_type))) ||
    (body.mime_type !== null && typeof body.mime_type !== "string") ||
    (body.provider !== null && typeof body.provider !== "string") ||
    (body.model !== null && typeof body.model !== "string") ||
    !VERIFICATION_STATUSES.has(String(body.status)) ||
    typeof body.verified !== "boolean" ||
    typeof body.signature_valid !== "boolean" ||
    typeof body.envelope_valid !== "boolean" ||
    (body.hash_match !== null && typeof body.hash_match !== "boolean") ||
    typeof body.custody_reference_valid !== "boolean" ||
    typeof body.safe_reason_code !== "string" ||
    typeof body.verified_at !== "string"
  ) {
    throw new SafeApiError("malformed", "MALFORMED_VERIFICATION_RESPONSE");
  }
  return body as unknown as VerificationResult;
}

export async function getCertificate(certId: string): Promise<CertificateLookup> {
  if (!isCertificateId(certId)) {
    return { state: "not_found" };
  }
  try {
    const response = await fetchWithTimeout(`/v1/certificates/${encodeURIComponent(certId)}`, {
      cache: "no-store",
    });
    if (response.status === 404) return { state: "not_found" };
    if (response.status === 410) return { state: "revoked" };
    if (!response.ok) return { state: "error" };
    return { state: "found", certificate: parseCertificate(await response.json()) };
  } catch {
    return { state: "error" };
  }
}

export async function verifyCertificate(
  request: VerificationRequest,
  signal?: AbortSignal,
): Promise<VerificationResult> {
  if (!isCertificateId(request.cert_id)) {
    throw new SafeApiError("malformed", "CERTIFICATE_ID_INVALID");
  }
  if (request.presented_sha256 && !isSha256(request.presented_sha256)) {
    throw new SafeApiError("malformed", "SHA256_INVALID");
  }
  const response = await fetchWithTimeout(
    "/v1/verify",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    },
    signal,
  );
  if (!response.ok) {
    const code = await safeErrorCode(response);
    throw new SafeApiError(response.status === 422 ? "malformed" : "unavailable", code);
  }
  return parseVerification(await response.json());
}
