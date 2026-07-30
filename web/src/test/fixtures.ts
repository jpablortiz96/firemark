import type { PublicCertificate, VerificationResult } from "@/lib/types";

export const CERT_ID = "fm-cert-test-1";
export const SEALED_SHA = "a".repeat(64);
export const CANONICAL_HASH = "b".repeat(64);

export const certificateFixture: PublicCertificate = {
  schema_version: "1.0",
  cert_id: CERT_ID,
  asset_id: "fm-asset-test-1",
  run_id: "fm-run-test-1",
  sealed_sha256: SEALED_SHA,
  canonical_hash: CANONICAL_HASH,
  signer_key_id: "ed25519:test-signer",
  signer_public_key_b64: "cHVibGljLWtleS10ZXN0",
  signature_b64: "c2lnbmF0dXJlLXRlc3Q",
  public_manifest: {
    schema_version: "firemark.public-capsule.v1",
    source_sha256: "c".repeat(64),
    cert_id: CERT_ID,
  },
  certificate_status: "active",
  issued_at: "2026-07-30T12:00:00Z",
  verify_url: `https://api.firemark.test/v1/certificates/${CERT_ID}`,
};

export function verificationFixture(
  status: VerificationResult["status"] = "verified",
): VerificationResult {
  const verified = status === "verified";
  return {
    verification_event_id: "00000000-0000-4000-8000-000000000001",
    cert_id: CERT_ID,
    status,
    verified,
    signature_valid: verified,
    envelope_valid: verified,
    hash_match: status === "hash_mismatch" ? false : verified ? true : null,
    custody_reference_valid: verified,
    safe_reason_code: status.toUpperCase(),
    verified_at: "2026-07-30T12:01:00Z",
  };
}
