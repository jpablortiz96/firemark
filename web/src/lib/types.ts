export type CertificateStatus = "active" | "revoked" | "invalid";

export type VerificationStatus =
  | "verified"
  | "hash_mismatch"
  | "signature_invalid"
  | "certificate_revoked"
  | "certificate_not_found"
  | "malformed_evidence";

export interface PublicCertificate {
  schema_version: "1.0";
  cert_id: string;
  asset_id: string;
  run_id: string;
  provider: string;
  model: string;
  media_type: "image" | "audio";
  mime_type: string;
  byte_size: number;
  ai_generated: boolean;
  width: number | null;
  height: number | null;
  duration_ms: number | null;
  source_sha256: string;
  sealed_sha256: string;
  canonical_hash: string;
  signer_key_id: string;
  signer_public_key_b64: string;
  signature_b64: string;
  public_manifest: Record<string, unknown>;
  certificate_status: CertificateStatus;
  issued_at: string;
  verify_url: string;
}

export interface VerificationRequest {
  cert_id: string;
  presented_sha256?: string;
}

export interface VerificationResult {
  verification_event_id: string;
  cert_id: string;
  media_type: "image" | "audio" | null;
  mime_type: string | null;
  provider: string | null;
  model: string | null;
  status: VerificationStatus;
  verified: boolean;
  signature_valid: boolean;
  envelope_valid: boolean;
  hash_match: boolean | null;
  custody_reference_valid: boolean;
  safe_reason_code: string;
  verified_at: string;
}

export interface DeliverySuccess {
  cert_id: string;
  status: "issued";
  download_url: string;
  expires_at: string;
  expires_in: number;
}

export interface SafeErrorPayload {
  error?: {
    code?: string;
    message?: string;
  };
}

export type CertificateLookup =
  | { state: "found"; certificate: PublicCertificate }
  | { state: "revoked" }
  | { state: "not_found" }
  | { state: "error" };
