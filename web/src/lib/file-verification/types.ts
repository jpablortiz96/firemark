import type { VerificationResult } from "@/lib/types";

export const MAX_FILE_BYTES = 25 * 1024 * 1024;
export const MAX_CAPSULE_BYTES = 8 * 1024;
export const PUBLIC_CAPSULE_KEY = "firemark.public-capsule";

export interface FiremarkPublicCapsuleV1 {
  schema_version: "firemark.public-capsule.v1";
  cert_id: string;
  asset_id: string;
  run_id: string;
  canonical_hash: string;
  source_sha256: string;
  signer_key_id: string;
  verify_url: string;
  issued_at: string;
}

export type LayerStatus = "PASS" | "FAIL" | "NOT CHECKED";

export type VerificationLayerKey =
  | "file_format"
  | "public_capsule"
  | "sealed_hash"
  | "certificate_found"
  | "signature"
  | "certificate_status"
  | "custody_reference"
  | "delivery_eligibility";

export interface VerificationLayer {
  key: VerificationLayerKey;
  label: string;
  status: LayerStatus;
}

export type LensState =
  | "verified"
  | "tampered"
  | "no_capsule"
  | "malformed_capsule"
  | "invalid_file"
  | "revoked"
  | "not_found"
  | "unverified"
  | "unavailable";

export interface LensResult {
  state: LensState;
  layers: VerificationLayer[];
  fileName: string;
  fileSize: number;
  capsule?: FiremarkPublicCapsuleV1;
  sealedSha256?: string;
  verification?: VerificationResult;
}

export type ProgressPhase = "reading" | "capsule" | "hashing" | "verifying" | "complete";

export interface VerificationProgress {
  phase: ProgressPhase;
  percent: number;
}
