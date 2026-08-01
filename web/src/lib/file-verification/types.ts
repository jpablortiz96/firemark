import type { PublicCertificate, VerificationResult } from "@/lib/types";

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

export const MAX_AUDIO_FILE_BYTES = 50 * 1024 * 1024;
export const CANONICAL_AUDIO_MIME_TYPE = "audio/mpeg";

/** Browser MIME aliases normalized to the canonical FIREMARK audio type. */
export const AUDIO_MIME_ALIASES = ["audio/mpeg", "audio/mp3", "audio/x-mpeg"] as const;

export type MediaMode = "image" | "audio";

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

/**
 * Audio uses its own layer vocabulary. MP3 sealing is byte-preserving, so there
 * is no embedded capsule to check and the meaningful evidence is the media
 * contract plus the byte-preserving hash relationship.
 */
export type AudioLayerKey =
  | "local_processing"
  | "mp3_format"
  | "public_certificate"
  | "media_contract"
  | "byte_preserving_seal"
  | "local_file_hash"
  | "cryptographic_verification";

export interface VerificationLayer {
  key: VerificationLayerKey | AudioLayerKey;
  label: string;
  status: LayerStatus;
  /** Safe, non-technical explanation shown alongside PASS/FAIL. */
  detail?: string;
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
  mediaType?: "image" | "audio";
  mimeType?: string;
  certId?: string;
  capsule?: FiremarkPublicCapsuleV1;
  sealedSha256?: string;
  verification?: VerificationResult;
  /** Public certificate projection, when the audio flow retrieved one. */
  certificate?: PublicCertificate;
}

export type ProgressPhase = "reading" | "capsule" | "hashing" | "verifying" | "complete";

export interface VerificationProgress {
  phase: ProgressPhase;
  percent: number;
}
