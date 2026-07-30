import { strToU8, zipSync } from "fflate";
import QRCode from "qrcode-svg";

import type { PublicCertificate } from "@/lib/types";
import { containsPrivatePublicField, isCertificateId, isSha256, safeHttpUrl } from "@/lib/validation";

export const PROOF_PACK_ENTRIES = [
  "certificate.json",
  "verification-summary.txt",
  "public-key.txt",
  "qr-code.svg",
  "README.txt",
] as const;

interface ProofPack {
  bytes: Uint8Array;
  filename: string;
}

function sortedValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortedValue);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, nested]) => [key, sortedValue(nested)]),
  );
}

export function canonicalPublicCertificate(certificate: PublicCertificate): string {
  const projection = {
    schema_version: certificate.schema_version,
    cert_id: certificate.cert_id,
    asset_id: certificate.asset_id,
    run_id: certificate.run_id,
    provider: certificate.provider,
    model: certificate.model,
    media_type: certificate.media_type,
    mime_type: certificate.mime_type,
    byte_size: certificate.byte_size,
    ai_generated: certificate.ai_generated,
    width: certificate.width,
    height: certificate.height,
    duration_ms: certificate.duration_ms,
    source_sha256: certificate.source_sha256,
    sealed_sha256: certificate.sealed_sha256,
    canonical_hash: certificate.canonical_hash,
    signer_key_id: certificate.signer_key_id,
    signer_public_key_b64: certificate.signer_public_key_b64,
    signature_b64: certificate.signature_b64,
    public_manifest: certificate.public_manifest,
    certificate_status: certificate.certificate_status,
    issued_at: certificate.issued_at,
    verify_url: certificate.verify_url,
  };
  return `${JSON.stringify(sortedValue(projection))}\n`;
}

function validatePublicCertificate(certificate: PublicCertificate): void {
  const verificationUrlValid = (() => {
    try {
      const parsed = new URL(certificate.verify_url);
      return Boolean(
        parsed.protocol === "https:" &&
        parsed.hostname &&
        !parsed.username &&
        !parsed.password &&
        !parsed.search &&
        !parsed.hash,
      );
    } catch {
      return false;
    }
  })();
  if (
    certificate.schema_version !== "1.0" ||
    !isCertificateId(certificate.cert_id) ||
    !isCertificateId(certificate.asset_id) ||
    !isCertificateId(certificate.run_id) ||
    !certificate.provider.trim() ||
    !certificate.model.trim() ||
    !["image", "audio"].includes(certificate.media_type) ||
    !certificate.mime_type.trim() ||
    !Number.isInteger(certificate.byte_size) ||
    certificate.byte_size <= 0 ||
    !isSha256(certificate.source_sha256) ||
    !isSha256(certificate.sealed_sha256) ||
    !isSha256(certificate.canonical_hash) ||
    containsPrivatePublicField(certificate.public_manifest) ||
    !safeHttpUrl(certificate.verify_url) ||
    !verificationUrlValid ||
    !certificate.signer_key_id.trim() ||
    !certificate.signer_public_key_b64.trim() ||
    !certificate.signature_b64.trim() ||
    !Number.isFinite(Date.parse(certificate.issued_at)) ||
    !["active", "revoked", "invalid"].includes(certificate.certificate_status)
  ) {
    throw new Error("PUBLIC_CERTIFICATE_INVALID");
  }
}

function verificationSummary(certificate: PublicCertificate): string {
  return [
    "FIREMARK Public Verification Summary",
    "",
    `Certificate ID: ${certificate.cert_id}`,
    `Asset ID: ${certificate.asset_id}`,
    `Run ID: ${certificate.run_id}`,
    `Media type: ${certificate.media_type}`,
    `MIME type: ${certificate.mime_type}`,
    `Provider: ${certificate.provider}`,
    `Model: ${certificate.model}`,
    `AI generated: ${certificate.ai_generated}`,
    `Byte size: ${certificate.byte_size}`,
    `Issued at: ${certificate.issued_at}`,
    `Certificate status: ${certificate.certificate_status}`,
    `Sealed SHA-256: ${certificate.sealed_sha256}`,
    `Source SHA-256: ${certificate.source_sha256}`,
    `Canonical hash: ${certificate.canonical_hash}`,
    `Signer key ID: ${certificate.signer_key_id}`,
    `Public verification URL: ${certificate.verify_url}`,
    "",
    "This summary is public evidence. The final decision must come from FIREMARK Verify Gate.",
    "",
  ].join("\n");
}

function publicKey(certificate: PublicCertificate): string {
  return [
    "algorithm: Ed25519",
    `signer_key_id: ${certificate.signer_key_id}`,
    `public_key_base64: ${certificate.signer_public_key_b64}`,
    "",
  ].join("\n");
}

function readme(certificate: PublicCertificate): string {
  const localStep =
    certificate.media_type === "image"
      ? "2. Drop the sealed PNG into FIREMARK Lens."
      : "2. Select the audio locally and enter this certificate ID; only its SHA-256 is sent.";
  return [
    "FIREMARK Public Proof Pack",
    "",
    "This package contains only the public Birth Certificate projection and verification aids.",
    "It does not contain the sealed media, prompt, private manifest, credentials, or delivery URL.",
    "",
    "How to verify",
    `1. Open ${certificate.verify_url}`,
    localStep,
    "3. Compare the displayed hash and certificate with this Proof Pack.",
    "4. Treat revoked or modified assets as unverified and do not deliver them.",
    "",
  ].join("\n");
}

function qrCode(verificationUrl: string): string {
  return new QRCode({
    content: verificationUrl,
    padding: 4,
    width: 256,
    height: 256,
    color: "#111111",
    background: "#ffffff",
    ecl: "M",
    join: true,
    container: "svg-viewbox",
    pretty: false,
    xmlDeclaration: true,
  }).svg();
}

export function buildProofPack(certificate: PublicCertificate): ProofPack {
  validatePublicCertificate(certificate);
  const files: Record<(typeof PROOF_PACK_ENTRIES)[number], Uint8Array> = {
    "certificate.json": strToU8(canonicalPublicCertificate(certificate)),
    "verification-summary.txt": strToU8(verificationSummary(certificate)),
    "public-key.txt": strToU8(publicKey(certificate)),
    "qr-code.svg": strToU8(qrCode(certificate.verify_url)),
    "README.txt": strToU8(readme(certificate)),
  };
  return {
    bytes: zipSync(files, { level: 0 }),
    filename: `firemark-proof-${certificate.cert_id}.zip`,
  };
}
