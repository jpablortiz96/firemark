import { containsPrivatePublicField } from "@/lib/validation";
import { LensVerificationError } from "@/lib/file-verification/errors";
import type { FiremarkPublicCapsuleV1 } from "@/lib/file-verification/types";
import { MAX_CAPSULE_BYTES } from "@/lib/file-verification/types";

const CAPSULE_FIELDS = [
  "asset_id",
  "canonical_hash",
  "cert_id",
  "issued_at",
  "run_id",
  "schema_version",
  "signer_key_id",
  "source_sha256",
  "verify_url",
] as const;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const CANONICAL_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

function asciiJsonString(value: string): string {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

export function canonicalCapsuleJson(capsule: FiremarkPublicCapsuleV1): string {
  return `{${CAPSULE_FIELDS.map(
    (field) => `${JSON.stringify(field)}:${asciiJsonString(capsule[field])}`,
  ).join(",")}}`;
}

function validHttpsUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === "https:" &&
      Boolean(parsed.hostname) &&
      !parsed.username &&
      !parsed.password &&
      !parsed.search &&
      !parsed.hash
    );
  } catch {
    return false;
  }
}

export function parsePublicCapsule(payload: Uint8Array): FiremarkPublicCapsuleV1 {
  if (payload.byteLength > MAX_CAPSULE_BYTES) {
    throw new LensVerificationError("CAPSULE_TOO_LARGE", "malformed_capsule");
  }
  if (payload.some((byte) => byte > 0x7f)) {
    throw new LensVerificationError("CAPSULE_JSON_INVALID", "malformed_capsule");
  }
  const text = new TextDecoder("ascii").decode(payload);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new LensVerificationError("CAPSULE_JSON_INVALID", "malformed_capsule");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new LensVerificationError("CAPSULE_SCHEMA_INVALID", "malformed_capsule");
  }
  if (containsPrivatePublicField(parsed)) {
    throw new LensVerificationError("CAPSULE_PRIVATE_FIELD", "malformed_capsule");
  }
  const value = parsed as Record<string, unknown>;
  const fields = Object.keys(value).sort();
  if (fields.length !== CAPSULE_FIELDS.length || fields.some((field, index) => field !== CAPSULE_FIELDS[index])) {
    throw new LensVerificationError("CAPSULE_SCHEMA_INVALID", "malformed_capsule");
  }
  if (CAPSULE_FIELDS.some((field) => typeof value[field] !== "string")) {
    throw new LensVerificationError("CAPSULE_SCHEMA_INVALID", "malformed_capsule");
  }
  const capsule = value as unknown as FiremarkPublicCapsuleV1;
  if (capsule.schema_version !== "firemark.public-capsule.v1") {
    throw new LensVerificationError("CAPSULE_SCHEMA_INVALID", "malformed_capsule");
  }
  if (
    !IDENTIFIER.test(capsule.cert_id) ||
    !IDENTIFIER.test(capsule.asset_id) ||
    !IDENTIFIER.test(capsule.run_id) ||
    !IDENTIFIER.test(capsule.signer_key_id)
  ) {
    throw new LensVerificationError("CAPSULE_IDENTIFIER_INVALID", "malformed_capsule");
  }
  if (!SHA256.test(capsule.canonical_hash) || !SHA256.test(capsule.source_sha256)) {
    throw new LensVerificationError("CAPSULE_SCHEMA_INVALID", "malformed_capsule");
  }
  if (
    !CANONICAL_TIME.test(capsule.issued_at) ||
    !Number.isFinite(Date.parse(capsule.issued_at)) ||
    !validHttpsUrl(capsule.verify_url)
  ) {
    throw new LensVerificationError("CAPSULE_SCHEMA_INVALID", "malformed_capsule");
  }
  if (canonicalCapsuleJson(capsule) !== text) {
    throw new LensVerificationError("CAPSULE_NONCANONICAL", "malformed_capsule");
  }
  return capsule;
}
