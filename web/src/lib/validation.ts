const CERTIFICATE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const FORBIDDEN_PUBLIC_FIELDS = [
  "prompt",
  "parameter",
  "seed",
  "private_manifest",
  "vault",
  "version_id",
  "credential",
  "authorization",
  "presigned",
  "delivery_url",
];

export function isCertificateId(value: string): boolean {
  return CERTIFICATE_ID.test(value);
}

export function isSha256(value: string): boolean {
  return SHA256.test(value);
}

export function containsPrivatePublicField(value: unknown): boolean {
  if (Array.isArray(value)) {
    return value.some(containsPrivatePublicField);
  }
  if (value === null || typeof value !== "object") {
    return false;
  }
  return Object.entries(value).some(([key, nested]) => {
    const normalized = key.toLowerCase();
    return (
      FORBIDDEN_PUBLIC_FIELDS.some((field) => normalized.includes(field)) ||
      containsPrivatePublicField(nested)
    );
  });
}

export function safeHttpUrl(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" ||
      (parsed.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname))
      ? parsed.toString()
      : null;
  } catch {
    return null;
  }
}
