export type LensErrorCode =
  | "FILE_TYPE_INVALID"
  | "FILE_EXTENSION_INVALID"
  | "FILE_TOO_LARGE"
  | "PNG_MAGIC_INVALID"
  | "PNG_TRUNCATED"
  | "PNG_CHUNK_LENGTH_INVALID"
  | "PNG_CHUNK_CRC_INVALID"
  | "PNG_IEND_INVALID"
  | "CAPSULE_MISSING"
  | "CAPSULE_DUPLICATE"
  | "CAPSULE_CONFLICTING"
  | "CAPSULE_ENCODING_UNSUPPORTED"
  | "CAPSULE_TOO_LARGE"
  | "CAPSULE_JSON_INVALID"
  | "CAPSULE_SCHEMA_INVALID"
  | "CAPSULE_PRIVATE_FIELD"
  | "CAPSULE_NONCANONICAL"
  | "CAPSULE_IDENTIFIER_INVALID"
  | "HASH_UNAVAILABLE";

export type LensErrorKind = "file" | "no_capsule" | "malformed_capsule" | "hash";

export class LensVerificationError extends Error {
  constructor(
    readonly code: LensErrorCode,
    readonly kind: LensErrorKind,
  ) {
    super(code);
    this.name = "LensVerificationError";
  }
}

export function abortError(): DOMException {
  return new DOMException("Operation aborted", "AbortError");
}
