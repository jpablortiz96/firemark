export type SafeErrorKind =
  | "configuration"
  | "timeout"
  | "network"
  | "not_found"
  | "revoked"
  | "malformed"
  | "blocked"
  | "unavailable";

const SAFE_MESSAGES: Record<SafeErrorKind, string> = {
  configuration: "FIREMARK is not configured for this request.",
  timeout: "The verification service took too long to respond. Please retry.",
  network: "The verification service could not be reached. Please retry.",
  not_found: "No public Birth Certificate was found for that identifier.",
  revoked: "This Birth Certificate has been revoked and cannot authorize delivery.",
  malformed: "The supplied evidence is not in a valid FIREMARK format.",
  blocked: "Verification did not authorize delivery for this asset.",
  unavailable: "The requested FIREMARK service is temporarily unavailable.",
};

export class SafeApiError extends Error {
  readonly kind: SafeErrorKind;
  readonly code: string;

  constructor(kind: SafeErrorKind, code: string) {
    super(SAFE_MESSAGES[kind]);
    this.name = "SafeApiError";
    this.kind = kind;
    this.code = code;
  }
}

export function safeErrorMessage(error: unknown): string {
  return error instanceof SafeApiError
    ? error.message
    : "Something went wrong while checking this evidence. Please retry.";
}
