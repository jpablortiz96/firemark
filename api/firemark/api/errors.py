"""Safe API errors and consistent public error envelopes."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ErrorDetail(BaseModel):
    """One safe machine-readable API error."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    code: str
    message: str
    request_id: str


class ErrorResponse(BaseModel):
    """Uniform FIREMARK API error response."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    error: ErrorDetail


class APIError(RuntimeError):
    """Expected safe HTTP failure."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.safe_message = message
