"""Typed generation provider boundary and safe normalized failures."""

from __future__ import annotations

import re
from typing import Literal, Protocol

from api.firemark.generation.models import (
    AudioGenerationRequest,
    GeneratedAudio,
    GeneratedImage,
    GenerationRequest,
)

ProviderFailureCode = Literal[
    "authentication",
    "permission_denied",
    "quota_or_billing",
    "rate_limit",
    "invalid_request",
    "model_or_size_unsupported",
    "safety_rejection",
    "timeout",
    "unavailable",
    "malformed_response",
    "non_png_response",
    "non_mp3_response",
    "response_too_large",
    "voice_not_found",
    "unsupported_media_type",
]


#: Structured provider field paths (for example ``response_format.delivery``)
#: are safe to persist; anything outside this shape is discarded.
SAFE_FIELD_PATH = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,160}$")
MAX_SAFE_INVALID_FIELDS = 16

#: Exception class names that may be persisted as a safe diagnostic token. Only
#: the class name is ever retained; messages, repr, requests and responses are not.
SAFE_EXCEPTION_TOKENS = frozenset(
    {
        "ConnectTimeout",
        "ReadTimeout",
        "WriteTimeout",
        "PoolTimeout",
        "TimeoutException",
        "ProxyError",
        "ConnectError",
        "ReadError",
        "WriteError",
        "CloseError",
        "RemoteProtocolError",
        "LocalProtocolError",
        "DecodingError",
        "UnsupportedProtocol",
        "TransportError",
        "HTTPError",
    }
)


class GenerationProviderError(RuntimeError):
    """Safe provider failure that excludes raw response and credential material."""

    def __init__(
        self,
        code: ProviderFailureCode,
        *,
        status_code: int | None = None,
        safe_reason_code: str | None = None,
        safe_exception_token: str | None = None,
        safe_invalid_fields: tuple[str, ...] = (),
    ) -> None:
        self.status_code = status_code if status_code is not None and 100 <= status_code <= 599 else None
        self.safe_reason_code = (
            safe_reason_code
            if safe_reason_code is not None
            and safe_reason_code.replace("_", "").isalnum()
            and len(safe_reason_code) <= 64
            else None
        )
        self.safe_exception_token = (
            safe_exception_token if safe_exception_token in SAFE_EXCEPTION_TOKENS else None
        )
        #: Structured field paths a provider named as invalid. Only the path is
        #: kept; the accompanying description is always discarded.
        self.safe_invalid_fields = tuple(
            field
            for field in safe_invalid_fields
            if isinstance(field, str) and SAFE_FIELD_PATH.fullmatch(field)
        )[:MAX_SAFE_INVALID_FIELDS]
        suffix = f" (status={self.status_code})" if self.status_code is not None else ""
        super().__init__(f"Media provider failed: {code}{suffix}")
        self.code = code


class GenerationProvider(Protocol):
    """Minimum injectable image generation interface."""

    def generate_image(self, request: GenerationRequest) -> GeneratedImage: ...


ImageGenerationProvider = GenerationProvider


class AudioGenerationProvider(Protocol):
    """Minimum injectable text-to-speech generation interface."""

    def generate_audio(self, request: AudioGenerationRequest) -> GeneratedAudio: ...
