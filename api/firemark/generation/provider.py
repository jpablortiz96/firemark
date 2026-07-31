"""Typed generation provider boundary and safe normalized failures."""

from __future__ import annotations

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


class GenerationProviderError(RuntimeError):
    """Safe provider failure that excludes raw response and credential material."""

    def __init__(
        self,
        code: ProviderFailureCode,
        *,
        status_code: int | None = None,
        safe_reason_code: str | None = None,
    ) -> None:
        self.status_code = status_code if status_code is not None and 100 <= status_code <= 599 else None
        self.safe_reason_code = (
            safe_reason_code
            if safe_reason_code is not None
            and safe_reason_code.replace("_", "").isalnum()
            and len(safe_reason_code) <= 64
            else None
        )
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
