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

    def __init__(self, code: ProviderFailureCode) -> None:
        super().__init__(f"Media provider failed: {code}")
        self.code = code


class GenerationProvider(Protocol):
    """Minimum injectable image generation interface."""

    def generate_image(self, request: GenerationRequest) -> GeneratedImage: ...


ImageGenerationProvider = GenerationProvider


class AudioGenerationProvider(Protocol):
    """Minimum injectable text-to-speech generation interface."""

    def generate_audio(self, request: AudioGenerationRequest) -> GeneratedAudio: ...
