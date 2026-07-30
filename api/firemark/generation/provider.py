"""Typed generation provider boundary and safe normalized failures."""

from __future__ import annotations

from typing import Literal, Protocol

from api.firemark.generation.models import GeneratedImage, GenerationRequest

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
    "response_too_large",
]


class GenerationProviderError(RuntimeError):
    """Safe provider failure that excludes raw response and credential material."""

    def __init__(self, code: ProviderFailureCode) -> None:
        super().__init__(f"Image provider failed: {code}")
        self.code = code


class GenerationProvider(Protocol):
    """Minimum injectable image generation interface."""

    def generate_image(self, request: GenerationRequest) -> GeneratedImage: ...
