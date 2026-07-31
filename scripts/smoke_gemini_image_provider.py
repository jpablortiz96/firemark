"""Explicit opt-in, isolated Gemini image-provider checkpoint."""

from __future__ import annotations

import argparse
import hashlib
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

from api.firemark.generation.gemini_provider import (
    GeminiImageProvider,
    GeminiModelAccess,
)
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.settings import GeminiImageConfig, Settings

INFORMATIONAL_EXIT_CODE = 2
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
SMOKE_PROMPT = (
    "A premium forensic fire-shaped authenticity seal on a dark neutral background, "
    "clean geometric design, no text."
)
STAGES = (
    "configuration_validation",
    "model_access_preflight",
    "request_construction",
    "provider_generation",
    "response_validation",
    "png_validation",
    "source_hash",
)

SafeCategory = Literal[
    "OK",
    "CONFIGURATION_ERROR",
    "AUTHENTICATION_FAILURE",
    "PERMISSION_DENIED",
    "QUOTA_OR_BILLING_FAILURE",
    "RATE_LIMIT",
    "INVALID_REQUEST",
    "MODEL_UNSUPPORTED",
    "SAFETY_REJECTION",
    "TIMEOUT",
    "PROVIDER_UNAVAILABLE",
    "MALFORMED_RESPONSE",
    "NON_PNG_RESPONSE",
    "RESPONSE_TOO_LARGE",
    "SAFE_UNEXPECTED_FAILURE",
]

_PROVIDER_CATEGORIES: dict[str, SafeCategory] = {
    "authentication": "AUTHENTICATION_FAILURE",
    "permission_denied": "PERMISSION_DENIED",
    "quota_or_billing": "QUOTA_OR_BILLING_FAILURE",
    "rate_limit": "RATE_LIMIT",
    "invalid_request": "INVALID_REQUEST",
    "model_or_size_unsupported": "MODEL_UNSUPPORTED",
    "safety_rejection": "SAFETY_REJECTION",
    "timeout": "TIMEOUT",
    "unavailable": "PROVIDER_UNAVAILABLE",
    "malformed_response": "MALFORMED_RESPONSE",
    "non_png_response": "NON_PNG_RESPONSE",
    "response_too_large": "RESPONSE_TOO_LARGE",
}


class SafeSmokeError(RuntimeError):
    """Category-only local failure."""

    def __init__(self, category: SafeCategory) -> None:
        self.category = category
        super().__init__(category)


@dataclass(frozen=True)
class SmokeOutcome:
    category: SafeCategory
    stages: tuple[tuple[str, str], ...]
    config: GeminiImageConfig | None = None
    access: GeminiModelAccess | None = None
    image: GeneratedImage | None = None
    source_sha256: str | None = None
    provider_code: str | None = None
    provider_status: int | None = None
    safe_reason_code: str | None = None


class StageTracker:
    def __init__(self) -> None:
        self.current = STAGES[0]
        self.rows: list[tuple[str, str]] = []

    def begin(self, stage: str) -> None:
        if stage != self.current:
            self.rows.append((self.current, "PASS"))
            self.current = stage

    def success(self) -> tuple[tuple[str, str], ...]:
        self.rows.append((self.current, "PASS"))
        return tuple(self.rows)

    def failure(self) -> tuple[tuple[str, str], ...]:
        self.rows.append((self.current, "FAIL"))
        return tuple(self.rows)


def _load_gemini_config() -> GeminiImageConfig:
    names = {
        "GEMINI_API_KEY": "gemini_api_key",
        "GEMINI_IMAGE_MODEL": "gemini_image_model",
        "FIREMARK_GENERATION_TIMEOUT_SECONDS": "generation_timeout_seconds",
        "FIREMARK_MAX_GENERATED_IMAGE_BYTES": "max_generated_image_bytes",
    }
    values = {
        field: value
        for name, field in names.items()
        if (value := os.getenv(name)) not in (None, "")
    }
    return Settings.model_validate(values).require_gemini_image_config()


def _category(exc: Exception, stage: str) -> tuple[SafeCategory, str | None, int | None, str | None]:
    if isinstance(exc, SafeSmokeError):
        return exc.category, None, None, None
    if isinstance(exc, GenerationProviderError):
        return (
            _PROVIDER_CATEGORIES.get(exc.code, "SAFE_UNEXPECTED_FAILURE"),
            exc.code,
            exc.status_code,
            exc.safe_reason_code,
        )
    if stage == "configuration_validation":
        return "CONFIGURATION_ERROR", None, None, None
    return "SAFE_UNEXPECTED_FAILURE", None, None, None


def execute_live(
    *,
    config_loader: Callable[[], GeminiImageConfig] = _load_gemini_config,
    provider_factory: Callable[..., GeminiImageProvider] = GeminiImageProvider,
) -> SmokeOutcome:
    """Perform one preflight and exactly one generation request."""
    tracker = StageTracker()
    config: GeminiImageConfig | None = None
    access: GeminiModelAccess | None = None
    image: GeneratedImage | None = None
    digest: str | None = None
    try:
        config = config_loader()
        provider = provider_factory(
            api_key=config.api_key.get_secret_value(),
            timeout_seconds=config.timeout_seconds,
            max_image_bytes=config.max_image_bytes,
        )
        tracker.begin("model_access_preflight")
        access = provider.preflight_model(config.model)
        if not access.available or access.supports_generate_content is False:
            raise SafeSmokeError("MODEL_UNSUPPORTED")
        tracker.begin("request_construction")
        request = GenerationRequest(
            prompt=SMOKE_PROMPT,
            model=config.model,
            size="auto",
            request_id="firemark-gemini-provider-smoke",
        )
        payload = provider.build_request_parameters(request)
        expected = {
            "contents": [{"parts": [{"text": SMOKE_PROMPT}]}],
            "generationConfig": {"responseModalities": ["IMAGE"]},
        }
        if payload != expected:
            raise SafeSmokeError("INVALID_REQUEST")
        tracker.begin("provider_generation")
        image = provider.generate_image(request)
        tracker.begin("response_validation")
        if image.provider != "gemini" or not image.ai_generated:
            raise SafeSmokeError("MALFORMED_RESPONSE")
        tracker.begin("png_validation")
        if (
            image.media_type != "image/png"
            or image.file_extension != "png"
            or not image.data.startswith(b"\x89PNG\r\n\x1a\n")
        ):
            raise SafeSmokeError("NON_PNG_RESPONSE")
        if len(image.data) > config.max_image_bytes:
            raise SafeSmokeError("RESPONSE_TOO_LARGE")
        tracker.begin("source_hash")
        digest = hashlib.sha256(image.data).hexdigest()
        return SmokeOutcome(
            category="OK",
            stages=tracker.success(),
            config=config,
            access=access,
            image=image,
            source_sha256=digest,
        )
    except Exception as exc:
        category, code, status, reason = _category(exc, tracker.current)
        return SmokeOutcome(
            category=category,
            stages=tracker.failure(),
            config=config,
            access=access,
            image=image,
            source_sha256=digest,
            provider_code=code,
            provider_status=status,
            safe_reason_code=reason,
        )


def _print_outcome(outcome: SmokeOutcome) -> None:
    if outcome.config is not None:
        print("provider: gemini")
        print(f"configured model: {outcome.config.model}")
    if outcome.access is not None:
        print(f"model available: {str(outcome.access.available).lower()}")
        support = outcome.access.supports_generate_content
        print(
            "generateContent support: "
            + ("UNDECLARED" if support is None else str(support).lower())
        )
    if outcome.image is not None:
        print(f"generated byte count: {len(outcome.image.data)}")
        print(f"SHA-256: {outcome.source_sha256 or 'UNAVAILABLE'}")
        print(f"ai_generated: {str(outcome.image.ai_generated).lower()}")
    print("stage table:")
    for stage, status in outcome.stages:
        print(f"{status}: {stage}")
    print(f"normalized safe category: {outcome.category}")
    if outcome.provider_status is not None:
        print(f"provider HTTP status: {outcome.provider_status}")
    if outcome.safe_reason_code is not None:
        print(f"provider safe reason: {outcome.safe_reason_code}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one isolated Gemini image-provider verification checkpoint."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Allow one model preflight and exactly one real Gemini generation request.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.live:
        print("INFO: --live not supplied; zero network calls were made.")
        print("INFO: no Gemini client was constructed and no provider cost was incurred.")
        return INFORMATIONAL_EXIT_CODE
    load_dotenv(DEFAULT_ENV_FILE, override=False)
    outcome = execute_live()
    _print_outcome(outcome)
    return 0 if outcome.category == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
