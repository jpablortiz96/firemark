"""Explicit opt-in, OpenAI-only image provider checkpoint."""

from __future__ import annotations

import argparse
import hashlib
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.openai_provider import OpenAIImageProvider
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.settings import OpenAIImageConfig, Settings

INFORMATIONAL_EXIT_CODE = 2
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
SMOKE_PROMPT = (
    "A minimal geometric flame-shaped verification seal on a neutral background, "
    "clean vector style, no text."
)
STAGES = (
    "configuration_validation",
    "adapter_construction",
    "client_construction",
    "provider_request_construction",
    "provider_generation",
    "provider_response_validation",
    "png_validation",
    "media_validation",
    "maximum_size_validation",
    "source_hash",
)

SafeCategory = Literal[
    "OK",
    "CONFIGURATION_ERROR",
    "CLIENT_CONSTRUCTION_ERROR",
    "REQUEST_CONSTRUCTION_ERROR",
    "AUTHENTICATION_FAILURE",
    "PERMISSION_DENIED",
    "QUOTA_OR_BILLING_FAILURE",
    "RATE_LIMIT",
    "INVALID_REQUEST",
    "MODEL_OR_SIZE_UNSUPPORTED",
    "SAFETY_REJECTION",
    "TIMEOUT",
    "PROVIDER_UNAVAILABLE",
    "MALFORMED_RESPONSE",
    "NON_PNG_RESPONSE",
    "RESPONSE_TOO_LARGE",
    "LOCAL_ADAPTER_ERROR",
    "UNKNOWN_SAFE_ERROR",
]

_PROVIDER_CATEGORIES: dict[str, SafeCategory] = {
    "authentication": "AUTHENTICATION_FAILURE",
    "permission_denied": "PERMISSION_DENIED",
    "quota_or_billing": "QUOTA_OR_BILLING_FAILURE",
    "rate_limit": "RATE_LIMIT",
    "invalid_request": "INVALID_REQUEST",
    "model_or_size_unsupported": "MODEL_OR_SIZE_UNSUPPORTED",
    "safety_rejection": "SAFETY_REJECTION",
    "timeout": "TIMEOUT",
    "unavailable": "PROVIDER_UNAVAILABLE",
    "malformed_response": "MALFORMED_RESPONSE",
    "non_png_response": "NON_PNG_RESPONSE",
    "response_too_large": "RESPONSE_TOO_LARGE",
}
_CATEGORY_EXIT_CODES: dict[SafeCategory, int] = {
    "OK": 0,
    "CONFIGURATION_ERROR": 10,
    "CLIENT_CONSTRUCTION_ERROR": 20,
    "REQUEST_CONSTRUCTION_ERROR": 20,
    "AUTHENTICATION_FAILURE": 30,
    "PERMISSION_DENIED": 30,
    "QUOTA_OR_BILLING_FAILURE": 31,
    "RATE_LIMIT": 32,
    "INVALID_REQUEST": 33,
    "MODEL_OR_SIZE_UNSUPPORTED": 33,
    "SAFETY_REJECTION": 34,
    "TIMEOUT": 40,
    "PROVIDER_UNAVAILABLE": 40,
    "MALFORMED_RESPONSE": 50,
    "NON_PNG_RESPONSE": 50,
    "RESPONSE_TOO_LARGE": 50,
    "LOCAL_ADAPTER_ERROR": 60,
    "UNKNOWN_SAFE_ERROR": 60,
}


class SafeSmokeError(RuntimeError):
    """A category-only local checkpoint failure."""

    def __init__(self, category: SafeCategory) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class SmokeOutcome:
    category: SafeCategory
    exit_code: int
    stages: tuple[tuple[str, str], ...]
    config: OpenAIImageConfig | None = None
    image: GeneratedImage | None = None
    source_sha256: str | None = None
    provider_code: str | None = None


class StageTracker:
    """Record each stage as current before its operation starts."""

    def __init__(self) -> None:
        self.current = STAGES[0]
        self._rows: list[tuple[str, str]] = []

    def begin(self, stage: str) -> None:
        if stage != self.current:
            self._rows.append((self.current, "PASS"))
            self.current = stage

    def success(self) -> tuple[tuple[str, str], ...]:
        self._rows.append((self.current, "PASS"))
        return tuple(self._rows)

    def failure(self) -> tuple[tuple[str, str], ...]:
        self._rows.append((self.current, "FAIL"))
        return tuple(self._rows)


def _load_openai_config() -> OpenAIImageConfig:
    names = {
        "OPENAI_API_KEY": "openai_api_key",
        "OPENAI_IMAGE_MODEL": "openai_image_model",
        "OPENAI_IMAGE_SIZE": "openai_image_size",
        "FIREMARK_GENERATION_TIMEOUT_SECONDS": "generation_timeout_seconds",
        "FIREMARK_MAX_GENERATED_IMAGE_BYTES": "max_generated_image_bytes",
    }
    values = {
        field: value
        for name, field in names.items()
        if (value := os.getenv(name)) not in (None, "")
    }
    return Settings.model_validate(values).require_openai_image_config()


def _category(exc: Exception, stage: str) -> tuple[SafeCategory, str | None]:
    if isinstance(exc, SafeSmokeError):
        return exc.category, None
    if isinstance(exc, GenerationProviderError):
        return _PROVIDER_CATEGORIES.get(exc.code, "UNKNOWN_SAFE_ERROR"), exc.code
    if stage == "configuration_validation":
        return "CONFIGURATION_ERROR", None
    if stage == "client_construction":
        return "CLIENT_CONSTRUCTION_ERROR", None
    if stage == "provider_request_construction":
        return "REQUEST_CONSTRUCTION_ERROR", None
    if stage == "adapter_construction":
        return "LOCAL_ADAPTER_ERROR", None
    return "UNKNOWN_SAFE_ERROR", None


def execute_live(
    *,
    config_loader: Callable[[], OpenAIImageConfig] = _load_openai_config,
    provider_factory: Callable[..., OpenAIImageProvider] = OpenAIImageProvider,
) -> SmokeOutcome:
    """Execute one isolated provider request; callers must load dotenv explicitly."""
    tracker = StageTracker()
    config: OpenAIImageConfig | None = None
    image: GeneratedImage | None = None
    digest: str | None = None
    try:
        config = config_loader()
        tracker.begin("adapter_construction")
        provider = provider_factory(
            api_key=config.api_key.get_secret_value(),
            timeout_seconds=config.timeout_seconds,
            max_image_bytes=config.max_image_bytes,
        )
        tracker.begin("client_construction")
        client = provider.construct_client()
        tracker.begin("provider_request_construction")
        request = GenerationRequest(
            prompt=SMOKE_PROMPT,
            model=config.model,
            size=config.size,
            request_id="firemark-openai-provider-smoke",
        )
        parameters = provider.build_request_parameters(request)
        tracker.begin("provider_generation")
        response = provider.request_image(client, parameters)
        tracker.begin("provider_response_validation")
        image = provider.validate_response(response, request)
        tracker.begin("png_validation")
        if not image.data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise SafeSmokeError("NON_PNG_RESPONSE")
        tracker.begin("media_validation")
        if image.media_type != "image/png" or image.file_extension != "png":
            raise SafeSmokeError("NON_PNG_RESPONSE")
        tracker.begin("maximum_size_validation")
        if len(image.data) > config.max_image_bytes:
            raise SafeSmokeError("RESPONSE_TOO_LARGE")
        tracker.begin("source_hash")
        digest = hashlib.sha256(image.data).hexdigest()
        return SmokeOutcome(
            category="OK",
            exit_code=0,
            stages=tracker.success(),
            config=config,
            image=image,
            source_sha256=digest,
        )
    except Exception as exc:
        category, provider_code = _category(exc, tracker.current)
        return SmokeOutcome(
            category=category,
            exit_code=_CATEGORY_EXIT_CODES[category],
            stages=tracker.failure(),
            config=config,
            image=image,
            source_sha256=digest,
            provider_code=provider_code,
        )


def _print_outcome(outcome: SmokeOutcome) -> None:
    if outcome.config is not None:
        print("provider: openai")
        print(f"configured model: {outcome.config.model}")
        print(f"configured size: {outcome.config.size}")
    if outcome.image is not None:
        print(f"generated byte count: {len(outcome.image.data)}")
        print(f"SHA-256: {outcome.source_sha256 or 'UNAVAILABLE'}")
        print(f"ai_generated: {str(outcome.image.ai_generated).lower()}")
    print("stage table:")
    for stage, status in outcome.stages:
        print(f"{status}: {stage}")
    print(f"normalized safe category: {outcome.category}")
    print(f"PROVIDER_SMOKE_EXIT_CODE: {outcome.exit_code}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one isolated OpenAI image-provider verification checkpoint."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Allow exactly one real OpenAI image-generation request and provider cost.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.live:
        print("INFO: --live not supplied; zero network calls were made.")
        print("INFO: no OpenAI client was constructed and no provider cost was incurred.")
        return INFORMATIONAL_EXIT_CODE
    load_dotenv(DEFAULT_ENV_FILE, override=False)
    outcome = execute_live()
    _print_outcome(outcome)
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
