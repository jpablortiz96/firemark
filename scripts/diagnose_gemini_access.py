"""Read-only Google Gemini access diagnostic.

The diagnostic never generates media and therefore never incurs generation cost.
It distinguishes configuration, authentication, permission, quota, model,
endpoint, timeout, transport, and malformed-response outcomes using only the
documented read-only model endpoints. It prints HTTP status, a normalized safe
category, a safe reason code, the configured model, whether that model appears
in the model listing, and safely bounded supported method names. It never prints
the API key, a prompt, a raw response, a provider error message, an
authorization header, a request identifier, quota metadata, or account metadata.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

from api.firemark.generation.gemini_provider import (
    GEMINI_API_VERSION,
    GEMINI_INTERACTIONS_PATH,
    GEMINI_MODELS_PATH,
    GeminiImageProvider,
)
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.generation.provider_identity import (
    GOOGLE_GEMINI_PROVIDER,
    provider_model_display_name,
)
from api.firemark.settings import GeminiImageConfig, Settings

INFORMATIONAL_EXIT_CODE = 2
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"

SafeCategory = Literal[
    "OK",
    "CONFIGURATION_ERROR",
    "AUTHENTICATION_FAILURE",
    "PERMISSION_DENIED",
    "QUOTA_OR_BILLING_FAILURE",
    "RATE_LIMIT",
    "INVALID_REQUEST",
    "MODEL_UNSUPPORTED",
    "TIMEOUT",
    "PROVIDER_UNAVAILABLE",
    "MALFORMED_RESPONSE",
    "SAFE_UNEXPECTED_FAILURE",
]

PROVIDER_CATEGORIES: dict[str, SafeCategory] = {
    "authentication": "AUTHENTICATION_FAILURE",
    "permission_denied": "PERMISSION_DENIED",
    "quota_or_billing": "QUOTA_OR_BILLING_FAILURE",
    "rate_limit": "RATE_LIMIT",
    "invalid_request": "INVALID_REQUEST",
    "model_or_size_unsupported": "MODEL_UNSUPPORTED",
    "timeout": "TIMEOUT",
    "unavailable": "PROVIDER_UNAVAILABLE",
    "malformed_response": "MALFORMED_RESPONSE",
}

#: Safe reason codes that separate a transport problem from an endpoint problem.
TRANSPORT_REASONS = frozenset(
    {
        "DNS_RESOLUTION_FAILURE",
        "TRANSPORT_CONNECT_FAILURE",
        "TRANSPORT_PROXY_FAILURE",
        "TRANSPORT_TIMEOUT",
        "TRANSPORT_FAILURE",
    }
)


@dataclass(frozen=True)
class ProbeResult:
    """One read-only probe reduced to non-identifying safe fields."""

    name: str
    category: SafeCategory
    status_code: int | None = None
    safe_reason_code: str | None = None

    @property
    def passed(self) -> bool:
        return self.category == "OK"

    @property
    def failure_domain(self) -> str:
        if self.safe_reason_code in TRANSPORT_REASONS:
            return "TRANSPORT"
        if self.category == "OK":
            return "NONE"
        if self.status_code is None:
            return "LOCAL"
        return "ENDPOINT"


@dataclass(frozen=True)
class DiagnosticOutcome:
    category: SafeCategory
    model: str | None = None
    probes: tuple[ProbeResult, ...] = ()
    model_listed: bool | None = None
    listed_model_count: int | None = None
    supported_methods: tuple[str, ...] | None = None


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


def _probe(name: str, action: Callable[[], object]) -> tuple[ProbeResult, object | None]:
    try:
        return ProbeResult(name=name, category="OK"), action()
    except GenerationProviderError as exc:
        return (
            ProbeResult(
                name=name,
                category=PROVIDER_CATEGORIES.get(exc.code, "SAFE_UNEXPECTED_FAILURE"),
                status_code=exc.status_code,
                safe_reason_code=exc.safe_reason_code,
            ),
            None,
        )
    except Exception:
        return ProbeResult(name=name, category="SAFE_UNEXPECTED_FAILURE"), None


def execute_live(
    *,
    config_loader: Callable[[], GeminiImageConfig] = _load_gemini_config,
    provider_factory: Callable[..., GeminiImageProvider] = GeminiImageProvider,
) -> DiagnosticOutcome:
    """Run only read-only probes; never submit a generation request."""
    try:
        config = config_loader()
    except Exception:
        return DiagnosticOutcome(category="CONFIGURATION_ERROR")
    provider = provider_factory(
        api_key=config.api_key.get_secret_value(),
        timeout_seconds=config.timeout_seconds,
        max_image_bytes=config.max_image_bytes,
    )
    listing_probe, listing = _probe("model_listing", provider.list_models)
    model_listed: bool | None = None
    listed_count: int | None = None
    if isinstance(listing, tuple):
        listed_count = len(listing)
        model_listed = config.model in listing
    metadata_probe, access = _probe(
        "model_metadata", lambda: provider.preflight_model(config.model)
    )
    supported = getattr(access, "supported_methods", None)
    probes = (listing_probe, metadata_probe)
    failures = tuple(probe for probe in probes if not probe.passed)
    return DiagnosticOutcome(
        category="OK" if not failures else failures[0].category,
        model=config.model,
        probes=probes,
        model_listed=model_listed,
        listed_model_count=listed_count,
        supported_methods=supported if isinstance(supported, tuple) else None,
    )


def _print_outcome(outcome: DiagnosticOutcome) -> None:
    print(f"provider: {GOOGLE_GEMINI_PROVIDER}")
    print(f"configured model: {outcome.model or 'UNAVAILABLE'}")
    display_name = provider_model_display_name(GOOGLE_GEMINI_PROVIDER, outcome.model)
    print(f"provider model name: {display_name or 'UNDECLARED'}")
    print(f"generation endpoint: {GEMINI_INTERACTIONS_PATH} (not contacted)")
    print(f"read-only endpoint: {GEMINI_MODELS_PATH} (api version {GEMINI_API_VERSION})")
    print(
        "model appears in listing: "
        + ("UNKNOWN" if outcome.model_listed is None else str(outcome.model_listed).lower())
    )
    if outcome.listed_model_count is not None:
        print(f"listed model count: {outcome.listed_model_count}")
    if outcome.supported_methods is not None:
        print(f"supported methods: {', '.join(outcome.supported_methods) or 'NONE DECLARED'}")
    print("probe table:")
    for probe in outcome.probes:
        status = "UNAVAILABLE" if probe.status_code is None else str(probe.status_code)
        print(
            f"{'PASS' if probe.passed else 'FAIL'}: {probe.name} "
            f"(category={probe.category}, http_status={status}, "
            f"reason={probe.safe_reason_code or 'UNDECLARED'}, "
            f"domain={probe.failure_domain})"
        )
    print(f"normalized safe category: {outcome.category}")
    print(
        "NOTE: a read-only model result never blocks generation; "
        "run scripts\\smoke_gemini_image_provider.py --live to prove the generation path."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run read-only Google Gemini access diagnostics without generating media."
        )
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Allow read-only Gemini model requests. No media is generated.",
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
