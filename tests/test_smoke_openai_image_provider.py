"""Zero-network tests for the isolated OpenAI image-provider checkpoint."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

import scripts.smoke_openai_image_provider as smoke
from api.firemark.generation.fake_provider import _TINY_PNG
from api.firemark.generation.models import GeneratedImage
from api.firemark.generation.openai_provider import OpenAIImageProvider
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.settings import OpenAIImageConfig


def config(*, secret: str = "test-only-openai-secret") -> OpenAIImageConfig:
    return OpenAIImageConfig(
        api_key=SecretStr(secret),
        model="gpt-image-test",
        size="1024x1024",
        timeout_seconds=30,
        max_image_bytes=1024 * 1024,
    )


def generated() -> GeneratedImage:
    return GeneratedImage(
        data=_TINY_PNG,
        provider="openai",
        model="gpt-image-test",
        provider_created_at=datetime.now(UTC),
        ai_generated=True,
    )


class FakeProvider:
    def __init__(
        self,
        *,
        failure_stage: str | None = None,
        error: Exception | None = None,
    ) -> None:
        self.failure_stage = failure_stage
        self.error = error or RuntimeError("private raw service message")
        self.operations: list[str] = []

    def _operation(self, stage: str, result: object) -> object:
        self.operations.append(stage)
        if self.failure_stage == stage:
            raise self.error
        return result

    def construct_client(self) -> object:
        return self._operation("client_construction", object())

    def build_request_parameters(self, request: object) -> dict[str, object]:
        return self._operation(
            "provider_request_construction", {"request": request}
        )  # type: ignore[return-value]

    def request_image(self, client: object, parameters: object) -> object:
        del client, parameters
        return self._operation("provider_generation", object())

    def validate_response(self, response: object, request: object) -> GeneratedImage:
        del response, request
        return self._operation(
            "provider_response_validation", generated()
        )  # type: ignore[return-value]


def execute(provider: object) -> smoke.SmokeOutcome:
    return smoke.execute_live(
        config_loader=config,
        provider_factory=lambda **_kwargs: provider,  # type: ignore[arg-type]
    )


def test_non_live_is_informational_and_never_constructs_client(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        smoke,
        "execute_live",
        lambda: (_ for _ in ()).throw(AssertionError("live path must not execute")),
    )
    assert smoke.main([]) == 2
    output = capsys.readouterr().out
    assert "zero network calls" in output
    assert "no OpenAI client was constructed" in output


def test_help_contract_and_successful_stage_order() -> None:
    assert "--live" in smoke.build_parser().format_help()
    provider = FakeProvider()
    outcome = execute(provider)
    assert outcome.category == "OK"
    assert outcome.exit_code == 0
    assert tuple(stage for stage, status in outcome.stages if status == "PASS") == smoke.STAGES
    assert provider.operations == [
        "client_construction",
        "provider_request_construction",
        "provider_generation",
        "provider_response_validation",
    ]


@pytest.mark.parametrize(
    ("provider_code", "category", "exit_code"),
    [
        ("authentication", "AUTHENTICATION_FAILURE", 30),
        ("permission_denied", "PERMISSION_DENIED", 30),
        ("quota_or_billing", "QUOTA_OR_BILLING_FAILURE", 31),
        ("rate_limit", "RATE_LIMIT", 32),
        ("invalid_request", "INVALID_REQUEST", 33),
        ("model_or_size_unsupported", "MODEL_OR_SIZE_UNSUPPORTED", 33),
        ("safety_rejection", "SAFETY_REJECTION", 34),
        ("timeout", "TIMEOUT", 40),
        ("unavailable", "PROVIDER_UNAVAILABLE", 40),
        ("malformed_response", "MALFORMED_RESPONSE", 50),
        ("non_png_response", "NON_PNG_RESPONSE", 50),
        ("response_too_large", "RESPONSE_TOO_LARGE", 50),
    ],
)
def test_provider_failures_have_explicit_safe_categories_and_exit_codes(
    provider_code: str, category: str, exit_code: int
) -> None:
    provider = FakeProvider(
        failure_stage="provider_response_validation",
        error=GenerationProviderError(provider_code),  # type: ignore[arg-type]
    )
    outcome = execute(provider)
    assert outcome.category == category
    assert outcome.exit_code == exit_code
    assert outcome.provider_code == provider_code
    assert outcome.stages[-1] == ("provider_response_validation", "FAIL")


@pytest.mark.parametrize(
    ("stage", "category"),
    [
        ("client_construction", "CLIENT_CONSTRUCTION_ERROR"),
        ("provider_request_construction", "REQUEST_CONSTRUCTION_ERROR"),
        ("provider_generation", "UNKNOWN_SAFE_ERROR"),
    ],
)
def test_local_failures_are_attributed_to_the_operation_already_in_progress(
    stage: str, category: str
) -> None:
    outcome = execute(FakeProvider(failure_stage=stage))
    assert outcome.category == category
    assert outcome.stages[-1] == (stage, "FAIL")


def _real_provider_factory(
    response: object,
    *,
    http_client_factory: Any | None = None,
) -> Any:
    class Images:
        calls = 0

        @classmethod
        def generate(cls, **kwargs: object) -> object:
            del kwargs
            cls.calls += 1
            return response

    def factory(**kwargs: Any) -> OpenAIImageProvider:
        extra = (
            {"http_client_factory": http_client_factory}
            if http_client_factory is not None
            else {}
        )
        return OpenAIImageProvider(
            **kwargs,
            client_factory=lambda: SimpleNamespace(images=Images()),
            **extra,
        )

    return factory, Images


def test_successful_base64_png_response_uses_one_generation_request() -> None:
    item = SimpleNamespace(b64_json=base64.b64encode(_TINY_PNG).decode(), url=None)
    factory, images = _real_provider_factory(SimpleNamespace(data=[item], created=1))
    outcome = smoke.execute_live(config_loader=config, provider_factory=factory)
    assert outcome.category == "OK"
    assert outcome.image is not None and outcome.image.data == _TINY_PNG
    assert images.calls == 1


def test_successful_supported_url_response_is_safe_and_downloaded_once() -> None:
    provider_url = "https://images.openai.com/private-provider-path?token=private"
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=_TINY_PNG)

    item = SimpleNamespace(b64_json=None, url=provider_url)
    factory, images = _real_provider_factory(
        SimpleNamespace(data=[item], created=1),
        http_client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ),
    )
    outcome = smoke.execute_live(config_loader=config, provider_factory=factory)
    assert outcome.category == "OK"
    assert images.calls == 1
    assert len(requests) == 1
    assert provider_url not in repr(outcome)


def test_safe_output_excludes_key_prompt_url_and_raw_service_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "test-api-key-must-never-print"
    provider_url = "https://images.openai.com/private?token=must-not-print"
    raw = "private raw service message must-not-print"
    provider = FakeProvider(
        failure_stage="provider_generation",
        error=RuntimeError(f"{secret} {smoke.SMOKE_PROMPT} {provider_url} {raw}"),
    )
    outcome = smoke.execute_live(
        config_loader=lambda: config(secret=secret),
        provider_factory=lambda **_kwargs: provider,  # type: ignore[arg-type]
    )
    smoke._print_outcome(outcome)
    output = capsys.readouterr().out
    assert secret not in output
    assert smoke.SMOKE_PROMPT not in output
    assert provider_url not in output
    assert raw not in output
    assert "UNKNOWN_SAFE_ERROR" in output


def test_configuration_error_does_not_construct_adapter() -> None:
    constructed = False

    def factory(**kwargs: object) -> object:
        nonlocal constructed
        del kwargs
        constructed = True
        return object()

    outcome = smoke.execute_live(
        config_loader=lambda: (_ for _ in ()).throw(ValueError("private config")),
        provider_factory=factory,  # type: ignore[arg-type]
    )
    assert outcome.category == "CONFIGURATION_ERROR"
    assert outcome.exit_code == 10
    assert outcome.stages == (("configuration_validation", "FAIL"),)
    assert constructed is False
