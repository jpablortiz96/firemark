"""Zero-network tests for the isolated Google Gemini image-provider checkpoint.

Every test in this module mocks transport. No test contacts Google Gemini,
GMI Cloud, OpenAI, ElevenLabs, Backblaze B2, or Supabase.
"""

from __future__ import annotations

import base64
import json
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

import scripts.diagnose_gemini_access as diagnose
import scripts.smoke_gemini_image_provider as smoke
import scripts.smoke_multimodal_generate_and_seal as multimodal
from api.firemark.generation.fake_provider import _TINY_PNG
from api.firemark.generation.gemini_provider import (
    GEMINI_API_BASE_URL,
    GEMINI_INTERACTIONS_PATH,
    GeminiImageProvider,
)
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.generation.provider_identity import provider_model_display_name
from api.firemark.settings import GeminiImageConfig

NOW = datetime(2026, 7, 30, 22, tzinfo=UTC)
MODEL = "gemini-3.1-flash-image"
FORBIDDEN_HOSTS = ("gmi", "replicate", "openai", "elevenlabs")


def config(*, secret: str = "test-gemini-secret") -> GeminiImageConfig:
    return GeminiImageConfig(
        api_key=SecretStr(secret),
        model=MODEL,
        timeout_seconds=30,
        max_image_bytes=1024 * 1024,
    )


def request(prompt: str = "private prompt") -> GenerationRequest:
    return GenerationRequest(
        prompt=prompt,
        model=MODEL,
        size="1024x1024",
        request_id="firemark-gemini-test",
    )


def interaction_body(
    *,
    data: str | None = None,
    mime_type: str = "image/png",
    status: str = "completed",
    use_steps: bool = False,
    image_blocks: int = 1,
) -> dict[str, object]:
    image = {
        "type": "image",
        "mime_type": mime_type,
        "data": data if data is not None else base64.b64encode(_TINY_PNG).decode(),
    }
    body: dict[str, object] = {"id": "interaction-1", "object": "interaction", "status": status}
    if use_steps:
        body["steps"] = [
            {
                "type": "model_output",
                "content": [{"type": "text", "text": "ignored"}]
                + [dict(image) for _ in range(image_blocks)],
            }
        ]
    else:
        body["output_image"] = image
    return body


def client(handler: Any) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url=GEMINI_API_BASE_URL,
    )


def provider(handler: Any, *, secret: str = "test-gemini-secret") -> GeminiImageProvider:
    return GeminiImageProvider(
        api_key=secret,
        timeout_seconds=30,
        max_image_bytes=1024 * 1024,
        client_factory=lambda: client(handler),
        now=lambda: NOW,
    )


def ok_provider() -> GeminiImageProvider:
    return provider(lambda _request: httpx.Response(200, json=interaction_body()))


def failing_transport(failure: Exception) -> GeminiImageProvider:
    return provider(lambda _request: (_ for _ in ()).throw(failure))


# --------------------------------------------------------------------------
# Command surface
# --------------------------------------------------------------------------


def test_non_live_constructs_no_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        smoke,
        "execute_live",
        lambda **_kwargs: pytest.fail("live execution must remain opt-in"),
    )
    assert smoke.main([]) == 2


def test_help_contract() -> None:
    help_text = smoke.build_parser().format_help()
    assert "--live" in help_text
    assert "--allow-definitive-retry" in help_text


def test_diagnostic_non_live_constructs_no_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        diagnose,
        "execute_live",
        lambda **_kwargs: pytest.fail("live diagnostics must remain opt-in"),
    )
    assert diagnose.main([]) == 2
    assert "--live" in diagnose.build_parser().format_help()


# --------------------------------------------------------------------------
# Official Interactions request contract
# --------------------------------------------------------------------------


def test_google_ai_studio_key_authenticates_only_with_x_goog_api_key() -> None:
    calls: list[httpx.Request] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        calls.append(http_request)
        assert http_request.method == "POST"
        assert http_request.url.path == GEMINI_INTERACTIONS_PATH == "/v1beta/interactions"
        assert http_request.url.host == "generativelanguage.googleapis.com"
        assert http_request.headers["x-goog-api-key"] == "test-gemini-secret"
        assert "authorization" not in http_request.headers
        assert http_request.headers["content-type"].startswith("application/json")
        return httpx.Response(200, json=interaction_body())

    result = provider(handler).generate_image(request())
    assert result.data == _TINY_PNG
    assert len(calls) == 1


def test_official_minimal_request_structure_uses_exact_configured_model() -> None:
    captured: list[dict[str, Any]] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        payload = json.loads(http_request.content)
        captured.append(payload)
        return httpx.Response(200, json=interaction_body())

    provider(handler).generate_image(request())
    assert captured == [
        {
            "model": MODEL,
            "input": [{"type": "text", "text": "private prompt"}],
            "response_format": {"type": "image", "mime_type": "image/png"},
        }
    ]
    assert captured[0]["model"] == MODEL
    assert "contents" not in captured[0]
    assert "generationConfig" not in captured[0]


def test_model_field_never_carries_a_duplicate_resource_prefix() -> None:
    payload = GeminiImageProvider.build_request_parameters(request())
    assert not str(payload["model"]).startswith("models/")
    prefixed = request().model_copy(update={"model": "models/gemini-3.1-flash-image"})
    with pytest.raises(GenerationProviderError) as caught:
        GeminiImageProvider.build_request_parameters(prefixed)
    assert caught.value.code == "invalid_request"
    assert caught.value.safe_reason_code == "DUPLICATE_MODEL_PREFIX"


def test_request_never_targets_gmi_cloud_or_another_provider() -> None:
    seen: list[str] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        seen.append(str(http_request.url))
        return httpx.Response(200, json=interaction_body())

    default = GeminiImageProvider(api_key="secret", timeout_seconds=5, max_image_bytes=1024)
    default_client = default._client()
    assert str(default_client.base_url) == GEMINI_API_BASE_URL
    default_client.close()
    provider(handler).generate_image(request())
    assert seen == [f"{GEMINI_API_BASE_URL}{GEMINI_INTERACTIONS_PATH}"]
    assert all(token not in url.lower() for url in seen for token in FORBIDDEN_HOSTS)


def test_provider_size_is_recorded_but_never_sent() -> None:
    first = GeminiImageProvider.build_request_parameters(request())
    second = GeminiImageProvider.build_request_parameters(
        request().model_copy(update={"size": "1792x1024"})
    )
    assert first == second
    assert set(first) == {"model", "input", "response_format"}


# --------------------------------------------------------------------------
# Response extraction
# --------------------------------------------------------------------------


@pytest.mark.parametrize("use_steps", [False, True])
def test_successful_image_extraction_from_documented_shapes(use_steps: bool) -> None:
    result = provider(
        lambda _request: httpx.Response(200, json=interaction_body(use_steps=use_steps))
    ).generate_image(request())
    assert result.data == _TINY_PNG
    assert result.media_type == "image/png"
    assert result.file_extension == "png"


def test_generated_image_reports_accurate_provider_identity() -> None:
    result = ok_provider().generate_image(request())
    assert result.provider == "google_gemini"
    assert result.model == MODEL
    assert result.ai_generated is True
    assert result.media_type == "image/png"
    metadata = result.safe_generation_metadata
    assert metadata["provider_model_name"] == "Nano Banana 2"
    assert metadata["provider_api"] == "interactions"
    assert metadata["provider_api_version"] == "v1beta"
    assert provider_model_display_name("google_gemini", MODEL) == "Nano Banana 2"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"id": "x", "status": "completed"}, "malformed_response"),
        ({"id": "x", "status": "completed", "steps": []}, "malformed_response"),
        ({"id": "x", "status": "completed", "steps": "invalid"}, "malformed_response"),
        (interaction_body(use_steps=True, image_blocks=2), "malformed_response"),
        (interaction_body(data="%%%"), "malformed_response"),
        (interaction_body(data=""), "malformed_response"),
        (interaction_body(mime_type="image/jpeg"), "non_png_response"),
        (interaction_body(mime_type="image/webp"), "non_png_response"),
        (interaction_body(data=base64.b64encode(b"not-png").decode()), "non_png_response"),
        (interaction_body(status="failed"), "malformed_response"),
        (interaction_body(status="in_progress"), "malformed_response"),
        (interaction_body(status="budget_exceeded"), "quota_or_billing"),
    ],
)
def test_missing_malformed_or_unsupported_images_fail_closed(
    body: dict[str, object], code: str
) -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(200, json=body)).generate_image(request())
    assert caught.value.code == code


def test_oversized_declared_and_decoded_responses_fail_closed() -> None:
    bounded = GeminiImageProvider(api_key="secret", timeout_seconds=30, max_image_bytes=10)
    with pytest.raises(GenerationProviderError) as decoded:
        bounded.validate_response(httpx.Response(200, json=interaction_body()), request())
    assert decoded.value.code == "response_too_large"
    streamed = provider(
        lambda _request: httpx.Response(
            200, headers={"content-length": str(8 * 1024 * 1024)}, json=interaction_body()
        )
    )
    with pytest.raises(GenerationProviderError) as declared:
        streamed.generate_image(request())
    assert declared.value.code == "response_too_large"


def test_redirects_and_unreadable_content_length_fail_closed() -> None:
    with pytest.raises(GenerationProviderError) as redirected:
        provider(lambda _request: httpx.Response(302)).generate_image(request())
    assert redirected.value.code == "malformed_response"
    with pytest.raises(GenerationProviderError) as unreadable:
        provider(
            lambda _request: httpx.Response(
                200, headers={"content-length": "invalid"}, json=interaction_body()
            )
        ).generate_image(request())
    assert unreadable.value.code == "malformed_response"


# --------------------------------------------------------------------------
# Safe failure classification
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "error", "code", "category"),
    [
        (
            400,
            {"status": "INVALID_ARGUMENT", "message": "invalid field"},
            "invalid_request",
            "INVALID_REQUEST",
        ),
        (
            400,
            {"status": "INVALID_ARGUMENT", "message": "model is unsupported"},
            "model_or_size_unsupported",
            "MODEL_UNSUPPORTED",
        ),
        (
            400,
            {"status": "FAILED_PRECONDITION", "message": "blocked by safety"},
            "safety_rejection",
            "SAFETY_REJECTION",
        ),
        (
            401,
            {"status": "UNAUTHENTICATED", "message": "api key not valid"},
            "authentication",
            "AUTHENTICATION_FAILURE",
        ),
        (
            403,
            {"status": "PERMISSION_DENIED", "message": "caller lacks permission"},
            "permission_denied",
            "PERMISSION_DENIED",
        ),
        (
            403,
            {"status": "RESOURCE_EXHAUSTED", "message": "quota exhausted"},
            "quota_or_billing",
            "QUOTA_OR_BILLING_FAILURE",
        ),
        (
            404,
            {"status": "NOT_FOUND", "message": "model was not found"},
            "model_or_size_unsupported",
            "MODEL_UNSUPPORTED",
        ),
        (
            429,
            {"status": "RESOURCE_EXHAUSTED", "message": "rate limited"},
            "rate_limit",
            "RATE_LIMIT",
        ),
        (
            429,
            {"status": "RESOURCE_EXHAUSTED", "message": "billing quota"},
            "quota_or_billing",
            "QUOTA_OR_BILLING_FAILURE",
        ),
        (
            500,
            {"status": "INTERNAL", "message": "private raw message"},
            "unavailable",
            "PROVIDER_UNAVAILABLE",
        ),
        (
            503,
            {"status": "UNAVAILABLE", "message": "private raw message"},
            "unavailable",
            "PROVIDER_UNAVAILABLE",
        ),
    ],
)
def test_http_statuses_remain_distinguishable_and_safe(
    status: int, error: dict[str, str], code: str, category: str
) -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(status, json={"error": error})
        ).generate_image(request("secret prompt"))
    assert caught.value.code == code
    assert caught.value.status_code == status
    assert caught.value.safe_reason_code == error["status"]
    assert smoke.PROVIDER_CATEGORIES[code] == category
    rendered = str(caught.value)
    assert error["message"] not in rendered
    assert "secret prompt" not in rendered
    assert "test-gemini-secret" not in rendered


def test_timeout_is_distinct_from_provider_unavailable() -> None:
    with pytest.raises(GenerationProviderError) as caught:
        failing_transport(httpx.ReadTimeout("boom")).generate_image(request())
    assert caught.value.code == "timeout"
    assert caught.value.safe_reason_code == "TRANSPORT_TIMEOUT"
    assert smoke.PROVIDER_CATEGORIES["timeout"] == "TIMEOUT"


def test_dns_and_transport_failures_are_distinguishable_from_http_5xx() -> None:
    resolution = httpx.ConnectError("offline")
    resolution.__cause__ = socket.gaierror("name resolution failed")
    cases = {
        "DNS_RESOLUTION_FAILURE": resolution,
        "TRANSPORT_CONNECT_FAILURE": httpx.ConnectError("refused"),
        "TRANSPORT_PROXY_FAILURE": httpx.ProxyError("proxy"),
        "TRANSPORT_FAILURE": httpx.ReadError("reset"),
    }
    for reason, failure in cases.items():
        with pytest.raises(GenerationProviderError) as caught:
            failing_transport(failure).generate_image(request())
        assert caught.value.code == "unavailable"
        assert caught.value.status_code is None
        assert caught.value.safe_reason_code == reason
        assert str(failure) not in str(caught.value)
    with pytest.raises(GenerationProviderError) as server_error:
        provider(lambda _request: httpx.Response(503)).generate_image(request())
    assert server_error.value.code == "unavailable"
    assert server_error.value.status_code == 503
    assert server_error.value.safe_reason_code == "HTTP_503"


def test_exceptions_never_carry_prompt_key_or_raw_response() -> None:
    secret_prompt = "the private prompt that must never leak"
    raw = {"error": {"status": "INVALID_ARGUMENT", "message": "raw provider detail"}}
    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(400, json=raw), secret="super-secret-key"
        ).generate_image(request(secret_prompt))
    rendered = f"{caught.value!r} {caught.value!s} {caught.value.args}"
    assert secret_prompt not in rendered
    assert "super-secret-key" not in rendered
    assert "raw provider detail" not in rendered
    assert json.dumps(raw) not in rendered


# --------------------------------------------------------------------------
# Read-only diagnostic and preflight policy
# --------------------------------------------------------------------------


def test_model_listing_and_metadata_are_read_only() -> None:
    seen: list[httpx.Request] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        seen.append(http_request)
        assert http_request.method == "GET"
        assert http_request.headers["x-goog-api-key"] == "test-gemini-secret"
        if http_request.url.path == "/v1beta/models":
            return httpx.Response(
                200, json={"models": [{"name": f"models/{MODEL}"}, {"name": "models/other"}]}
            )
        return httpx.Response(
            200,
            json={
                "name": f"models/{MODEL}",
                "supportedGenerationMethods": ["generateContent", "countTokens"],
            },
        )

    instance = provider(handler)
    assert instance.list_models() == (MODEL, "other")
    access = instance.preflight_model(MODEL)
    assert access.available is True
    assert access.supported_methods == ("generateContent", "countTokens")
    assert [call.url.path for call in seen] == ["/v1beta/models", f"/v1beta/models/{MODEL}"]


def test_preflight_uses_the_same_api_version_as_generation() -> None:
    versions: list[str] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        versions.append(http_request.url.path.split("/")[1])
        if http_request.method == "GET":
            return httpx.Response(200, json={"name": f"models/{MODEL}"})
        return httpx.Response(200, json=interaction_body())

    instance = provider(handler)
    instance.preflight_model(MODEL)
    instance.generate_image(request())
    assert versions == ["v1beta", "v1beta"]


@pytest.mark.parametrize(
    ("status", "code"),
    [(401, "authentication"), (403, "permission_denied"), (404, "model_or_size_unsupported"), (429, "rate_limit")],
)
def test_read_only_probe_failures_stay_distinguishable(status: int, code: str) -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(status)).preflight_model(MODEL)
    assert caught.value.code == code
    assert caught.value.status_code == status


@pytest.mark.parametrize(
    "payload", [[], {"name": "models/other"}, {"name": f"models/{MODEL}", "supportedGenerationMethods": [1]}]
)
def test_preflight_rejects_malformed_metadata(payload: object) -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(200, json=payload)).preflight_model(MODEL)
    assert caught.value.code == "malformed_response"


def test_model_listing_rejects_malformed_payloads() -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(200, json={"models": "invalid"})).list_models()
    assert caught.value.code == "malformed_response"
    assert provider(
        lambda _request: httpx.Response(200, json={"models": [{"name": 1}, "bad"]})
    ).list_models() == ()


def test_read_only_probes_reject_redirects_and_unbounded_bodies() -> None:
    with pytest.raises(GenerationProviderError) as redirected:
        provider(lambda _request: httpx.Response(302)).list_models()
    assert redirected.value.code == "malformed_response"
    oversized = provider(
        lambda _request: httpx.Response(200, content=b"x" * (600 * 1024))
    )
    with pytest.raises(GenerationProviderError) as unbounded:
        oversized.preflight_model(MODEL)
    assert unbounded.value.code == "response_too_large"


class UndeclaredStream(httpx.SyncByteStream):
    """A chunked body that never declares its length up front."""

    def __init__(self, chunks: int) -> None:
        self.chunks = chunks

    def __iter__(self) -> Any:
        for _ in range(self.chunks):
            yield b"x" * (1024 * 1024)


def test_streamed_generation_body_is_bounded_without_content_length() -> None:
    bounded = GeminiImageProvider(
        api_key="secret",
        timeout_seconds=30,
        max_image_bytes=1024 * 1024,
        client_factory=lambda: client(
            lambda _request: httpx.Response(200, stream=UndeclaredStream(4))
        ),
    )
    with pytest.raises(GenerationProviderError) as caught:
        bounded.generate_image(request())
    assert caught.value.code == "response_too_large"


def test_decoded_image_exceeding_the_limit_fails_after_a_bounded_body() -> None:
    response = httpx.Response(200, json=interaction_body())
    del response.headers["content-length"]
    bounded = GeminiImageProvider(api_key="secret", timeout_seconds=30, max_image_bytes=8)
    with pytest.raises(GenerationProviderError) as caught:
        bounded.validate_response(response, request())
    assert caught.value.code == "response_too_large"


def test_model_listing_rejects_a_non_object_payload() -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(200, json=["unexpected"])).list_models()
    assert caught.value.code == "malformed_response"


def test_non_object_body_and_camel_case_image_key_are_handled() -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(200, json=["unexpected"])).generate_image(
            request()
        )
    assert caught.value.code == "malformed_response"
    camel = {
        "status": "completed",
        "output_image": {
            "type": "image",
            "mimeType": "image/png",
            "data": base64.b64encode(_TINY_PNG).decode(),
        },
    }
    assert provider(
        lambda _request: httpx.Response(200, json=camel)
    ).generate_image(request()).data == _TINY_PNG


def test_steps_without_content_are_skipped_and_invalid_content_fails() -> None:
    skipped = {
        "status": "completed",
        "steps": [
            {"type": "user_input"},
            {
                "type": "model_output",
                "content": [
                    {
                        "type": "image",
                        "mime_type": "image/png",
                        "data": base64.b64encode(_TINY_PNG).decode(),
                    }
                ],
            },
        ],
    }
    assert provider(
        lambda _request: httpx.Response(200, json=skipped)
    ).generate_image(request()).data == _TINY_PNG
    invalid = {"status": "completed", "steps": [{"content": "not-a-list"}]}
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(200, json=invalid)).generate_image(request())
    assert caught.value.code == "malformed_response"


def test_unknown_provider_or_model_has_no_marketing_name() -> None:
    assert provider_model_display_name(None, MODEL) is None
    assert provider_model_display_name("google_gemini", None) is None
    assert provider_model_display_name("google_gemini", "unknown-model") is None
    assert provider_model_display_name("gemini", MODEL) == "Nano Banana 2"


def test_diagnostic_separates_transport_from_endpoint_failures() -> None:
    resolution = httpx.ConnectError("offline")
    resolution.__cause__ = socket.gaierror("no such host")
    outcome = diagnose.execute_live(
        config_loader=config,
        provider_factory=lambda **_kwargs: failing_transport(resolution),
    )
    assert outcome.category == "PROVIDER_UNAVAILABLE"
    assert {probe.failure_domain for probe in outcome.probes} == {"TRANSPORT"}
    assert all(probe.safe_reason_code == "DNS_RESOLUTION_FAILURE" for probe in outcome.probes)
    endpoint = diagnose.execute_live(
        config_loader=config,
        provider_factory=lambda **_kwargs: provider(lambda _request: httpx.Response(401)),
    )
    assert endpoint.category == "AUTHENTICATION_FAILURE"
    assert {probe.failure_domain for probe in endpoint.probes} == {"ENDPOINT"}


def test_diagnostic_reports_model_listing_without_generating(
    capsys: pytest.CaptureFixture[str],
) -> None:
    def handler(http_request: httpx.Request) -> httpx.Response:
        assert http_request.method == "GET"
        if http_request.url.path == "/v1beta/models":
            return httpx.Response(200, json={"models": [{"name": f"models/{MODEL}"}]})
        return httpx.Response(
            200, json={"name": f"models/{MODEL}", "supportedGenerationMethods": ["generateContent"]}
        )

    outcome = diagnose.execute_live(
        config_loader=lambda: config(secret="diagnostic-secret"),
        provider_factory=lambda **_kwargs: provider(handler, secret="diagnostic-secret"),
    )
    assert outcome.category == "OK"
    assert outcome.model_listed is True
    assert outcome.supported_methods == ("generateContent",)
    diagnose._print_outcome(outcome)
    output = capsys.readouterr().out
    assert "diagnostic-secret" not in output
    assert smoke.SMOKE_PROMPT not in output
    assert "google_gemini" in output and "Nano Banana 2" in output
    assert "model appears in listing: true" in output


def test_diagnostic_reports_configuration_error_without_a_client() -> None:
    def refuse(**_kwargs: object) -> GeminiImageProvider:
        pytest.fail("a client must not be constructed for an invalid configuration")

    outcome = diagnose.execute_live(
        config_loader=lambda: (_ for _ in ()).throw(ValueError("missing key")),
        provider_factory=refuse,
    )
    assert outcome.category == "CONFIGURATION_ERROR"
    assert outcome.probes == ()


def test_preflight_failure_cannot_block_a_valid_generation(tmp_path: Path) -> None:
    """A model-listing problem must never stop a working generation path."""

    class HostileMetadata(GeminiImageProvider):
        def list_models(self) -> tuple[str, ...]:
            raise GenerationProviderError("unavailable", status_code=503)

        def preflight_model(self, model: str) -> Any:
            raise GenerationProviderError("model_or_size_unsupported", status_code=404)

    hostile = HostileMetadata(
        api_key="secret",
        timeout_seconds=30,
        max_image_bytes=1024 * 1024,
        client_factory=lambda: client(
            lambda _request: httpx.Response(200, json=interaction_body())
        ),
        now=lambda: NOW,
    )
    outcome = smoke.execute_live(
        config_loader=config,
        provider_factory=lambda **_kwargs: hostile,
        checkpoint_path=tmp_path / "checkpoint.json",
        private_root=tmp_path / "private",
    )
    assert outcome.category == "OK"
    assert outcome.provider_calls == 1
    assert [stage for stage, _status in outcome.stages] == list(smoke.STAGES)
    assert "model_access_preflight" not in dict(outcome.stages)


# --------------------------------------------------------------------------
# Checkpoint recovery
# --------------------------------------------------------------------------


class CountingProvider:
    def __init__(self, result: GeneratedImage | Exception) -> None:
        self.result = result
        self.calls = 0

    def generate_image(self, _request: GenerationRequest) -> GeneratedImage:
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def generated_image() -> GeneratedImage:
    return GeneratedImage(
        data=_TINY_PNG,
        provider="google_gemini",
        model=MODEL,
        provider_created_at=NOW,
        ai_generated=True,
    )


def run_smoke(
    tmp_path: Path, instance: object, *, allow_definitive_retry: bool = False
) -> smoke.SmokeOutcome:
    return smoke.execute_live(
        config_loader=config,
        provider_factory=lambda **_kwargs: instance,  # type: ignore[arg-type,return-value]
        checkpoint_path=tmp_path / "checkpoint.json",
        private_root=tmp_path / "private",
        allow_definitive_retry=allow_definitive_retry,
    )


def test_exactly_one_generation_call_and_state_is_persisted(tmp_path: Path) -> None:
    counting = CountingProvider(generated_image())
    outcome = run_smoke(tmp_path, counting)
    assert outcome.category == "OK"
    assert counting.calls == 1
    stored = smoke.CheckpointStore(tmp_path / "checkpoint.json", tmp_path / "private").read()
    assert stored.operation_state == "complete"
    assert stored.new_provider_calls == 1
    assert stored.provider == "google_gemini"
    assert stored.source_sha256 == outcome.source_sha256
    assert Path(str(stored.source_path)).read_bytes() == _TINY_PNG


def test_recovery_reuses_persisted_png_and_never_calls_gemini_again(tmp_path: Path) -> None:
    first = CountingProvider(generated_image())
    assert run_smoke(tmp_path, first).category == "OK"

    def refuse(_request: GenerationRequest) -> GeneratedImage:
        pytest.fail("Gemini must never be called again after bytes are persisted")

    class RefusingProvider:
        generate_image = staticmethod(refuse)

    second = run_smoke(tmp_path, RefusingProvider())
    assert second.category == "OK"
    assert second.recovered is True
    assert second.provider_calls == 0
    assert second.source_sha256 == run_smoke(tmp_path, RefusingProvider()).source_sha256


def test_ambiguous_prior_submission_never_submits_again(tmp_path: Path) -> None:
    store = smoke.CheckpointStore(tmp_path / "checkpoint.json", tmp_path / "private")
    store.write(
        smoke.GeminiProviderCheckpoint(
            operation_state="provider_call_started",
            model=MODEL,
            request_id=smoke.SMOKE_REQUEST_ID,
            created_at=NOW,
            new_provider_calls=1,
        )
    )
    counting = CountingProvider(generated_image())
    outcome = run_smoke(tmp_path, counting)
    assert outcome.category == "AMBIGUOUS_PRIOR_SUBMISSION"
    assert counting.calls == 0


def rejected(tmp_path: Path, code: str) -> smoke.SmokeOutcome:
    failure = GenerationProviderError(code, status_code=400)  # type: ignore[arg-type]
    return run_smoke(tmp_path, CountingProvider(failure))


def test_definitive_rejection_permits_one_authorized_retry(tmp_path: Path) -> None:
    first = rejected(tmp_path, "invalid_request")
    assert first.category == "INVALID_REQUEST"
    assert first.retry_permitted is True
    blocked = CountingProvider(generated_image())
    assert run_smoke(tmp_path, blocked).category == "AMBIGUOUS_PRIOR_SUBMISSION"
    assert blocked.calls == 0
    authorized = CountingProvider(generated_image())
    assert run_smoke(tmp_path, authorized, allow_definitive_retry=True).category == "OK"
    assert authorized.calls == 1


@pytest.mark.parametrize("code", ["timeout", "unavailable", "rate_limit", "malformed_response"])
def test_ambiguous_rejection_is_never_retried(tmp_path: Path, code: str) -> None:
    first = rejected(tmp_path, code)
    assert first.retry_permitted is False
    counting = CountingProvider(generated_image())
    assert (
        run_smoke(tmp_path, counting, allow_definitive_retry=True).category
        == "AMBIGUOUS_PRIOR_SUBMISSION"
    )
    assert counting.calls == 0


def test_configuration_change_fails_closed(tmp_path: Path) -> None:
    assert run_smoke(tmp_path, CountingProvider(generated_image())).category == "OK"
    outcome = smoke.execute_live(
        config_loader=lambda: config().model_copy(update={"model": "gemini-3-pro-image"}),
        provider_factory=lambda **_kwargs: CountingProvider(generated_image()),  # type: ignore[arg-type,return-value]
        checkpoint_path=tmp_path / "checkpoint.json",
        private_root=tmp_path / "private",
    )
    assert outcome.category == "CONFIGURATION_ERROR"


def test_smoke_output_excludes_key_prompt_and_raw_response(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "key-must-not-print"
    failure = GenerationProviderError(
        "invalid_request", status_code=400, safe_reason_code="INVALID_ARGUMENT"
    )
    outcome = smoke.execute_live(
        config_loader=lambda: config(secret=secret),
        provider_factory=lambda **_kwargs: CountingProvider(failure),  # type: ignore[arg-type,return-value]
        checkpoint_path=tmp_path / "checkpoint.json",
        private_root=tmp_path / "private",
    )
    smoke._print_outcome(outcome)
    output = capsys.readouterr().out
    assert secret not in output
    assert smoke.SMOKE_PROMPT not in output
    assert "INVALID_ARGUMENT" in output
    assert "provider HTTP status: 400" in output
    assert "read-only model preflight: NOT PERFORMED (diagnostic-only)" in output
    stored = (tmp_path / "checkpoint.json").read_text("utf-8")
    assert secret not in stored
    assert smoke.SMOKE_PROMPT not in stored


# --------------------------------------------------------------------------
# Multimodal ordering and isolation
# --------------------------------------------------------------------------


def checkpoint(tmp_path: Path, *, code: str, retry: bool) -> multimodal.MultimodalCheckpoint:
    store = multimodal.CheckpointStore(tmp_path / "checkpoint.json", tmp_path / "private")
    signer = multimodal.Ed25519Signer.generate()
    multimodal._initialize_checkpoint(
        store,
        media_type="image",
        provider="google_gemini",
        model=MODEL,
        size="1024x1024",
        signer=signer,
        retention_days=90,
    )
    return store.update(
        operation_state="provider_rejected",
        new_provider_calls=1,
        prior_rejected_calls=1,
        provider_failure_code=code,
        provider_retry_allowed=retry,
    )


def test_invalid_request_checkpoint_may_retry(tmp_path: Path) -> None:
    assert multimodal._checkpoint_retry_allowed(checkpoint(tmp_path, code="invalid_request", retry=True))


def test_only_one_definitive_retry_is_permitted(tmp_path: Path) -> None:
    value = checkpoint(tmp_path, code="invalid_request", retry=True).model_copy(
        update={"prior_rejected_calls": 2}
    )
    assert not multimodal._checkpoint_retry_allowed(value)


@pytest.mark.parametrize("code", ["timeout", "unavailable", "rate_limit"])
def test_ambiguous_checkpoint_may_not_retry(tmp_path: Path, code: str) -> None:
    assert not multimodal._checkpoint_retry_allowed(checkpoint(tmp_path, code=code, retry=False))


def test_multimodal_runs_elevenlabs_only_after_gemini_completes() -> None:
    calls: list[str] = []

    def gemini() -> dict[str, object]:
        calls.append("gemini")
        return {"status": "complete"}

    def elevenlabs() -> dict[str, object]:
        calls.append("elevenlabs")
        return {"status": "complete"}

    multimodal._run_sequential_operations(gemini, elevenlabs)
    assert calls == ["gemini", "elevenlabs"]


def test_elevenlabs_never_starts_when_gemini_fails() -> None:
    calls: list[str] = []

    def gemini() -> dict[str, object]:
        calls.append("gemini")
        raise multimodal.LiveCheckpointError("PROVIDER_UNAVAILABLE")

    def elevenlabs() -> dict[str, object]:
        calls.append("elevenlabs")
        return {"status": "complete"}

    with pytest.raises(multimodal.LiveCheckpointError):
        multimodal._run_sequential_operations(gemini, elevenlabs)
    assert calls == ["gemini"]


def test_gemini_smoke_contacts_no_other_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("ordinary tests must make zero network calls")

    monkeypatch.setattr(httpx.Client, "send", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    assert smoke.main([]) == 2
    assert diagnose.main([]) == 2
    module_source = Path(smoke.__file__).read_text("utf-8").lower()
    assert all(token not in module_source for token in FORBIDDEN_HOSTS)
