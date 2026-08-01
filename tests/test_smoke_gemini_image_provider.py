"""Zero-network tests for the isolated Google Gemini image-provider checkpoint.

Every test in this module mocks transport. No test contacts Google Gemini,
GMI Cloud, OpenAI, ElevenLabs, Backblaze B2, or Supabase.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

import api.firemark.generate_and_seal as generate_and_seal
import api.firemark.generation.normalization as normalization
import scripts.diagnose_gemini_access as diagnose
import scripts.smoke_gemini_image_provider as smoke
import scripts.smoke_multimodal_generate_and_seal as multimodal
from api.firemark.control_plane.models import AssetRecord
from api.firemark.generation.fake_provider import _TINY_JPEG, _TINY_PNG
from api.firemark.generation.gemini_provider import (
    FORBIDDEN_REQUEST_FIELDS,
    GEMINI_API_BASE_URL,
    GEMINI_INTERACTIONS_PATH,
    GEMINI_REQUEST_MIME_TYPE,
    GEMINI_SOURCE_MIME_TYPE,
    GeminiImageProvider,
)
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.normalization import (
    ImageNormalizationError,
    inspect_image_source,
    normalize_to_png,
)
from api.firemark.generation.provider import (
    SAFE_EXCEPTION_TOKENS,
    GenerationProviderError,
)
from api.firemark.generation.provider_identity import provider_model_display_name
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import (
    FiremarkPublicCapsuleV1,
    embed_public_capsule_png,
    extract_public_capsule_png,
)
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
    mime_type: str = "image/jpeg",
    status: str = "completed",
    use_steps: bool = False,
    image_blocks: int = 1,
) -> dict[str, object]:
    """Build an interaction response carrying one inline Base64 JPEG."""
    image: dict[str, object] = {
        "type": "image",
        "mime_type": mime_type,
        "data": data if data is not None else base64.b64encode(_TINY_JPEG).decode(),
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


def inline_body(**kwargs: Any) -> dict[str, object]:
    return interaction_body(**kwargs)
def client(handler: Any) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url=GEMINI_API_BASE_URL,
    )


def provider(
    handler: Any,
    *,
    secret: str = "test-gemini-secret",
    max_image_bytes: int = 1024 * 1024,
    stage_callback: Any = None,
) -> GeminiImageProvider:
    return GeminiImageProvider(
        api_key=secret,
        timeout_seconds=30,
        max_image_bytes=max_image_bytes,
        client_factory=lambda: client(handler),
        now=lambda: NOW,
        stage_callback=stage_callback,
    )


def ok_provider(**kwargs: Any) -> GeminiImageProvider:
    return provider(lambda _request: httpx.Response(200, json=interaction_body()), **kwargs)


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
    assert result.data == _TINY_JPEG
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
            "response_format": {
                "type": "image",
                "mime_type": "image/jpeg",
                "aspect_ratio": "1:1",
                "image_size": "1K",
            },
        }
    ]
    payload = captured[0]
    assert set(payload) == {"model", "input", "response_format"}
    assert payload["model"] == MODEL
    response_format = payload["response_format"]
    assert isinstance(response_format, dict)
    assert set(response_format) == {"type", "mime_type", "aspect_ratio", "image_size"}
    assert response_format["type"] == "image"
    assert response_format["mime_type"] == GEMINI_REQUEST_MIME_TYPE == "image/jpeg"
    assert response_format["aspect_ratio"] == "1:1"
    assert response_format["image_size"] == "1K"
    assert "image/png" not in json.dumps(payload)
    assert "contents" not in payload
    assert "generationConfig" not in payload
    assert ":generateContent" not in json.dumps(payload)


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
    assert default_client.follow_redirects is False
    default_client.close()
    provider(handler).generate_image(request())
    # Exactly one host is ever contacted: no second resource is downloaded.
    assert seen == [f"{GEMINI_API_BASE_URL}{GEMINI_INTERACTIONS_PATH}"]
    assert all(token not in url.lower() for url in seen for token in FORBIDDEN_HOSTS)
    assert all(":generateContent" not in url for url in seen)


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
    assert result.data == _TINY_JPEG
    assert result.source_mime_type == GEMINI_SOURCE_MIME_TYPE == "image/jpeg"
    assert result.source_extension == "jpg"
    assert result.media_type == "image/jpeg"
    assert result.file_extension == "jpg"


def test_generated_image_reports_accurate_provider_identity() -> None:
    result = ok_provider().generate_image(request())
    assert result.provider == "google_gemini"
    assert result.model == MODEL
    assert result.ai_generated is True
    assert result.media_type == "image/jpeg"
    metadata = result.safe_generation_metadata
    assert metadata["provider_model_name"] == "Nano Banana 2"
    assert metadata["provider_api"] == "interactions"
    assert metadata["provider_api_version"] == "v1beta"
    assert metadata["provider_source_mime_type"] == "image/jpeg"
    assert metadata["sealed_mime_type"] == "image/png"
    assert metadata["source_byte_size"] == len(_TINY_JPEG)
    assert result.width == 2 and result.height == 2
    assert provider_model_display_name("google_gemini", MODEL) == "Nano Banana 2"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"id": "x", "status": "completed"}, "malformed_response"),
        ({"id": "x", "status": "completed", "steps": []}, "malformed_response"),
        ({"id": "x", "status": "completed", "steps": "invalid"}, "malformed_response"),
        (interaction_body(use_steps=True, image_blocks=2), "malformed_response"),
        (inline_body(data="%%%"), "malformed_response"),
        (inline_body(data=""), "malformed_response"),
        ({"status": "completed", "output_image": {"type": "image"}}, "malformed_response"),
        (inline_body(mime_type="image/png"), "unsupported_media_type"),
        (inline_body(mime_type="image/webp"), "unsupported_media_type"),
        (inline_body(mime_type="application/json"), "unsupported_media_type"),
        (inline_body(data=base64.b64encode(b"not-a-jpeg").decode()), "non_jpeg_source"),
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
    if code == "non_jpeg_source":
        assert caught.value.code == "unsupported_media_type"
        assert caught.value.safe_reason_code == "NON_JPEG_SOURCE"
    else:
        assert caught.value.code == code


def test_oversized_inline_response_fails_closed() -> None:
    bounded = provider(
        lambda _request: httpx.Response(200, json=inline_body()), max_image_bytes=10
    )
    with pytest.raises(GenerationProviderError) as decoded:
        bounded.generate_image(request())
    assert decoded.value.code == "response_too_large"


def test_oversized_interaction_metadata_body_fails_closed() -> None:
    padded = inline_body()
    padded["padding"] = "x" * (3 * 1024 * 1024)
    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(200, json=padded), max_image_bytes=1024 * 1024
        ).generate_image(request())
    assert caught.value.code == "response_too_large"


def test_interaction_redirect_fails_closed() -> None:
    with pytest.raises(GenerationProviderError) as redirected:
        provider(lambda _request: httpx.Response(302)).generate_image(request())
    assert redirected.value.code == "malformed_response"


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


@pytest.mark.parametrize(
    ("failure", "code", "reason", "token"),
    [
        (httpx.ConnectTimeout("private-connect-timeout"), "timeout", "TRANSPORT_CONNECT_TIMEOUT", "ConnectTimeout"),
        (httpx.ReadTimeout("private-read-timeout"), "timeout", "TRANSPORT_READ_TIMEOUT", "ReadTimeout"),
        (httpx.WriteTimeout("private-write-timeout"), "timeout", "TRANSPORT_WRITE_TIMEOUT", "WriteTimeout"),
        (httpx.PoolTimeout("private-pool-timeout"), "timeout", "TRANSPORT_POOL_TIMEOUT", "PoolTimeout"),
        (httpx.ProxyError("private-proxy-failure"), "unavailable", "TRANSPORT_PROXY_FAILURE", "ProxyError"),
        (httpx.ReadError("private-read-failure"), "unavailable", "TRANSPORT_READ_FAILURE", "ReadError"),
        (httpx.WriteError("private-write-failure"), "unavailable", "TRANSPORT_WRITE_FAILURE", "WriteError"),
        (
            httpx.RemoteProtocolError("private-remote-protocol"),
            "unavailable",
            "TRANSPORT_REMOTE_PROTOCOL_FAILURE",
            "RemoteProtocolError",
        ),
        (
            httpx.LocalProtocolError("private-local-protocol"),
            "unavailable",
            "TRANSPORT_LOCAL_PROTOCOL_FAILURE",
            "LocalProtocolError",
        ),
        (
            httpx.DecodingError("private-decoding-failure"),
            "unavailable",
            "TRANSPORT_DECODING_FAILURE",
            "DecodingError",
        ),
        (
            httpx.UnsupportedProtocol("private-unsupported"),
            "unavailable",
            "TRANSPORT_UNSUPPORTED_PROTOCOL",
            "UnsupportedProtocol",
        ),
        (httpx.CloseError("private-close-failure"), "unavailable", "TRANSPORT_CLOSE_FAILURE", "CloseError"),
    ],
)
def test_every_relevant_transport_error_is_classified_safely(
    failure: Exception, code: str, reason: str, token: str
) -> None:
    with pytest.raises(GenerationProviderError) as caught:
        failing_transport(failure).generate_image(request())
    assert caught.value.code == code
    assert caught.value.status_code is None
    assert caught.value.safe_reason_code == reason
    assert caught.value.safe_exception_token == token
    assert token in SAFE_EXCEPTION_TOKENS
    assert str(failure) not in str(caught.value)
    assert smoke.PROVIDER_CATEGORIES[code] in {"TIMEOUT", "PROVIDER_UNAVAILABLE"}


def test_remaining_transport_errors_keep_the_generic_reason() -> None:
    class OddTransportError(httpx.TransportError):
        pass

    with pytest.raises(GenerationProviderError) as caught:
        failing_transport(OddTransportError("odd")).generate_image(request())
    assert caught.value.code == "unavailable"
    assert caught.value.safe_reason_code == "TRANSPORT_FAILURE"
    assert caught.value.safe_exception_token is None


def test_dns_and_transport_failures_are_distinguishable_from_http_5xx() -> None:
    resolution = httpx.ConnectError("offline")
    resolution.__cause__ = socket.gaierror("name resolution failed")
    cases = {
        "DNS_RESOLUTION_FAILURE": resolution,
        "TRANSPORT_CONNECT_FAILURE": httpx.ConnectError("refused"),
    }
    for reason, failure in cases.items():
        with pytest.raises(GenerationProviderError) as caught:
            failing_transport(failure).generate_image(request())
        assert caught.value.code == "unavailable"
        assert caught.value.status_code is None
        assert caught.value.safe_reason_code == reason
        assert caught.value.safe_exception_token == "ConnectError"
        assert str(failure) not in str(caught.value)
    with pytest.raises(GenerationProviderError) as server_error:
        provider(lambda _request: httpx.Response(503)).generate_image(request())
    assert server_error.value.code == "unavailable"
    assert server_error.value.status_code == 503
    assert server_error.value.safe_reason_code == "HTTP_503"
    assert server_error.value.safe_exception_token is None
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


def test_decoded_inline_image_exceeding_the_limit_fails_closed() -> None:
    response = httpx.Response(200, json=inline_body())
    bounded = provider(lambda _request: response, max_image_bytes=8)
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
            "mimeType": "image/jpeg",
            "data": base64.b64encode(_TINY_JPEG).decode(),
        },
    }
    assert provider(
        lambda _request: httpx.Response(200, json=camel)
    ).generate_image(request()).data == _TINY_JPEG


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
                        "mime_type": "image/jpeg",
                        "data": base64.b64encode(_TINY_JPEG).decode(),
                    }
                ],
            },
        ],
    }
    assert provider(
        lambda _request: httpx.Response(200, json=skipped)
    ).generate_image(request()).data == _TINY_JPEG
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

    def hostile_factory(**kwargs: Any) -> GeminiImageProvider:
        return HostileMetadata(
            api_key="secret",
            timeout_seconds=30,
            max_image_bytes=1024 * 1024,
            client_factory=lambda: client(
                lambda _request: httpx.Response(200, json=interaction_body())
            ),
            now=lambda: NOW,
            stage_callback=kwargs.get("stage_callback"),
        )
    outcome = smoke.execute_live(
        config_loader=config,
        provider_factory=lambda **kwargs: hostile_factory(**kwargs),
        checkpoint_path=tmp_path / "checkpoint.json",
        private_root=tmp_path / "private",
        archive_directory=tmp_path / "archive",
    )
    assert outcome.category == "OK"
    assert outcome.provider_calls == 1
    assert [stage for stage, _status in outcome.stages] == list(smoke.STAGES)
    assert "model_access_preflight" not in dict(outcome.stages)
    assert smoke.STAGES[6:9] == (
        "inline_metadata_validation",
        "inline_jpeg_base64_validation",
        "jpeg_validation",
    )
    assert smoke.STAGES[10:12] == (
        "deterministic_png_normalization",
        "normalized_png_validation",
    )


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
        data=_TINY_JPEG,
        source_mime_type="image/jpeg",
        source_extension="jpg",
        width=2,
        height=2,
        provider="google_gemini",
        model=MODEL,
        provider_created_at=NOW,
        ai_generated=True,
    )


def run_smoke(
    tmp_path: Path,
    instance: object,
    *,
    allow_definitive_retry: bool = False,
    start_new_operation_after_ambiguous: bool = False,
    start_new_operation_after_definitive: bool = False,
) -> smoke.SmokeOutcome:
    return smoke.execute_live(
        config_loader=config,
        provider_factory=lambda **_kwargs: instance,  # type: ignore[arg-type,return-value]
        checkpoint_path=tmp_path / "checkpoint.json",
        private_root=tmp_path / "private",
        archive_directory=tmp_path / "archive",
        allow_definitive_retry=allow_definitive_retry,
        start_new_operation_after_ambiguous=start_new_operation_after_ambiguous,
        start_new_operation_after_definitive=start_new_operation_after_definitive,
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
    assert stored.source_mime_type == "image/jpeg"
    assert stored.source_extension == "jpg"
    assert stored.source_sha256 == outcome.source_sha256
    assert stored.source_sha256 != stored.normalized_sha256
    assert Path(str(stored.source_path)).read_bytes() == _TINY_JPEG
    assert Path(str(stored.source_path)).name == "source.jpg"


def test_recovery_reuses_persisted_source_and_never_calls_gemini_again(tmp_path: Path) -> None:
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


def ambiguous_store(tmp_path: Path, **values: object) -> smoke.CheckpointStore:
    store = smoke.CheckpointStore(tmp_path / "checkpoint.json", tmp_path / "private")
    store.write(
        smoke.GeminiProviderCheckpoint.model_validate(
            {
                "operation_state": "provider_call_started",
                "model": MODEL,
                "request_id": smoke.SMOKE_REQUEST_ID,
                "created_at": NOW,
                "new_provider_calls": 1,
                **values,
            }
        )
    )
    return store


def test_ambiguous_prior_submission_never_submits_again(tmp_path: Path) -> None:
    store = ambiguous_store(tmp_path)
    original = store.path.read_bytes()
    counting = CountingProvider(generated_image())
    outcome = run_smoke(tmp_path, counting)
    assert outcome.category == "AMBIGUOUS_PRIOR_SUBMISSION"
    assert outcome.prior_class == "ambiguous"
    assert counting.calls == 0
    assert store.path.read_bytes() == original


def rejected(tmp_path: Path, code: str) -> smoke.SmokeOutcome:
    failure = GenerationProviderError(code, status_code=400)  # type: ignore[arg-type]
    return run_smoke(tmp_path, CountingProvider(failure))


def test_definitive_rejection_permits_one_authorized_retry(tmp_path: Path) -> None:
    first = rejected(tmp_path, "invalid_request")
    assert first.category == "INVALID_REQUEST"
    assert first.retry_permitted is True
    blocked = CountingProvider(generated_image())
    assert run_smoke(tmp_path, blocked).category == "DEFINITIVE_REJECTION_NOT_AUTHORIZED"
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
        archive_directory=tmp_path / "archive",
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
        archive_directory=tmp_path / "archive",
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


# --------------------------------------------------------------------------
# URI delivery: parsing, security and bounded download
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# The transient URI never escapes the download operation
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# Ambiguous checkpoint preservation and operator-authorized new operations
# --------------------------------------------------------------------------


def test_help_documents_the_new_operation_options() -> None:
    help_text = " ".join(smoke.build_parser().format_help().split())
    assert "--start-new-operation-after-ambiguous" in help_text
    assert "--start-new-operation-after-definitive" in help_text
    assert "not a retry of the ambiguous submission" in help_text
    assert "not a retry of the rejected submission" in help_text
    assert help_text.count("Requires --live") == 2


@pytest.mark.parametrize(
    "option",
    ["--start-new-operation-after-ambiguous", "--start-new-operation-after-definitive"],
)
def test_new_operation_options_require_live(
    option: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert smoke.main([option]) == 1
    output = capsys.readouterr().out
    assert "requires --live" in output
    assert "zero network calls" in output


def test_real_ambiguous_checkpoint_shape_is_classified_not_retryable(tmp_path: Path) -> None:
    """The preserved production checkpoint is a v1 record with two rejections."""
    store = smoke.CheckpointStore(tmp_path / "checkpoint.json", tmp_path / "private")
    payload = {
        "schema_version": "firemark.gemini-image-provider-checkpoint.v1",
        "operation_state": "provider_rejected",
        "provider": "google_gemini",
        "model": MODEL,
        "media_type": "image",
        "mime_type": "image/png",
        "request_id": smoke.SMOKE_REQUEST_ID,
        "created_at": "2026-07-31T20:19:31.116809Z",
        "new_provider_calls": 1,
        "prior_rejected_calls": 2,
        "provider_failure_code": "unavailable",
        "provider_failure_status": None,
        "provider_safe_reason_code": "TRANSPORT_FAILURE",
        "provider_retry_allowed": False,
        "source_sha256": None,
        "source_path": None,
        "current_stage": "provider_generation",
        "stage_results": [],
    }
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(json.dumps(payload), encoding="utf-8")
    checkpoint = store.read()
    assert checkpoint.schema_version.endswith(".v1")
    assert not smoke._retry_allowed(checkpoint)
    assert smoke.classify_prior_checkpoint(store, config()) == "ambiguous"


def test_ambiguous_checkpoint_blocks_and_is_never_rewritten(tmp_path: Path) -> None:
    store = ambiguous_store(tmp_path, operation_state="provider_rejected", provider_failure_code="unavailable")
    original = store.path.read_bytes()
    counting = CountingProvider(generated_image())
    outcome = run_smoke(tmp_path, counting, allow_definitive_retry=True)
    assert outcome.category == "AMBIGUOUS_PRIOR_SUBMISSION"
    assert counting.calls == 0
    assert store.path.read_bytes() == original


def test_new_operation_archives_the_ambiguous_checkpoint_atomically(tmp_path: Path) -> None:
    store = ambiguous_store(tmp_path)
    original = store.path.read_bytes()
    counting = CountingProvider(generated_image())
    outcome = run_smoke(tmp_path, counting, start_new_operation_after_ambiguous=True)
    assert outcome.category == "OK"
    assert outcome.new_operation is True
    assert outcome.archived is True
    assert counting.calls == 1
    archived = sorted((tmp_path / "archive").glob(f"{smoke.ARCHIVE_PREFIX}*.json"))
    assert len(archived) == 1
    assert archived[0].read_bytes() == original
    preserved = json.loads(archived[0].read_text("utf-8"))
    assert preserved["operation_state"] == "provider_call_started"
    assert preserved["provider_retry_allowed"] is False


def test_new_operation_receives_a_new_operation_id(tmp_path: Path) -> None:
    ambiguous_store(tmp_path, operation_id="firemark-gemini-op-original")
    outcome = run_smoke(
        tmp_path, CountingProvider(generated_image()), start_new_operation_after_ambiguous=True
    )
    assert outcome.operation_id is not None
    assert outcome.operation_id != "firemark-gemini-op-original"
    assert outcome.operation_id.startswith("firemark-gemini-op-")


def test_new_operation_allows_exactly_one_submission(tmp_path: Path) -> None:
    ambiguous_store(tmp_path)
    counting = CountingProvider(generated_image())
    assert run_smoke(
        tmp_path, counting, start_new_operation_after_ambiguous=True
    ).category == "OK"
    assert counting.calls == 1
    again = CountingProvider(generated_image())
    assert run_smoke(tmp_path, again).category == "OK"
    assert again.calls == 0


def test_a_second_ambiguous_result_fails_closed(tmp_path: Path) -> None:
    ambiguous_store(tmp_path)
    failure = GenerationProviderError(
        "unavailable", safe_reason_code="TRANSPORT_REMOTE_PROTOCOL_FAILURE"
    )
    first = run_smoke(
        tmp_path, CountingProvider(failure), start_new_operation_after_ambiguous=True
    )
    assert first.category == "PROVIDER_UNAVAILABLE"
    assert first.retry_permitted is False
    blocked = CountingProvider(generated_image())
    assert run_smoke(tmp_path, blocked).category == "AMBIGUOUS_PRIOR_SUBMISSION"
    assert blocked.calls == 0
    assert (
        run_smoke(tmp_path, blocked, allow_definitive_retry=True).category
        == "AMBIGUOUS_PRIOR_SUBMISSION"
    )
    assert blocked.calls == 0


def test_new_operation_without_an_ambiguous_checkpoint_is_refused(tmp_path: Path) -> None:
    counting = CountingProvider(generated_image())
    assert (
        run_smoke(tmp_path, counting, start_new_operation_after_ambiguous=True).category
        == "NO_AMBIGUOUS_CHECKPOINT"
    )
    assert counting.calls == 0
    assert not (tmp_path / "archive").exists()


def test_archive_refuses_to_overwrite_an_existing_record(tmp_path: Path) -> None:
    store = ambiguous_store(tmp_path)
    archive = tmp_path / "archive"
    fixed = datetime(2026, 8, 1, 12, tzinfo=UTC)
    first = smoke.archive_ambiguous_checkpoint(store, archive, now=lambda: fixed)
    assert first.exists()
    ambiguous_store(tmp_path)
    with pytest.raises(smoke.SafeSmokeError) as caught:
        smoke.archive_ambiguous_checkpoint(store, archive, now=lambda: fixed)
    assert caught.value.category == "SAFE_UNEXPECTED_FAILURE"
    assert first.read_bytes()


def test_archive_requires_an_existing_checkpoint(tmp_path: Path) -> None:
    store = smoke.CheckpointStore(tmp_path / "missing.json", tmp_path / "private")
    with pytest.raises(smoke.SafeSmokeError) as caught:
        smoke.archive_ambiguous_checkpoint(store, tmp_path / "archive")
    assert caught.value.category == "NO_AMBIGUOUS_CHECKPOINT"


def test_persisted_failure_keeps_only_allowlisted_diagnostics(tmp_path: Path) -> None:
    failure = GenerationProviderError(
        "unavailable",
        safe_reason_code="TRANSPORT_READ_FAILURE",
        safe_exception_token="ReadError",
    )
    outcome = run_smoke(tmp_path, CountingProvider(failure))
    assert outcome.category == "PROVIDER_UNAVAILABLE"
    stored = json.loads((tmp_path / "checkpoint.json").read_text("utf-8"))
    assert stored["provider_failure_code"] == "unavailable"
    assert stored["provider_safe_reason_code"] == "TRANSPORT_READ_FAILURE"
    assert stored["provider_exception_token"] == "ReadError"
    assert stored["provider_failure_status"] is None
    assert set(stored) == set(smoke.GeminiProviderCheckpoint.model_fields)


def test_unlisted_exception_tokens_are_discarded() -> None:
    error = GenerationProviderError("unavailable", safe_exception_token="SomeInternalError")
    assert error.safe_exception_token is None
def test_read_only_probe_bounds_use_the_shared_buffer() -> None:
    with pytest.raises(GenerationProviderError) as unreadable:
        provider(
            lambda _request: httpx.Response(
                200, headers={"content-length": "invalid"}, json={"models": []}
            )
        ).list_models()
    assert unreadable.value.code == "malformed_response"

    class Oversized(httpx.SyncByteStream):
        def __iter__(self) -> Any:
            for _ in range(3):
                yield b"y" * (256 * 1024)

    with pytest.raises(GenerationProviderError) as unbounded:
        provider(lambda _request: httpx.Response(200, stream=Oversized())).list_models()
    assert unbounded.value.code == "response_too_large"


def test_non_json_interaction_body_fails_closed() -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(
                200, headers={"content-type": "application/json"}, content=b"not json"
            )
        ).generate_image(request())
    assert caught.value.code == "malformed_response"
def test_provider_reported_stages_are_part_of_the_declared_stage_table() -> None:
    assert smoke.PROVIDER_STAGES <= set(smoke.STAGES)
    reported: list[str] = []
    ok_provider(stage_callback=reported.append).generate_image(request())
    assert reported == [
        "interaction_submission",
        "inline_metadata_validation",
        "inline_jpeg_base64_validation",
        "jpeg_validation",
    ]


# --------------------------------------------------------------------------
# Deterministic JPEG to PNG normalization
# --------------------------------------------------------------------------


def build_jpeg(
    size: tuple[int, int] = (8, 8), *, exif_orientation: int | None = None, quality: int = 90
) -> bytes:
    from PIL import Image

    image = Image.new("RGB", size, (180, 60, 30))
    image.putpixel((0, 0), (12, 200, 90))
    buffer = io.BytesIO()
    save_kwargs: dict[str, Any] = {"format": "JPEG", "quality": quality}
    if exif_orientation is not None:
        exif = Image.Exif()
        exif[0x0112] = exif_orientation
        exif[0x010E] = "private provider comment"
        save_kwargs["exif"] = exif.tobytes()
    image.save(buffer, **save_kwargs)
    return buffer.getvalue()


def test_normalization_produces_a_valid_deterministic_png() -> None:
    source = build_jpeg()
    first = normalize_to_png(source, source_mime_type="image/jpeg")
    second = normalize_to_png(source, source_mime_type="image/jpeg")
    assert first.data == second.data
    assert first.data.startswith(b"\x89PNG\r\n\x1a\n")
    assert first.mime_type == "image/png"
    assert first.file_extension == "png"
    assert (first.width, first.height) == (8, 8)
    assert first.data != source


def test_normalization_strips_exif_comments_and_icc_profile() -> None:
    from PIL import Image

    source = build_jpeg(exif_orientation=1)
    assert b"private provider comment" in source
    normalized = normalize_to_png(source, source_mime_type="image/jpeg")
    assert b"private provider comment" not in normalized.data
    assert b"eXIf" not in normalized.data
    assert b"iCCP" not in normalized.data
    assert b"tEXt" not in normalized.data
    with Image.open(io.BytesIO(normalized.data)) as decoded:
        assert decoded.info == {}
        assert decoded.getexif() == Image.Exif()


def test_normalization_applies_orientation_deterministically() -> None:
    from PIL import Image

    rotated = build_jpeg(size=(8, 4), exif_orientation=6)
    normalized = normalize_to_png(rotated, source_mime_type="image/jpeg")
    # Orientation 6 rotates the frame, so the normalized carrier is portrait.
    assert (normalized.width, normalized.height) == (4, 8)
    with Image.open(io.BytesIO(normalized.data)) as decoded:
        assert decoded.size == (4, 8)


def test_normalization_converts_to_rgb_and_keeps_alpha_only_when_real() -> None:
    from PIL import Image

    opaque = normalize_to_png(build_jpeg(), source_mime_type="image/jpeg")
    with Image.open(io.BytesIO(opaque.data)) as decoded:
        assert decoded.mode == "RGB"

    buffer = io.BytesIO()
    transparent = Image.new("RGBA", (4, 4), (10, 20, 30, 128))
    transparent.save(buffer, format="PNG")
    kept = normalize_to_png(buffer.getvalue(), source_mime_type="image/png")
    with Image.open(io.BytesIO(kept.data)) as decoded:
        assert decoded.mode == "RGBA"

    buffer = io.BytesIO()
    Image.new("RGBA", (4, 4), (10, 20, 30, 255)).save(buffer, format="PNG")
    flattened = normalize_to_png(buffer.getvalue(), source_mime_type="image/png")
    with Image.open(io.BytesIO(flattened.data)) as decoded:
        assert decoded.mode == "RGB"


@pytest.mark.parametrize(
    ("payload", "mime_type", "code"),
    [
        (b"not-an-image", "image/jpeg", "non_jpeg_source"),
        (_TINY_PNG, "image/jpeg", "non_jpeg_source"),
        (_TINY_JPEG, "image/webp", "unsupported_source_mime"),
        (_TINY_JPEG[:20], "image/jpeg", "malformed_image"),
    ],
)
def test_normalization_rejects_unusable_sources(
    payload: bytes, mime_type: str, code: str
) -> None:
    with pytest.raises(ImageNormalizationError) as caught:
        normalize_to_png(payload, source_mime_type=mime_type)
    assert caught.value.code == code
    with pytest.raises(ImageNormalizationError) as inspected:
        inspect_image_source(payload, mime_type=mime_type)
    assert inspected.value.code == code


def test_truncated_jpeg_fails_structural_inspection_and_decoding() -> None:
    truncated = _TINY_JPEG[:-30]
    with pytest.raises(ImageNormalizationError) as inspected:
        inspect_image_source(truncated, mime_type="image/jpeg")
    assert inspected.value.code == "malformed_image"
    with pytest.raises(ImageNormalizationError) as decoded:
        normalize_to_png(truncated, source_mime_type="image/jpeg")
    assert decoded.value.code == "image_decoding_failure"


def test_normalization_rejects_excessive_dimensions_and_pixel_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = build_jpeg(size=(64, 64))
    monkeypatch.setattr(normalization, "MAX_IMAGE_DIMENSION", 32)
    with pytest.raises(ImageNormalizationError) as dimensions:
        normalize_to_png(source, source_mime_type="image/jpeg")
    assert dimensions.value.code == "image_dimensions_exceeded"

    monkeypatch.setattr(normalization, "MAX_IMAGE_DIMENSION", 16384)
    monkeypatch.setattr(normalization, "MAX_IMAGE_PIXELS", 1024)
    with pytest.raises(ImageNormalizationError) as pixels:
        normalize_to_png(source, source_mime_type="image/jpeg")
    assert pixels.value.code == "image_pixels_exceeded"


def test_normalization_rejects_a_decompression_bomb(monkeypatch: pytest.MonkeyPatch) -> None:
    from PIL import Image

    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 16)
    with pytest.raises(ImageNormalizationError) as caught:
        normalize_to_png(build_jpeg(size=(64, 64)), source_mime_type="image/jpeg")
    assert caught.value.code == "image_pixels_exceeded"


def test_normalization_failure_is_reported_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    from PIL import Image

    source = build_jpeg()

    def refuse(self: Any, *args: Any, **kwargs: Any) -> None:
        raise OSError("private encoder detail")

    monkeypatch.setattr(Image.Image, "save", refuse)
    with pytest.raises(ImageNormalizationError) as caught:
        normalize_to_png(source, source_mime_type="image/jpeg")
    assert caught.value.code == "png_normalization_failure"
    assert "private encoder detail" not in str(caught.value)


def test_source_facts_describe_the_untouched_bytes() -> None:
    source = build_jpeg(size=(6, 3))
    facts = inspect_image_source(source, mime_type="image/jpeg")
    assert facts.mime_type == "image/jpeg"
    assert (facts.width, facts.height) == (6, 3)
    assert facts.byte_size == len(source)


# --------------------------------------------------------------------------
# Source versus sealed contract through Generate & Seal
# --------------------------------------------------------------------------


def seal_image(image: GeneratedImage) -> dict[str, Any]:
    """Run the source-to-sealed portion of Generate & Seal without any network."""
    source_sha256 = sha256_bytes(image.data)
    carrier = generate_and_seal._png_carrier(image, stage_callback=lambda _stage: None)
    manifest = generate_and_seal._build_manifest(
        image,
        "private prompt",
        {"requested_size": "1024x1024"},
        run_id="firemark-run-jpeg-contract",
        source_sha256=source_sha256,
        normalization=carrier.record,
    )
    capsule = FiremarkPublicCapsuleV1.model_validate(
        {
            "cert_id": "firemark-cert-jpeg",
            "asset_id": "firemark-asset-jpeg",
            "run_id": "firemark-run-jpeg-contract",
            "canonical_hash": manifest.canonical_hash,
            "source_sha256": source_sha256,
            "signer_key_id": "firemark-signer-1",
            "verify_url": "https://verify.firemark.test/v1/certificates/firemark-cert-jpeg",
            "issued_at": NOW,
        }
    )
    sealed = embed_public_capsule_png(carrier.data, capsule)
    return {
        "source_sha256": source_sha256,
        "sealed_sha256": sha256_bytes(sealed),
        "sealed": sealed,
        "carrier": carrier,
        "manifest": manifest,
        "capsule": capsule,
    }


def gemini_source_image() -> GeneratedImage:
    source = build_jpeg(size=(10, 10))
    return GeneratedImage(
        data=source,
        source_mime_type="image/jpeg",
        source_extension="jpg",
        width=10,
        height=10,
        provider="google_gemini",
        model=MODEL,
        provider_created_at=NOW,
        safe_generation_metadata={
            "provider_source_mime_type": "image/jpeg",
            "provider_model_name": "Nano Banana 2",
        },
        ai_generated=True,
    )


def test_source_hash_is_the_exact_jpeg_and_sealed_hash_is_the_png() -> None:
    image = gemini_source_image()
    result = seal_image(image)
    assert result["source_sha256"] == hashlib.sha256(image.data).hexdigest()
    assert result["source_sha256"] != result["sealed_sha256"]
    assert result["sealed"].startswith(b"\x89PNG\r\n\x1a\n")
    assert not image.data.startswith(b"\x89PNG\r\n\x1a\n")
    assert result["sealed_sha256"] != hashlib.sha256(result["carrier"].data).hexdigest()


def test_sealed_png_carries_the_public_capsule() -> None:
    result = seal_image(gemini_source_image())
    extracted = extract_public_capsule_png(result["sealed"])
    assert extracted.model_dump(mode="json") == result["capsule"].model_dump(mode="json")
    assert extracted.source_sha256 == result["source_sha256"]


def test_private_provenance_records_the_normalization_step() -> None:
    result = seal_image(gemini_source_image())
    step = result["manifest"].run.steps[0]
    record = dict(step.metadata)["firemark_normalization"]
    assert record == {
        "operation": "normalize_image",
        "input_mime_type": "image/jpeg",
        "output_mime_type": "image/png",
        "purpose": "firemark_public_capsule_embedding",
    }
    assert dict(step.metadata)["provider_source_mime_type"] == "image/jpeg"
    assert step.assets[0].sha256 == result["source_sha256"]


def test_a_png_source_is_carried_through_without_re_encoding() -> None:
    image = GeneratedImage(
        data=_TINY_PNG,
        source_mime_type="image/png",
        source_extension="png",
        provider="openai",
        model="gpt-image-1.5",
        provider_created_at=NOW,
        ai_generated=True,
    )
    carrier = generate_and_seal._png_carrier(image, stage_callback=lambda _stage: None)
    assert carrier.data == _TINY_PNG
    assert carrier.record is None


def test_public_certificate_represents_the_sealed_png_not_the_jpeg_source() -> None:
    result = seal_image(gemini_source_image())
    asset = AssetRecord(
        asset_id="firemark-asset-jpeg",
        run_id="firemark-run-jpeg-contract",
        asset_type="image",
        media_type=generate_and_seal.SEALED_IMAGE_MIME_TYPE,
        file_extension=generate_and_seal.SEALED_IMAGE_EXTENSION,
        byte_size=len(result["sealed"]),
        width=10,
        height=10,
        source_sha256=result["source_sha256"],
        sealed_sha256=result["sealed_sha256"],
        assets_bucket="firemark-assets",
        assets_key="assets/ab/cd/sealed.png",
        assets_version_id="version-1",
        vault_bucket="firemark-vault",
        vault_key="vault/sources/ab/cd/source.jpg",
        vault_version_id="version-2",
        created_at=NOW,
    )
    assert asset.media_type == "image/png"
    assert asset.file_extension == "png"
    assert asset.vault_key.endswith(".jpg")
    assert asset.source_sha256 != asset.sealed_sha256


def test_generated_image_never_labels_jpeg_bytes_as_png() -> None:
    with pytest.raises(ValidationError):
        GeneratedImage(
            data=build_jpeg(),
            source_mime_type="image/png",
            source_extension="png",
            provider="google_gemini",
            model=MODEL,
            provider_created_at=NOW,
            ai_generated=True,
        )
    with pytest.raises(ValidationError):
        GeneratedImage(
            data=build_jpeg(),
            source_mime_type="image/jpeg",
            source_extension="png",
            provider="google_gemini",
            model=MODEL,
            provider_created_at=NOW,
            ai_generated=True,
        )


def test_definitive_rejection_is_the_only_authorized_path_after_http_400(
    tmp_path: Path,
) -> None:
    """The live HTTP 400 checkpoint stays retryable only through explicit authorization."""
    store = smoke.CheckpointStore(tmp_path / "checkpoint.json", tmp_path / "private")
    store.write(
        smoke.GeminiProviderCheckpoint(
            operation_state="provider_rejected",
            operation_id="firemark-gemini-op-b4295a0602be4ee2ac74fb9cc90af51b",
            model=MODEL,
            request_id=smoke.SMOKE_REQUEST_ID,
            created_at=NOW,
            new_provider_calls=1,
            prior_rejected_calls=1,
            provider_failure_code="invalid_request",
            provider_failure_status=400,
            provider_safe_reason_code="HTTP_400",
            provider_retry_allowed=True,
        )
    )
    original = store.path.read_bytes()
    assert smoke.classify_prior_checkpoint(store, config()) == "definitive_rejection"

    blocked = CountingProvider(generated_image())
    assert run_smoke(tmp_path, blocked).category == "DEFINITIVE_REJECTION_NOT_AUTHORIZED"
    assert blocked.calls == 0
    assert store.path.read_bytes() == original

    refused = CountingProvider(generated_image())
    assert (
        run_smoke(tmp_path, refused, start_new_operation_after_ambiguous=True).category
        == "NO_AMBIGUOUS_CHECKPOINT"
    )
    assert refused.calls == 0
    assert store.path.read_bytes() == original
    assert not (tmp_path / "archive").exists()

    authorized = CountingProvider(generated_image())
    outcome = run_smoke(tmp_path, authorized, allow_definitive_retry=True)
    assert outcome.category == "OK"
    assert authorized.calls == 1
    assert outcome.source_mime_type == "image/jpeg"


def test_format_mismatch_between_magic_and_container_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A payload whose magic and decoded container disagree is never accepted."""
    from PIL import Image

    real_open = Image.open

    def wrong_format(*args: Any, **kwargs: Any) -> Any:
        image = real_open(*args, **kwargs)
        image.format = "GIF"
        return image

    monkeypatch.setattr(Image, "open", wrong_format)
    for mime_type, code in (("image/jpeg", "non_jpeg_source"), ("image/png", "malformed_image")):
        payload = build_jpeg() if mime_type == "image/jpeg" else _TINY_PNG
        with pytest.raises(ImageNormalizationError) as caught:
            inspect_image_source(payload, mime_type=mime_type)
        assert caught.value.code == code


def test_zero_dimension_images_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from PIL import Image

    real_open = Image.open

    def empty(*args: Any, **kwargs: Any) -> Any:
        image = real_open(*args, **kwargs)
        monkeypatch.setattr(type(image), "size", (0, 0), raising=False)
        return image

    monkeypatch.setattr(Image, "open", empty)
    with pytest.raises(ImageNormalizationError) as caught:
        inspect_image_source(build_jpeg(), mime_type="image/jpeg")
    assert caught.value.code == "malformed_image"


def test_decompression_bomb_during_load_and_transpose_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from PIL import Image, ImageOps

    source = build_jpeg()

    def bomb(*args: Any, **kwargs: Any) -> Any:
        raise Image.DecompressionBombError("private bomb detail")

    monkeypatch.setattr(Image.Image, "load", bomb)
    with pytest.raises(ImageNormalizationError) as loading:
        inspect_image_source(source, mime_type="image/jpeg")
    assert loading.value.code == "image_pixels_exceeded"

    monkeypatch.undo()
    monkeypatch.setattr(ImageOps, "exif_transpose", bomb)
    with pytest.raises(ImageNormalizationError) as transposing:
        normalize_to_png(source, source_mime_type="image/jpeg")
    assert transposing.value.code == "image_pixels_exceeded"
    assert "private bomb detail" not in str(transposing.value)


def test_transparency_marker_alone_reports_real_alpha() -> None:
    from PIL import Image

    buffer = io.BytesIO()
    palette = Image.new("P", (4, 4))
    palette.info["transparency"] = 0
    palette.save(buffer, format="PNG", transparency=0)
    normalized = normalize_to_png(buffer.getvalue(), source_mime_type="image/png")
    with Image.open(io.BytesIO(normalized.data)) as decoded:
        assert decoded.mode == "RGBA"


def test_non_png_encoder_output_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from PIL import Image

    source = build_jpeg()

    def write_garbage(self: Any, fp: Any, *args: Any, **kwargs: Any) -> None:
        fp.write(b"GIF89a-not-a-png")

    monkeypatch.setattr(Image.Image, "save", write_garbage)
    with pytest.raises(ImageNormalizationError) as caught:
        normalize_to_png(source, source_mime_type="image/jpeg")
    assert caught.value.code == "non_png_normalized_output"


def test_source_bytes_property_exposes_the_untouched_provider_payload() -> None:
    image = gemini_source_image()
    assert image.source_bytes is image.data
    assert image.source_bytes.startswith(b"\xff\xd8\xff")


def test_generate_and_seal_reports_normalization_failures_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = gemini_source_image()

    def refuse(_data: bytes, *, source_mime_type: str) -> None:
        raise ImageNormalizationError("image_decoding_failure")

    monkeypatch.setattr(generate_and_seal, "normalize_to_png", refuse)
    with pytest.raises(generate_and_seal.GenerateAndSealError) as caught:
        generate_and_seal._png_carrier(image, stage_callback=lambda _stage: None)
    assert caught.value.code == "IMAGE_NORMALIZATION_IMAGE_DECODING_FAILURE"


def test_generate_and_seal_rejects_a_non_png_normalized_carrier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = gemini_source_image()
    fake = normalization.NormalizedImage(data=b"GIF89a", width=1, height=1)
    monkeypatch.setattr(
        generate_and_seal, "normalize_to_png", lambda _data, *, source_mime_type: fake
    )
    with pytest.raises(generate_and_seal.GenerateAndSealError) as caught:
        generate_and_seal._png_carrier(image, stage_callback=lambda _stage: None)
    assert caught.value.code == "IMAGE_NORMALIZATION_NON_PNG_NORMALIZED_OUTPUT"


# --------------------------------------------------------------------------
# Minimal inline request contract
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "delivery",
        "stream",
        "background",
        "store",
        "response_modalities",
        "responseModalities",
        "generationConfig",
        "generation_config",
        "tools",
        "previous_interaction_id",
        "contents",
    ],
)
def test_generic_schema_fields_are_never_sent(field: str) -> None:
    """Only the fields the image model's own examples use may be submitted."""
    captured: list[bytes] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        captured.append(http_request.content)
        return httpx.Response(200, json=interaction_body())

    provider(handler).generate_image(request())
    payload = json.loads(captured[0])
    assert field not in payload
    assert field not in payload["response_format"]
    assert field in FORBIDDEN_REQUEST_FIELDS
    assert field.encode() not in captured[0]


def test_request_headers_disable_content_encoding() -> None:
    seen: list[httpx.Headers] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        seen.append(http_request.headers)
        return httpx.Response(200, json=interaction_body())

    provider(handler).generate_image(request())
    headers = seen[0]
    assert headers["accept-encoding"] == "identity"
    assert headers["accept"] == "application/json"
    assert headers["content-type"].startswith("application/json")
    assert headers["x-goog-api-key"] == "test-gemini-secret"
    assert "authorization" not in headers


def test_forbidden_field_guard_rejects_a_reintroduced_field() -> None:
    assert smoke._request_fields_are_supported(
        smoke.expected_request_payload(MODEL, "prompt")
    )
    with_delivery = smoke.expected_request_payload(MODEL, "prompt")
    response_format = with_delivery["response_format"]
    assert isinstance(response_format, dict)
    response_format["delivery"] = "uri"
    assert not smoke._request_fields_are_supported(with_delivery)
    with_stream = smoke.expected_request_payload(MODEL, "prompt")
    with_stream["stream"] = False
    assert not smoke._request_fields_are_supported(with_stream)


def test_exactly_one_request_and_no_second_resource_is_fetched() -> None:
    calls: list[httpx.Request] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        calls.append(http_request)
        return httpx.Response(200, json=interaction_body())

    image = provider(handler).generate_image(request())
    assert image.data == _TINY_JPEG
    assert len(calls) == 1
    assert calls[0].method == "POST"
    assert calls[0].url.path == GEMINI_INTERACTIONS_PATH


# --------------------------------------------------------------------------
# Bounded streamed JSON body
# --------------------------------------------------------------------------


def test_truncated_json_body_fails_closed() -> None:
    partial = json.dumps(interaction_body())[:-40].encode()
    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(
                200, headers={"content-type": "application/json"}, content=partial
            )
        ).generate_image(request())
    assert caught.value.code == "malformed_response"
    assert caught.value.safe_reason_code == "INTERACTION_BODY_NOT_JSON"


def test_streamed_json_body_is_bounded_without_content_length() -> None:
    class Endless(httpx.SyncByteStream):
        def __iter__(self) -> Any:
            for _ in range(6):
                yield b"{" + b"x" * (1024 * 1024)

    bounded = provider(
        lambda _request: httpx.Response(200, stream=Endless()), max_image_bytes=1024 * 1024
    )
    with pytest.raises(GenerationProviderError) as caught:
        bounded.generate_image(request())
    assert caught.value.code == "response_too_large"


def test_read_failure_while_streaming_the_body_is_classified() -> None:
    class Failing(httpx.SyncByteStream):
        def __iter__(self) -> Any:
            yield b'{"status":'
            raise httpx.RemoteProtocolError("peer closed mid body")

    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(200, stream=Failing())).generate_image(
            request()
        )
    assert caught.value.code == "unavailable"
    assert caught.value.safe_reason_code == "TRANSPORT_REMOTE_PROTOCOL_FAILURE"
    assert caught.value.safe_exception_token == "RemoteProtocolError"
    assert "peer closed mid body" not in str(caught.value)


# --------------------------------------------------------------------------
# Safe structured Google error details
# --------------------------------------------------------------------------


def bad_request_body(
    *,
    status: str = "INVALID_ARGUMENT",
    message: str = "private provider explanation",
    fields: list[str] | None = None,
    description: str = "private violation description",
) -> dict[str, object]:
    violations = [{"field": field, "description": description} for field in (fields or [])]
    return {
        "error": {
            "code": 400,
            "message": message,
            "status": status,
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.BadRequest",
                    "fieldViolations": violations,
                }
            ],
        }
    }


def test_error_status_and_invalid_fields_are_extracted_safely() -> None:
    body = bad_request_body(fields=["response_format.delivery", "response_format.image_size"])
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(400, json=body)).generate_image(
            request("private prompt text")
        )
    assert caught.value.code == "invalid_request"
    assert caught.value.status_code == 400
    assert caught.value.safe_reason_code == "INVALID_ARGUMENT"
    assert caught.value.safe_invalid_fields == (
        "response_format.delivery",
        "response_format.image_size",
    )


def test_error_message_and_raw_body_are_never_retained(tmp_path: Path) -> None:
    body = bad_request_body(fields=["response_format.delivery"])
    error = GenerationProviderError("invalid_request")
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(400, json=body)).generate_image(
            request("private prompt text")
        )
    error = caught.value
    rendered = f"{error!r} {error!s} {error.args} {error.__dict__}"
    for secret in (
        "private provider explanation",
        "private violation description",
        "private prompt text",
        "test-gemini-secret",
        json.dumps(body),
    ):
        assert secret not in rendered

    outcome = run_smoke(tmp_path, CountingProvider(error))
    stored = (tmp_path / "checkpoint.json").read_text("utf-8")
    for secret in (
        "private provider explanation",
        "private violation description",
        smoke.SMOKE_PROMPT,
        "test-gemini-secret",
    ):
        assert secret not in stored
    assert json.loads(stored)["provider_invalid_fields"] == ["response_format.delivery"]
    assert outcome.invalid_fields == ("response_format.delivery",)


def test_safe_error_output_names_the_status_and_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    failure = GenerationProviderError(
        "invalid_request",
        status_code=400,
        safe_reason_code="INVALID_ARGUMENT",
        safe_invalid_fields=("response_format.delivery",),
    )
    outcome = run_smoke(tmp_path, CountingProvider(failure))
    smoke._print_outcome(outcome)
    output = capsys.readouterr().out
    assert "PROVIDER_ERROR_STATUS=INVALID_ARGUMENT" in output
    assert "PROVIDER_INVALID_FIELDS=response_format.delivery" in output
    assert "provider HTTP status: 400" in output
    assert smoke.SMOKE_PROMPT not in output


@pytest.mark.parametrize(
    "field",
    [
        "field with spaces",
        "field\nwith\nnewlines",
        "x" * 200,
        "",
        "field;DROP TABLE",
        "../../etc/passwd",
        "<script>alert(1)</script>",
    ],
)
def test_malicious_field_paths_are_discarded(field: str) -> None:
    body = bad_request_body(fields=[field])
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(400, json=body)).generate_image(request())
    assert caught.value.safe_invalid_fields == ()


@pytest.mark.parametrize(
    "status", ["invalid argument", "x" * 100, "", "A;B", "STATUS/SLASH"]
)
def test_malformed_error_status_is_discarded(status: str) -> None:
    body = bad_request_body(status=status, fields=[])
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(400, json=body)).generate_image(request())
    assert caught.value.safe_reason_code == "HTTP_400"


def test_no_field_name_is_invented_when_google_supplies_none() -> None:
    for body in (
        bad_request_body(fields=[]),
        {"error": {"status": "INVALID_ARGUMENT", "message": "no details"}},
        {"error": {"status": "INVALID_ARGUMENT", "details": "not-a-list"}},
        {"error": {"status": "INVALID_ARGUMENT", "details": [{"@type": "other.Type"}]}},
        {
            "error": {
                "status": "INVALID_ARGUMENT",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.BadRequest",
                        "fieldViolations": "invalid",
                    }
                ],
            }
        },
        {
            "error": {
                "status": "INVALID_ARGUMENT",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.BadRequest",
                        "fieldViolations": ["not-a-dict", {"description": "no field"}],
                    }
                ],
            }
        },
    ):
        with pytest.raises(GenerationProviderError) as caught:
            provider(lambda _request, b=body: httpx.Response(400, json=b)).generate_image(
                request()
            )
        assert caught.value.safe_invalid_fields == ()
        assert caught.value.safe_reason_code == "INVALID_ARGUMENT"


def test_snake_case_field_violations_are_supported_and_bounded() -> None:
    many = [f"response_format.field_{index}" for index in range(40)]
    body = {
        "error": {
            "status": "INVALID_ARGUMENT",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.BadRequest",
                    "field_violations": [{"field": field} for field in many],
                }
            ],
        }
    }
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(400, json=body)).generate_image(request())
    assert len(caught.value.safe_invalid_fields) == 16
    assert caught.value.safe_invalid_fields[0] == "response_format.field_0"


def test_unlisted_field_paths_are_dropped_by_the_error_type() -> None:
    error = GenerationProviderError(
        "invalid_request", safe_invalid_fields=("ok.path", "bad path", 42)  # type: ignore[arg-type]
    )
    assert error.safe_invalid_fields == ("ok.path",)


# --------------------------------------------------------------------------
# Definitive rejection: preservation and a new authorized operation
# --------------------------------------------------------------------------


def definitive_store(tmp_path: Path, *, rejections: int = 2) -> smoke.CheckpointStore:
    """Reproduce the live checkpoint: a definitive HTTP 400 with no bytes."""
    store = smoke.CheckpointStore(tmp_path / "checkpoint.json", tmp_path / "private")
    store.write(
        smoke.GeminiProviderCheckpoint(
            operation_state="provider_rejected",
            operation_id="firemark-gemini-op-b4295a0602be4ee2ac74fb9cc90af51b",
            model=MODEL,
            request_id=smoke.SMOKE_REQUEST_ID,
            created_at=NOW,
            new_provider_calls=1,
            prior_rejected_calls=rejections,
            provider_failure_code="invalid_request",
            provider_failure_status=400,
            provider_safe_reason_code="HTTP_400",
            provider_retry_allowed=True,
        )
    )
    return store


def test_second_definitive_rejection_is_classified_as_exhausted(tmp_path: Path) -> None:
    store = definitive_store(tmp_path)
    assert smoke.classify_prior_checkpoint(store, config()) == "definitive_rejection_exhausted"
    assert not smoke._retry_allowed(store.read())
    assert smoke.classify_prior_checkpoint(
        definitive_store(tmp_path, rejections=1), config()
    ) == "definitive_rejection"


def test_exhausted_definitive_checkpoint_blocks_and_is_never_rewritten(tmp_path: Path) -> None:
    store = definitive_store(tmp_path)
    original = store.path.read_bytes()
    blocked = CountingProvider(generated_image())
    outcome = run_smoke(tmp_path, blocked, allow_definitive_retry=True)
    assert outcome.category == "DEFINITIVE_REJECTION_NOT_AUTHORIZED"
    assert blocked.calls == 0
    assert store.path.read_bytes() == original


def test_definitive_option_archives_atomically_and_starts_one_new_operation(
    tmp_path: Path,
) -> None:
    store = definitive_store(tmp_path)
    original = store.path.read_bytes()
    counting = CountingProvider(generated_image())
    outcome = run_smoke(tmp_path, counting, start_new_operation_after_definitive=True)
    assert outcome.category == "OK"
    assert outcome.new_operation is True and outcome.archived is True
    assert counting.calls == 1

    archived = sorted((tmp_path / "archive").glob(f"{smoke.DEFINITIVE_ARCHIVE_PREFIX}*.json"))
    assert len(archived) == 1
    assert archived[0].read_bytes() == original
    preserved = json.loads(archived[0].read_text("utf-8"))
    assert preserved["operation_state"] == "provider_rejected"
    assert preserved["provider_failure_status"] == 400
    assert preserved["prior_rejected_calls"] == 2

    assert outcome.operation_id is not None
    assert outcome.operation_id != "firemark-gemini-op-b4295a0602be4ee2ac74fb9cc90af51b"
    assert outcome.operation_id.startswith("firemark-gemini-op-")

    again = CountingProvider(generated_image())
    assert run_smoke(tmp_path, again).category == "OK"
    assert again.calls == 0


def test_a_second_definitive_failure_closes_the_new_operation(tmp_path: Path) -> None:
    definitive_store(tmp_path)
    failure = GenerationProviderError(
        "invalid_request", status_code=400, safe_reason_code="INVALID_ARGUMENT"
    )
    first = run_smoke(
        tmp_path, CountingProvider(failure), start_new_operation_after_definitive=True
    )
    assert first.category == "INVALID_REQUEST"
    blocked = CountingProvider(generated_image())
    assert run_smoke(tmp_path, blocked).category == "DEFINITIVE_REJECTION_NOT_AUTHORIZED"
    assert blocked.calls == 0
    second = run_smoke(tmp_path, CountingProvider(failure), allow_definitive_retry=True)
    assert second.category == "INVALID_REQUEST"
    exhausted = CountingProvider(generated_image())
    assert run_smoke(tmp_path, exhausted).category == "DEFINITIVE_REJECTION_NOT_AUTHORIZED"
    assert exhausted.calls == 0


@pytest.mark.parametrize(
    ("builder", "category"),
    [
        ("ambiguous", "NO_DEFINITIVE_CHECKPOINT"),
        ("none", "NO_DEFINITIVE_CHECKPOINT"),
        ("recoverable", "NO_DEFINITIVE_CHECKPOINT"),
    ],
)
def test_definitive_option_refuses_every_other_state(
    tmp_path: Path, builder: str, category: str
) -> None:
    if builder == "ambiguous":
        ambiguous_store(tmp_path)
    elif builder == "recoverable":
        assert run_smoke(tmp_path, CountingProvider(generated_image())).category == "OK"
    counting = CountingProvider(generated_image())
    outcome = run_smoke(tmp_path, counting, start_new_operation_after_definitive=True)
    assert outcome.category == category
    assert counting.calls == 0


def test_definitive_option_refuses_a_configuration_mismatch(tmp_path: Path) -> None:
    definitive_store(tmp_path)
    counting = CountingProvider(generated_image())
    outcome = smoke.execute_live(
        config_loader=lambda: config().model_copy(update={"model": "gemini-3-pro-image"}),
        provider_factory=lambda **_kwargs: counting,  # type: ignore[arg-type,return-value]
        checkpoint_path=tmp_path / "checkpoint.json",
        private_root=tmp_path / "private",
        archive_directory=tmp_path / "archive",
        start_new_operation_after_definitive=True,
    )
    assert outcome.category == "NO_DEFINITIVE_CHECKPOINT"
    assert counting.calls == 0
    assert not (tmp_path / "archive").exists()


def test_ambiguous_checkpoint_cannot_use_the_definitive_option(tmp_path: Path) -> None:
    store = ambiguous_store(tmp_path)
    original = store.path.read_bytes()
    counting = CountingProvider(generated_image())
    outcome = run_smoke(tmp_path, counting, start_new_operation_after_definitive=True)
    assert outcome.category == "NO_DEFINITIVE_CHECKPOINT"
    assert counting.calls == 0
    assert store.path.read_bytes() == original


def test_both_new_operation_options_together_are_refused(tmp_path: Path) -> None:
    definitive_store(tmp_path)
    counting = CountingProvider(generated_image())
    outcome = smoke.execute_live(
        config_loader=config,
        provider_factory=lambda **_kwargs: counting,  # type: ignore[arg-type,return-value]
        checkpoint_path=tmp_path / "checkpoint.json",
        private_root=tmp_path / "private",
        archive_directory=tmp_path / "archive",
        start_new_operation_after_ambiguous=True,
        start_new_operation_after_definitive=True,
    )
    assert outcome.category == "CONFIGURATION_ERROR"
    assert counting.calls == 0


def test_definitive_archive_never_overwrites_or_deletes(tmp_path: Path) -> None:
    store = definitive_store(tmp_path)
    archive = tmp_path / "archive"
    fixed = datetime(2026, 8, 2, 9, tzinfo=UTC)
    first = smoke.archive_definitive_checkpoint(store, archive, now=lambda: fixed)
    assert first.name.startswith(smoke.DEFINITIVE_ARCHIVE_PREFIX)
    assert not store.exists()
    definitive_store(tmp_path)
    with pytest.raises(smoke.SafeSmokeError) as caught:
        smoke.archive_definitive_checkpoint(store, archive, now=lambda: fixed)
    assert caught.value.category == "SAFE_UNEXPECTED_FAILURE"
    assert first.read_bytes()
    assert store.exists()


def test_definitive_archive_requires_an_existing_checkpoint(tmp_path: Path) -> None:
    store = smoke.CheckpointStore(tmp_path / "missing.json", tmp_path / "private")
    with pytest.raises(smoke.SafeSmokeError) as caught:
        smoke.archive_definitive_checkpoint(store, tmp_path / "archive")
    assert caught.value.category == "NO_DEFINITIVE_CHECKPOINT"


def test_non_object_error_details_are_skipped() -> None:
    body = {
        "error": {
            "status": "INVALID_ARGUMENT",
            "details": [
                "not-a-dict",
                {
                    "@type": "type.googleapis.com/google.rpc.BadRequest",
                    "fieldViolations": [{"field": "response_format.delivery"}],
                },
            ],
        }
    }
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(400, json=body)).generate_image(request())
    assert caught.value.safe_invalid_fields == ("response_format.delivery",)
