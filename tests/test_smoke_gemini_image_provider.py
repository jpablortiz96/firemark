"""Zero-network tests for the isolated Google Gemini image-provider checkpoint.

Every test in this module mocks transport. No test contacts Google Gemini,
GMI Cloud, OpenAI, ElevenLabs, Backblaze B2, or Supabase.
"""

from __future__ import annotations

import base64
import hashlib
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
    DOCUMENTED_IMAGE_MIME_TYPES,
    GEMINI_API_BASE_URL,
    GEMINI_API_HOST,
    GEMINI_INTERACTIONS_PATH,
    GeminiImageProvider,
)
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.provider import (
    SAFE_EXCEPTION_TOKENS,
    GenerationProviderError,
)
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


IMAGE_URI = f"https://{GEMINI_API_HOST}/v1beta/files/generated-image:download"
SIGNED_URI = "https://lh3.googleusercontent.com/firemark/generated-image"


def interaction_body(
    *,
    uri: str | None = IMAGE_URI,
    data: str | None = None,
    mime_type: str = "image/png",
    status: str = "completed",
    use_steps: bool = False,
    image_blocks: int = 1,
) -> dict[str, object]:
    """Build an interaction response. URI delivery is the default shape."""
    image: dict[str, object] = {"type": "image", "mime_type": mime_type}
    if data is not None:
        image["data"] = data
    elif uri is not None:
        image["uri"] = uri
    else:
        image["data"] = base64.b64encode(_TINY_PNG).decode()
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
    """The defensive inline-Base64 shape used when a provider ignores delivery."""
    kwargs.setdefault("data", base64.b64encode(_TINY_PNG).decode())
    return interaction_body(uri=None, **kwargs)


def png_download(
    payload: bytes = _TINY_PNG,
    *,
    content_type: str = "image/png",
    content_length: str | None = None,
    status: int = 200,
    location: str | None = None,
) -> httpx.Response:
    headers = {"content-type": content_type}
    if location is not None:
        headers["location"] = location
    response = httpx.Response(status, headers=headers, content=payload)
    if content_length is not None:
        response.headers["content-length"] = content_length
    return response


class DownloadRecorder:
    """Capture every download request so URI and header use can be asserted."""

    def __init__(self, *responses: httpx.Response) -> None:
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, http_request: httpx.Request) -> httpx.Response:
        self.requests.append(http_request)
        if not self.responses:
            return png_download()
        return self.responses.pop(0)


def client(handler: Any) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url=GEMINI_API_BASE_URL,
    )


def provider(
    handler: Any,
    *,
    secret: str = "test-gemini-secret",
    download: Any = None,
    max_image_bytes: int = 1024 * 1024,
    stage_callback: Any = None,
) -> GeminiImageProvider:
    downloader = download if download is not None else DownloadRecorder()
    return GeminiImageProvider(
        api_key=secret,
        timeout_seconds=30,
        max_image_bytes=max_image_bytes,
        client_factory=lambda: client(handler),
        download_client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(downloader)
        ),
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
            "response_format": {
                "type": "image",
                "mime_type": "image/png",
                "aspect_ratio": "1:1",
                "image_size": "1K",
                "delivery": "uri",
            },
            "stream": False,
            "background": False,
            "store": False,
        }
    ]
    payload = captured[0]
    assert payload["model"] == MODEL
    assert payload["stream"] is False
    assert payload["background"] is False
    assert payload["store"] is False
    response_format = payload["response_format"]
    assert isinstance(response_format, dict)
    assert response_format["delivery"] == "uri"
    assert response_format["type"] == "image"
    assert response_format["mime_type"] == "image/png"
    assert response_format["aspect_ratio"] == "1:1"
    assert response_format["image_size"] == "1K"
    assert "contents" not in payload
    assert "generationConfig" not in payload


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
    assert set(first) == {"model", "input", "response_format", "stream", "background", "store"}


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
        (inline_body(data="%%%"), "malformed_response"),
        (inline_body(data=""), "malformed_response"),
        (inline_body(mime_type="image/jpeg"), "non_png_response"),
        (inline_body(mime_type="image/webp"), "non_png_response"),
        (inline_body(mime_type="application/json"), "malformed_response"),
        (inline_body(data=base64.b64encode(b"not-png").decode()), "non_png_response"),
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
    assert caught.value.safe_reason_code == "INTERACTION_BODY_TOO_LARGE"


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


def test_download_transport_failures_are_classified_separately() -> None:
    def failing_download(_request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("peer closed connection")

    with pytest.raises(GenerationProviderError) as caught:
        ok_provider(download=failing_download).generate_image(request())
    assert caught.value.code == "unavailable"
    assert caught.value.safe_reason_code == "TRANSPORT_REMOTE_PROTOCOL_FAILURE"
    assert caught.value.safe_exception_token == "RemoteProtocolError"


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

    def hostile_factory(**kwargs: Any) -> GeminiImageProvider:
        return HostileMetadata(
            api_key="secret",
            timeout_seconds=30,
            max_image_bytes=1024 * 1024,
            client_factory=lambda: client(
                lambda _request: httpx.Response(200, json=interaction_body())
            ),
            download_client_factory=lambda: httpx.Client(
                transport=httpx.MockTransport(DownloadRecorder())
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
    tmp_path: Path,
    instance: object,
    *,
    allow_definitive_retry: bool = False,
    start_new_operation_after_ambiguous: bool = False,
) -> smoke.SmokeOutcome:
    return smoke.execute_live(
        config_loader=config,
        provider_factory=lambda **_kwargs: instance,  # type: ignore[arg-type,return-value]
        checkpoint_path=tmp_path / "checkpoint.json",
        private_root=tmp_path / "private",
        archive_directory=tmp_path / "archive",
        allow_definitive_retry=allow_definitive_retry,
        start_new_operation_after_ambiguous=start_new_operation_after_ambiguous,
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


def test_uri_delivery_is_the_default_and_downloads_through_a_separate_client() -> None:
    recorder = DownloadRecorder(png_download())
    image = ok_provider(download=recorder).generate_image(request())
    assert image.data == _TINY_PNG
    assert image.safe_generation_metadata["delivery"] == "uri"
    assert image.safe_generation_metadata["aspect_ratio"] == "1:1"
    assert image.safe_generation_metadata["image_size"] == "1K"
    assert len(recorder.requests) == 1
    assert str(recorder.requests[0].url) == IMAGE_URI
    assert recorder.requests[0].method == "GET"


def test_source_sha256_is_calculated_during_the_download() -> None:
    recorder = DownloadRecorder(png_download())
    image = ok_provider(download=recorder).generate_image(request())
    assert image.safe_generation_metadata["source_sha256"] == hashlib.sha256(_TINY_PNG).hexdigest()


def test_step_content_image_uri_is_parsed() -> None:
    recorder = DownloadRecorder(png_download())
    image = provider(
        lambda _request: httpx.Response(200, json=interaction_body(use_steps=True)),
        download=recorder,
    ).generate_image(request())
    assert image.data == _TINY_PNG
    assert len(recorder.requests) == 1


def test_inline_delivery_remains_a_defensive_fallback() -> None:
    recorder = DownloadRecorder()
    image = provider(
        lambda _request: httpx.Response(200, json=inline_body()), download=recorder
    ).generate_image(request())
    assert image.data == _TINY_PNG
    assert image.safe_generation_metadata["delivery"] == "inline"
    assert recorder.requests == []


def test_api_key_is_sent_only_to_the_gemini_api_host() -> None:
    gemini_host = DownloadRecorder(png_download())
    provider(
        lambda _request: httpx.Response(200, json=interaction_body(uri=IMAGE_URI)),
        download=gemini_host,
    ).generate_image(request())
    assert gemini_host.requests[0].headers["x-goog-api-key"] == "test-gemini-secret"

    signed_host = DownloadRecorder(png_download())
    provider(
        lambda _request: httpx.Response(200, json=interaction_body(uri=SIGNED_URI)),
        download=signed_host,
    ).generate_image(request())
    assert "x-goog-api-key" not in signed_host.requests[0].headers
    assert "authorization" not in signed_host.requests[0].headers


@pytest.mark.parametrize(
    ("uri", "reason"),
    [
        ("http://generativelanguage.googleapis.com/image.png", "IMAGE_URI_SCHEME_REJECTED"),
        ("ftp://generativelanguage.googleapis.com/image.png", "IMAGE_URI_SCHEME_REJECTED"),
        ("file:///etc/passwd", "IMAGE_URI_SCHEME_REJECTED"),
        (
            "https://user:secret@generativelanguage.googleapis.com/image.png",
            "IMAGE_URI_CREDENTIALS_REJECTED",
        ),
        (f"https://{GEMINI_API_HOST}/image.png#fragment", "IMAGE_URI_FRAGMENT_REJECTED"),
        (f"https://{GEMINI_API_HOST}/" + "a" * 2100, "IMAGE_URI_TOO_LONG"),
        ("https://localhost/image.png", "IMAGE_URI_PRIVATE_HOST_REJECTED"),
        ("https://evil.localhost/image.png", "IMAGE_URI_PRIVATE_HOST_REJECTED"),
        ("https://127.0.0.1/image.png", "IMAGE_URI_PRIVATE_HOST_REJECTED"),
        ("https://[::1]/image.png", "IMAGE_URI_PRIVATE_HOST_REJECTED"),
        ("https://10.0.0.5/image.png", "IMAGE_URI_PRIVATE_HOST_REJECTED"),
        ("https://192.168.1.10/image.png", "IMAGE_URI_PRIVATE_HOST_REJECTED"),
        ("https://172.16.4.4/image.png", "IMAGE_URI_PRIVATE_HOST_REJECTED"),
        ("https://169.254.169.254/latest/meta-data", "IMAGE_URI_PRIVATE_HOST_REJECTED"),
        ("https://[fe80::1]/image.png", "IMAGE_URI_PRIVATE_HOST_REJECTED"),
        ("https://attacker.example.com/image.png", "IMAGE_URI_HOST_REJECTED"),
        ("https://googleapis.com.attacker.test/image.png", "IMAGE_URI_HOST_REJECTED"),
        ("https://gmi-cloud.test/image.png", "IMAGE_URI_HOST_REJECTED"),
        (f"https://{GEMINI_API_HOST}:notaport/image.png", "IMAGE_URI_MALFORMED"),
    ],
)
def test_unsafe_image_uris_are_rejected_without_downloading(uri: str, reason: str) -> None:
    recorder = DownloadRecorder()

    def refuse(_request: httpx.Request) -> httpx.Response:
        pytest.fail("an unsafe URI must never be downloaded")

    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(200, json=interaction_body(uri=uri)),
            download=refuse,
        ).generate_image(request())
    assert caught.value.code == "malformed_response"
    assert caught.value.safe_reason_code == reason
    assert uri not in str(caught.value)
    assert uri not in repr(caught.value)
    assert recorder.requests == []


@pytest.mark.parametrize(
    "uri",
    [
        f"https://{GEMINI_API_HOST}/v1beta/files/x:download",
        "https://storage.googleapis.com/bucket/generated.png",
        "https://lh3.googleusercontent.com/firemark/generated",
        "https://us-central1-aiplatform.googleapis.com/generated.png",
    ],
)
def test_google_hosted_uris_are_accepted(uri: str) -> None:
    recorder = DownloadRecorder(png_download())
    image = provider(
        lambda _request: httpx.Response(200, json=interaction_body(uri=uri)), download=recorder
    ).generate_image(request())
    assert image.data == _TINY_PNG
    assert str(recorder.requests[0].url) == uri


def test_missing_uri_and_missing_data_fails_closed() -> None:
    body = {"status": "completed", "output_image": {"type": "image", "mime_type": "image/png"}}
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(200, json=body)).generate_image(request())
    assert caught.value.safe_reason_code == "IMAGE_REFERENCE_MISSING"


def test_second_redirect_is_rejected_and_first_is_validated() -> None:
    single = DownloadRecorder(
        png_download(status=302, location=SIGNED_URI), png_download()
    )
    image = provider(
        lambda _request: httpx.Response(200, json=interaction_body()), download=single
    ).generate_image(request())
    assert image.data == _TINY_PNG
    assert [str(call.url) for call in single.requests] == [IMAGE_URI, SIGNED_URI]
    assert "x-goog-api-key" in single.requests[0].headers
    assert "x-goog-api-key" not in single.requests[1].headers

    chained = DownloadRecorder(
        png_download(status=302, location=SIGNED_URI),
        png_download(status=302, location=SIGNED_URI),
    )
    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(200, json=interaction_body()), download=chained
        ).generate_image(request())
    assert caught.value.safe_reason_code == "IMAGE_URI_REDIRECT_REJECTED"


def test_redirect_to_an_unsafe_destination_is_rejected() -> None:
    hostile = DownloadRecorder(png_download(status=302, location="https://127.0.0.1/image.png"))
    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(200, json=interaction_body()), download=hostile
        ).generate_image(request())
    assert caught.value.safe_reason_code == "IMAGE_URI_PRIVATE_HOST_REJECTED"


def test_redirect_without_a_location_is_rejected() -> None:
    headerless = DownloadRecorder(png_download(status=302))
    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(200, json=interaction_body()), download=headerless
        ).generate_image(request())
    assert caught.value.safe_reason_code == "IMAGE_URI_REDIRECT_REJECTED"


@pytest.mark.parametrize(
    ("response", "code", "reason"),
    [
        (png_download(content_type="image/jpeg"), "non_png_response", None),
        (png_download(content_type="image/webp"), "non_png_response", None),
        (png_download(content_type="text/html"), "malformed_response", "IMAGE_CONTENT_TYPE_REJECTED"),
        (
            png_download(content_type="application/json"),
            "malformed_response",
            "IMAGE_CONTENT_TYPE_REJECTED",
        ),
        (png_download(b"not-a-png-at-all"), "non_png_response", None),
        (
            png_download(content_length="9999"),
            "malformed_response",
            "IMAGE_DOWNLOAD_TRUNCATED",
        ),
        (
            png_download(content_length="invalid"),
            "malformed_response",
            "IMAGE_CONTENT_LENGTH_INVALID",
        ),
    ],
)
def test_download_responses_are_validated(
    response: httpx.Response, code: str, reason: str | None
) -> None:
    with pytest.raises(GenerationProviderError) as caught:
        ok_provider(download=DownloadRecorder(response)).generate_image(request())
    assert caught.value.code == code
    if reason is not None:
        assert caught.value.safe_reason_code == reason


def test_download_is_bounded_by_declared_and_streamed_size() -> None:
    declared = png_download(content_length=str(64 * 1024 * 1024))
    with pytest.raises(GenerationProviderError) as by_header:
        ok_provider(download=DownloadRecorder(declared), max_image_bytes=1024).generate_image(
            request()
        )
    assert by_header.value.code == "response_too_large"

    class LargeStream(httpx.SyncByteStream):
        def __iter__(self) -> Any:
            for _ in range(4):
                yield b"x" * 4096

    streamed = httpx.Response(
        200, headers={"content-type": "image/png"}, stream=LargeStream()
    )
    with pytest.raises(GenerationProviderError) as by_stream:
        ok_provider(download=DownloadRecorder(streamed), max_image_bytes=1024).generate_image(
            request()
        )
    assert by_stream.value.code == "response_too_large"


def test_failed_download_status_is_classified() -> None:
    with pytest.raises(GenerationProviderError) as caught:
        ok_provider(
            download=DownloadRecorder(httpx.Response(403, json={"error": {"status": "PERMISSION_DENIED"}}))
        ).generate_image(request())
    assert caught.value.code == "permission_denied"
    assert caught.value.status_code == 403


def test_documented_image_types_are_declared_once() -> None:
    assert DOCUMENTED_IMAGE_MIME_TYPES == {"image/png", "image/jpeg", "image/webp"}


# --------------------------------------------------------------------------
# The transient URI never escapes the download operation
# --------------------------------------------------------------------------


def test_uri_is_absent_from_checkpoint_output_and_metadata(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret_uri = f"https://{GEMINI_API_HOST}/v1beta/files/private-token-abc123:download"

    def factory(**kwargs: Any) -> GeminiImageProvider:
        return provider(
            lambda _request: httpx.Response(200, json=interaction_body(uri=secret_uri)),
            download=DownloadRecorder(png_download()),
            stage_callback=kwargs.get("stage_callback"),
        )

    outcome = smoke.execute_live(
        config_loader=config,
        provider_factory=factory,
        checkpoint_path=tmp_path / "checkpoint.json",
        private_root=tmp_path / "private",
        archive_directory=tmp_path / "archive",
    )
    assert outcome.category == "OK"
    assert outcome.image is not None
    smoke._print_outcome(outcome)
    output = capsys.readouterr().out
    stored = (tmp_path / "checkpoint.json").read_text("utf-8")
    metadata = json.dumps(outcome.image.safe_generation_metadata)
    for haystack in (output, stored, metadata):
        assert secret_uri not in haystack
        assert "private-token-abc123" not in haystack
    assert "URI delivery used: true" in output


def test_uri_never_appears_in_a_download_failure_exception() -> None:
    secret_uri = f"https://{GEMINI_API_HOST}/v1beta/files/leak-token-xyz:download"

    def failing(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadError("private transport detail")

    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(200, json=interaction_body(uri=secret_uri)),
            download=failing,
        ).generate_image(request())
    rendered = f"{caught.value!r} {caught.value!s} {caught.value.args}"
    assert secret_uri not in rendered
    assert "leak-token-xyz" not in rendered
    assert "private transport detail" not in rendered


# --------------------------------------------------------------------------
# Ambiguous checkpoint preservation and operator-authorized new operations
# --------------------------------------------------------------------------


def test_help_documents_the_new_operation_option() -> None:
    help_text = " ".join(smoke.build_parser().format_help().split())
    assert "--start-new-operation-after-ambiguous" in help_text
    assert "not a retry of the ambiguous submission" in help_text
    assert "Requires --live" in help_text


def test_new_operation_option_requires_live(capsys: pytest.CaptureFixture[str]) -> None:
    assert smoke.main(["--start-new-operation-after-ambiguous"]) == 1
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


def test_default_download_client_is_independent_and_non_redirecting() -> None:
    instance = GeminiImageProvider(api_key="secret", timeout_seconds=45, max_image_bytes=1024)
    download = instance._download_client()
    interaction = instance._client()
    assert download is not interaction
    assert download.follow_redirects is False
    assert str(interaction.base_url) == GEMINI_API_BASE_URL
    assert download.timeout.read == 45.0
    assert download.timeout.connect == 30.0
    assert download.timeout.pool == 30.0
    download.close()
    interaction.close()


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


def test_blank_and_hostless_uris_are_rejected() -> None:
    assert smoke  # module import guard keeps this test in the smoke suite
    for uri, reason in (("", "IMAGE_URI_MISSING"), ("https:///image.png", "IMAGE_URI_HOST_MISSING")):
        with pytest.raises(GenerationProviderError) as caught:
            GeminiImageProvider._validated_image_uri(uri)
        assert caught.value.safe_reason_code == reason


def test_download_bound_is_enforced_before_the_body_is_read() -> None:
    oversized = png_download(content_length=str(4096))
    with pytest.raises(GenerationProviderError) as caught:
        ok_provider(
            download=DownloadRecorder(oversized), max_image_bytes=1024
        ).generate_image(request())
    assert caught.value.code == "response_too_large"


def test_provider_reported_stages_are_part_of_the_declared_stage_table() -> None:
    assert smoke.PROVIDER_STAGES <= set(smoke.STAGES)
    reported: list[str] = []
    ok_provider(stage_callback=reported.append).generate_image(request())
    assert reported == [
        "interaction_submission",
        "interaction_metadata_validation",
        "image_uri_validation",
        "image_download",
    ]
