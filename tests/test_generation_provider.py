"""Zero-network generation provider contract tests."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from openai import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    InternalServerError,
    PermissionDeniedError,
    RateLimitError,
)
from pydantic import ValidationError

from api.firemark.generation.fake_provider import _TINY_PNG, FakeGenerationProvider
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.openai_provider import OpenAIImageProvider
from api.firemark.generation.provider import GenerationProviderError

SECRET = "test-only-openai-secret-value"


def request() -> GenerationRequest:
    return GenerationRequest(
        prompt="private test prompt",
        model="gpt-image-test",
        size="1024x1024",
        request_id="firemark-run-test",
    )


class Images:
    def __init__(self, response: object = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def generate(self, **kwargs: Any) -> object:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


def provider(images: Images, **kwargs: Any) -> OpenAIImageProvider:
    client = SimpleNamespace(images=images)
    return OpenAIImageProvider(
        api_key=SECRET,
        timeout_seconds=30,
        max_image_bytes=1024 * 1024,
        client_factory=lambda: client,
        **kwargs,
    )


def response(*, payload: bytes = _TINY_PNG, url: str | None = None) -> object:
    item = SimpleNamespace(
        b64_json=base64.b64encode(payload).decode() if url is None else None,
        url=url,
    )
    return SimpleNamespace(data=[item], created=1785412800, _request_id="req_safe-123")


def test_fake_provider_is_deterministic_and_explicitly_not_ai_generated() -> None:
    fake = FakeGenerationProvider()
    first = fake.generate_image(request())
    second = fake.generate_image(request())
    assert first == second
    assert first.provider == "fake"
    assert first.ai_generated is False
    assert first.safe_generation_metadata["local_fixture"] is True
    assert fake.calls == 2


def test_openai_base64_response_uses_official_shape_and_redacts_secret() -> None:
    images = Images(response())
    adapter = provider(images)
    result = adapter.generate_image(request())
    assert result.data == _TINY_PNG
    assert result.ai_generated is True
    assert result.provider == "openai"
    assert result.provider_request_id == "req_safe-123"
    assert result.provider_created_at.tzinfo == UTC
    assert images.calls == [
        {
            "prompt": "private test prompt",
            "model": "gpt-image-test",
            "size": "1024x1024",
            "n": 1,
            "output_format": "png",
            "timeout": 30.0,
        }
    ]
    assert SECRET not in repr(adapter)
    assert "private test prompt" not in repr(request())
    assert _TINY_PNG.hex() not in repr(result)


def test_dalle_family_uses_response_format_without_gpt_output_format() -> None:
    images = Images(response())
    dalle_request = request().model_copy(update={"model": "dall-e-3"})
    provider(images).generate_image(dalle_request)
    assert images.calls[0]["response_format"] == "b64_json"
    assert "output_format" not in images.calls[0]


def test_official_url_response_is_downloaded_once_with_no_redirect() -> None:
    calls: list[httpx.Request] = []

    def handler(incoming: httpx.Request) -> httpx.Response:
        calls.append(incoming)
        return httpx.Response(200, content=_TINY_PNG, headers={"Content-Length": "68"})

    images = Images(response(url="https://images.openai.com/generated?id=private"))
    adapter = provider(
        images,
        http_client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ),
    )
    assert adapter.generate_image(request()).data == _TINY_PNG
    assert len(calls) == 1
    assert calls[0].url.host == "images.openai.com"


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (
            AuthenticationError(
                "secret upstream detail",
                response=httpx.Response(401, request=httpx.Request("POST", "https://api.openai.com")),
                body=None,
            ),
            "authentication",
        ),
        (
            PermissionDeniedError(
                "secret upstream detail",
                response=httpx.Response(403, request=httpx.Request("POST", "https://api.openai.com")),
                body=None,
            ),
            "permission_denied",
        ),
        (
            RateLimitError(
                "secret upstream detail",
                response=httpx.Response(429, request=httpx.Request("POST", "https://api.openai.com")),
                body=None,
            ),
            "rate_limit",
        ),
        (APITimeoutError(request=httpx.Request("POST", "https://api.openai.com")), "timeout"),
        (
            APIConnectionError(request=httpx.Request("POST", "https://api.openai.com")),
            "unavailable",
        ),
        (
            InternalServerError(
                "secret upstream detail",
                response=httpx.Response(500, request=httpx.Request("POST", "https://api.openai.com")),
                body=None,
            ),
            "unavailable",
        ),
        (
            BadRequestError(
                "secret upstream detail",
                response=httpx.Response(400, request=httpx.Request("POST", "https://api.openai.com")),
                body={"code": "invalid_request"},
            ),
            "invalid_request",
        ),
    ],
)
def test_provider_failures_are_normalized_without_raw_messages(
    error: Exception, code: str
) -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(Images(error=error)).generate_image(request())
    assert caught.value.code == code
    assert "secret upstream detail" not in str(caught.value)
    assert SECRET not in str(caught.value)


def test_safety_failure_is_classified_intentionally() -> None:
    error = BadRequestError(
        "private policy response",
        response=httpx.Response(400, request=httpx.Request("POST", "https://api.openai.com")),
        body={"code": "content_policy_violation"},
    )
    error.code = "content_policy_violation"
    with pytest.raises(GenerationProviderError, match="safety_rejection"):
        provider(Images(error=error)).generate_image(request())


def test_quota_and_model_size_failures_are_distinct() -> None:
    quota = RateLimitError(
        "private quota response",
        response=httpx.Response(429, request=httpx.Request("POST", "https://api.openai.com")),
        body={"code": "insufficient_quota"},
    )
    quota.code = "insufficient_quota"
    model = BadRequestError(
        "private model response",
        response=httpx.Response(400, request=httpx.Request("POST", "https://api.openai.com")),
        body={"code": "model_not_found", "param": "model"},
    )
    model.code = "model_not_found"
    model.param = "model"
    with pytest.raises(GenerationProviderError, match="quota_or_billing"):
        provider(Images(error=quota)).generate_image(request())
    with pytest.raises(GenerationProviderError, match="model_or_size_unsupported"):
        provider(Images(error=model)).generate_image(request())


@pytest.mark.parametrize(
    "bad_response",
    [
        SimpleNamespace(data=None, created=1),
        SimpleNamespace(data=[], created=1),
        SimpleNamespace(data=[SimpleNamespace(b64_json="%%%", url=None)], created=1),
        SimpleNamespace(data=[SimpleNamespace(b64_json=None, url=None)], created=1),
        SimpleNamespace(data=[SimpleNamespace(b64_json=base64.b64encode(b"not-png").decode(), url=None)], created=1),
        SimpleNamespace(data=[SimpleNamespace(b64_json=base64.b64encode(_TINY_PNG).decode(), url=None)], created="bad"),
    ],
)
def test_malformed_response_shapes_and_non_png_fail_closed(bad_response: object) -> None:
    response_data = getattr(bad_response, "data", None)
    expected = (
        "non_png_response"
        if isinstance(response_data, list)
        and response_data
        and getattr(response_data[0], "b64_json", "")
        == base64.b64encode(b"not-png").decode()
        else "malformed_response"
    )
    with pytest.raises(GenerationProviderError, match=expected):
        provider(Images(bad_response)).generate_image(request())


@pytest.mark.parametrize(
    "url",
    [
        "http://images.openai.com/file",
        "https://user:password@images.openai.com/file",
        "https://127.0.0.1/file",
        "https://example.com/file",
        "https://images.openai.com:444/file",
    ],
)
def test_provider_url_validation_rejects_unsafe_origins_without_http(url: str) -> None:
    with pytest.raises(GenerationProviderError, match="malformed_response"):
        provider(Images(response(url=url))).generate_image(request())


def test_download_redirect_http_failure_declared_and_streamed_oversize_are_safe() -> None:
    def run(status: int, content: bytes, headers: dict[str, str] | None = None) -> str:
        adapter = provider(
            Images(response(url="https://images.openai.com/file")),
            http_client_factory=lambda: httpx.Client(
                transport=httpx.MockTransport(
                    lambda req: httpx.Response(status, content=content, headers=headers)
                ),
                follow_redirects=False,
            ),
        )
        with pytest.raises(GenerationProviderError) as caught:
            adapter.generate_image(request())
        return caught.value.code

    assert run(302, b"", {"Location": "https://images.openai.com/other"}) == "malformed_response"
    assert run(503, b"unavailable") == "unavailable"
    assert run(200, b"x", {"Content-Length": str(2 * 1024 * 1024)}) == "response_too_large"
    assert run(200, b"x" * (1024 * 1024 + 1)) == "response_too_large"


def test_generation_models_reject_private_invalid_and_oversized_shapes() -> None:
    with pytest.raises(ValidationError):
        GenerationRequest(prompt=" ", model="bad model", size="x", request_id="bad id")
    with pytest.raises(ValidationError, match="not a PNG"):
        GeneratedImage(
            data=b"not-png",
            provider="openai",
            model="test",
            provider_created_at=datetime.now(UTC),
            ai_generated=True,
        )
    with pytest.raises(ValidationError, match="private field"):
        GeneratedImage(
            data=_TINY_PNG,
            provider="openai",
            model="test",
            provider_created_at=datetime.now(UTC),
            safe_generation_metadata={"provider_url": "https://private.example"},
            ai_generated=True,
        )
    with pytest.raises(ValidationError, match="request identifier"):
        GeneratedImage(
            data=_TINY_PNG,
            provider="openai",
            model="test",
            provider_request_id="unsafe request id",
            provider_created_at=datetime.now(UTC),
            ai_generated=True,
        )
