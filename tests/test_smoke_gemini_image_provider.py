"""Zero-network tests for the isolated Gemini image-provider checkpoint."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

import scripts.smoke_gemini_image_provider as smoke
import scripts.smoke_multimodal_generate_and_seal as multimodal
from api.firemark.generation.fake_provider import _TINY_PNG
from api.firemark.generation.gemini_provider import (
    GeminiImageProvider,
    GeminiModelAccess,
)
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.settings import GeminiImageConfig

NOW = datetime(2026, 7, 30, 22, tzinfo=UTC)


def config(*, secret: str = "test-gemini-secret") -> GeminiImageConfig:
    return GeminiImageConfig(
        api_key=SecretStr(secret),
        model="gemini-3.1-flash-image",
        timeout_seconds=30,
        max_image_bytes=1024 * 1024,
    )


def request(prompt: str = "private prompt") -> GenerationRequest:
    return GenerationRequest(
        prompt=prompt,
        model="gemini-3.1-flash-image",
        size="1024x1024",
        request_id="firemark-gemini-test",
    )


def image_body(*, snake_case: bool = False, extra_parts: list[object] | None = None) -> dict[str, object]:
    inline_key = "inline_data" if snake_case else "inlineData"
    mime_key = "mime_type" if snake_case else "mimeType"
    parts: list[object] = list(extra_parts or [])
    parts.append(
        {
            inline_key: {
                mime_key: "image/png",
                "data": base64.b64encode(_TINY_PNG).decode(),
            }
        }
    )
    return {"candidates": [{"content": {"parts": parts}}]}


def client(handler: Any) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://generativelanguage.googleapis.com",
    )


def provider(handler: Any, *, secret: str = "test-gemini-secret") -> GeminiImageProvider:
    return GeminiImageProvider(
        api_key=secret,
        timeout_seconds=30,
        max_image_bytes=1024 * 1024,
        client_factory=lambda: client(handler),
        now=lambda: NOW,
    )


def test_non_live_constructs_no_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        smoke,
        "execute_live",
        lambda: pytest.fail("live execution must remain opt-in"),
    )
    assert smoke.main([]) == 2


def test_help_contract() -> None:
    assert "--live" in smoke.build_parser().format_help()


def test_exact_official_generation_endpoint_header_and_payload() -> None:
    calls: list[httpx.Request] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        calls.append(http_request)
        assert http_request.method == "POST"
        assert http_request.url.path == (
            "/v1/models/gemini-3.1-flash-image:generateContent"
        )
        assert http_request.headers["x-goog-api-key"] == "test-gemini-secret"
        assert http_request.headers["content-type"].startswith("application/json")
        payload = json.loads(http_request.content)
        assert payload == {
            "contents": [{"parts": [{"text": "private prompt"}]}],
            "generationConfig": {"responseModalities": ["IMAGE"]},
        }
        forbidden = {
            "size",
            "quality",
            "n",
            "output_format",
            "responseMimeType",
            "responseFormat",
        }
        generation_config = payload["generationConfig"]
        assert isinstance(generation_config, dict)
        assert all(field not in payload for field in forbidden)
        assert all(field not in generation_config for field in forbidden)
        return httpx.Response(200, json=image_body())

    result = provider(handler).generate_image(request())
    assert result.data == _TINY_PNG
    assert len(calls) == 1


def test_minimal_request_ignores_provider_neutral_size() -> None:
    first = GeminiImageProvider.build_request_parameters(request())
    second = GeminiImageProvider.build_request_parameters(
        request().model_copy(update={"size": "1792x1024"})
    )
    assert first == second
    assert set(first) == {"contents", "generationConfig"}


def test_model_preflight_success_and_generate_content_support() -> None:
    seen: list[httpx.Request] = []

    def handler(http_request: httpx.Request) -> httpx.Response:
        seen.append(http_request)
        return httpx.Response(
            200,
            json={
                "name": "models/gemini-3.1-flash-image",
                "supportedGenerationMethods": ["generateContent", "countTokens"],
            },
        )

    access = provider(handler).preflight_model("gemini-3.1-flash-image")
    assert access.available and access.supports_generate_content is True
    assert seen[0].method == "GET"
    assert seen[0].url.path == "/v1beta/models/gemini-3.1-flash-image"
    assert seen[0].headers["x-goog-api-key"] == "test-gemini-secret"


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (httpx.Response(302), "malformed_response"),
        (httpx.Response(200, headers={"content-length": "999999"}), "response_too_large"),
        (httpx.Response(200, headers={"content-length": "invalid"}), "malformed_response"),
    ],
)
def test_model_preflight_rejects_redirects_and_unbounded_bodies(
    response: httpx.Response, code: str
) -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: response).preflight_model("gemini-3.1-flash-image")
    assert caught.value.code == code


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"name": "models/different-model"},
        {"name": "models/gemini-3.1-flash-image", "supportedGenerationMethods": [1]},
    ],
)
def test_model_preflight_rejects_malformed_success(payload: object) -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(200, json=payload)).preflight_model(
            "gemini-3.1-flash-image"
        )
    assert caught.value.code == "malformed_response"


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        (httpx.ReadTimeout("timeout"), "timeout"),
        (httpx.ConnectError("offline"), "unavailable"),
    ],
)
def test_model_preflight_transport_failures_are_safe(
    failure: Exception, code: str
) -> None:
    failing = provider(lambda _request: (_ for _ in ()).throw(failure))
    with pytest.raises(GenerationProviderError) as caught:
        failing.preflight_model("gemini-3.1-flash-image")
    assert caught.value.code == code


@pytest.mark.parametrize(
    ("status", "provider_code"),
    [
        (401, "authentication"),
        (403, "permission_denied"),
        (404, "model_or_size_unsupported"),
        (429, "rate_limit"),
    ],
)
def test_model_preflight_safe_failures(status: int, provider_code: str) -> None:
    preflight = provider(lambda _request: httpx.Response(status))
    with pytest.raises(GenerationProviderError) as caught:
        preflight.preflight_model("gemini-3.1-flash-image")
    assert caught.value.code == provider_code
    assert caught.value.status_code == status


@pytest.mark.parametrize("snake_case", [False, True])
def test_response_supports_inline_data_casing(snake_case: bool) -> None:
    result = provider(
        lambda _request: httpx.Response(200, json=image_body(snake_case=snake_case))
    ).generate_image(request())
    assert result.data == _TINY_PNG


def test_text_and_thought_parts_are_ignored() -> None:
    body = image_body(extra_parts=[{"text": "ignored"}, {"thought": True, "text": "ignored"}])
    result = provider(lambda _request: httpx.Response(200, json=body)).generate_image(request())
    assert result.data == _TINY_PNG


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({}, "malformed_response"),
        ({"candidates": []}, "malformed_response"),
        ({"candidates": [{"content": {"parts": [{"text": "only"}]}}]}, "malformed_response"),
        (
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"inlineData": {"mimeType": "image/png", "data": "%%%"}}
                            ]
                        }
                    }
                ]
            },
            "malformed_response",
        ),
        (
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "inlineData": {
                                        "mimeType": "image/jpeg",
                                        "data": base64.b64encode(_TINY_PNG).decode(),
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
            "non_png_response",
        ),
        (
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "inlineData": {
                                        "mimeType": "image/png",
                                        "data": base64.b64encode(b"not-png").decode(),
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
            "non_png_response",
        ),
    ],
)
def test_malformed_or_missing_images_fail_closed(body: dict[str, object], code: str) -> None:
    with pytest.raises(GenerationProviderError) as caught:
        provider(lambda _request: httpx.Response(200, json=body)).generate_image(request())
    assert caught.value.code == code


def test_empty_base64_and_decoded_oversize_fail_closed() -> None:
    empty = {
        "candidates": [
            {
                "content": {
                    "parts": [{"inlineData": {"mimeType": "image/png", "data": ""}}]
                }
            }
        ]
    }
    with pytest.raises(GenerationProviderError) as caught_empty:
        provider(lambda _request: httpx.Response(200, json=empty)).generate_image(request())
    assert caught_empty.value.code == "malformed_response"
    bounded = GeminiImageProvider(
        api_key="secret",
        timeout_seconds=30,
        max_image_bytes=10,
    )
    with pytest.raises(GenerationProviderError) as caught_large:
        bounded.validate_response(httpx.Response(200, json=image_body()), request())
    assert caught_large.value.code == "response_too_large"


@pytest.mark.parametrize(
    ("status", "error", "code"),
    [
        (400, {"status": "INVALID_ARGUMENT", "message": "invalid field"}, "invalid_request"),
        (400, {"status": "INVALID_ARGUMENT", "message": "model is unsupported"}, "model_or_size_unsupported"),
        (400, {"status": "FAILED_PRECONDITION", "message": "blocked by safety"}, "safety_rejection"),
        (403, {"status": "RESOURCE_EXHAUSTED", "message": "quota exhausted"}, "quota_or_billing"),
        (429, {"status": "RESOURCE_EXHAUSTED", "message": "billing quota"}, "quota_or_billing"),
        (503, {"status": "UNAVAILABLE", "message": "private raw message"}, "unavailable"),
    ],
)
def test_safe_google_error_classification(
    status: int, error: dict[str, str], code: str
) -> None:
    raw_message = error["message"]
    with pytest.raises(GenerationProviderError) as caught:
        provider(
            lambda _request: httpx.Response(status, json={"error": error})
        ).generate_image(request("secret prompt"))
    assert caught.value.code == code
    assert caught.value.status_code == status
    assert caught.value.safe_reason_code == error["status"]
    assert raw_message not in str(caught.value)
    assert "secret prompt" not in str(caught.value)


def test_key_and_prompt_absent_from_smoke_output(capsys: pytest.CaptureFixture[str]) -> None:
    secret = "key-must-not-print"
    private_prompt = smoke.SMOKE_PROMPT

    class FailedProvider:
        def preflight_model(self, model: str) -> GeminiModelAccess:
            return GeminiModelAccess(model, True, True)

        def build_request_parameters(self, _request: GenerationRequest) -> dict[str, object]:
            return {
                "contents": [{"parts": [{"text": private_prompt}]}],
                "generationConfig": {"responseModalities": ["IMAGE"]},
            }

        def generate_image(self, _request: GenerationRequest) -> GeneratedImage:
            raise GenerationProviderError(
                "invalid_request", status_code=400, safe_reason_code="INVALID_ARGUMENT"
            )

    outcome = smoke.execute_live(
        config_loader=lambda: config(secret=secret),
        provider_factory=lambda **_kwargs: FailedProvider(),  # type: ignore[arg-type]
    )
    smoke._print_outcome(outcome)
    output = capsys.readouterr().out
    assert secret not in output
    assert private_prompt not in output
    assert "INVALID_ARGUMENT" in output


def checkpoint(tmp_path: Path, *, code: str, retry: bool) -> multimodal.MultimodalCheckpoint:
    store = multimodal.CheckpointStore(tmp_path / "checkpoint.json", tmp_path / "private")
    signer = multimodal.Ed25519Signer.generate()
    multimodal._initialize_checkpoint(
        store,
        media_type="image",
        provider="gemini",
        model="gemini-3.1-flash-image",
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
    value = checkpoint(tmp_path, code="invalid_request", retry=True)
    assert multimodal._checkpoint_retry_allowed(value)


def test_only_one_definitive_retry_is_permitted(tmp_path: Path) -> None:
    value = checkpoint(tmp_path, code="invalid_request", retry=True).model_copy(
        update={"prior_rejected_calls": 2}
    )
    assert not multimodal._checkpoint_retry_allowed(value)


@pytest.mark.parametrize("code", ["timeout", "unavailable", "rate_limit"])
def test_ambiguous_checkpoint_may_not_retry(tmp_path: Path, code: str) -> None:
    value = checkpoint(tmp_path, code=code, retry=False)
    assert not multimodal._checkpoint_retry_allowed(value)


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
