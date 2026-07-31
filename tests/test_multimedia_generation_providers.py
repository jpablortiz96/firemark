"""Zero-network contract tests for Gemini image and ElevenLabs audio boundaries."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import ValidationError

from api.firemark.generation.elevenlabs_provider import ElevenLabsAudioProvider
from api.firemark.generation.fake_provider import _TINY_MP3, _TINY_PNG
from api.firemark.generation.gemini_provider import GeminiImageProvider
from api.firemark.generation.models import (
    AudioGenerationRequest,
    GeneratedAudio,
    GeneratedImage,
    GenerationRequest,
)
from api.firemark.generation.provider import GenerationProviderError

NOW = datetime(2026, 7, 30, 20, tzinfo=UTC)


def _client(handler: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=handler, base_url="https://provider.test")


def _gemini_request() -> GenerationRequest:
    return GenerationRequest(
        prompt="safe",
        model="gemini-image",
        size="auto",
        request_id="firemark-run-gemini",
    )


def _gemini_body(data: str | None = None, mime_type: str = "image/png") -> dict[str, object]:
    return {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "inlineData": {
                                "mimeType": mime_type,
                                "data": data or base64.b64encode(_TINY_PNG).decode(),
                            }
                        }
                    ]
                }
            }
        ]
    }


def test_gemini_generates_one_bounded_png_without_leaking_key() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/gemini-3.1-flash-image:generateContent")
        assert request.headers["x-goog-api-key"] == "gemini-secret"
        assert b"private image prompt" in request.content
        return httpx.Response(
            200,
            headers={"x-request-id": "gemini-request-1"},
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "inlineData": {
                                        "mimeType": "image/png",
                                        "data": base64.b64encode(_TINY_PNG).decode(),
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
        )

    provider = GeminiImageProvider(
        api_key="gemini-secret",
        timeout_seconds=30,
        max_image_bytes=1024,
        client_factory=lambda: _client(httpx.MockTransport(respond)),
        now=lambda: NOW,
    )
    image = provider.generate_image(
        GenerationRequest(
            prompt="private image prompt",
            model="gemini-3.1-flash-image",
            size="1024x1024",
            request_id="firemark-run-gemini",
        )
    )
    assert image.data == _TINY_PNG
    assert image.provider == "gemini" and image.ai_generated
    assert "gemini-secret" not in repr(provider)


@pytest.mark.parametrize(
    ("status", "code"),
    [(401, "authentication"), (402, "quota_or_billing"), (403, "permission_denied"), (404, "model_or_size_unsupported"), (408, "timeout"), (429, "rate_limit"), (503, "unavailable")],
)
def test_gemini_normalizes_http_failures(status: int, code: str) -> None:
    provider = GeminiImageProvider(
        api_key="secret",
        timeout_seconds=30,
        max_image_bytes=1024,
        client_factory=lambda: _client(
            httpx.MockTransport(lambda _request: httpx.Response(status))
        ),
    )
    with pytest.raises(GenerationProviderError) as caught:
        provider.generate_image(_gemini_request())
    assert caught.value.code == code


def test_gemini_default_client_and_transport_failures_are_safe() -> None:
    default = GeminiImageProvider(api_key="secret", timeout_seconds=5, max_image_bytes=1024)
    client = default._client()
    assert str(client.base_url) == "https://generativelanguage.googleapis.com"
    client.close()
    for failure, expected in (
        (httpx.ReadTimeout("timeout"), "timeout"),
        (httpx.ConnectError("offline"), "unavailable"),
    ):
        provider = GeminiImageProvider(
            api_key="secret",
            timeout_seconds=5,
            max_image_bytes=1024,
            client_factory=lambda failure=failure: _client(
                httpx.MockTransport(lambda _request: (_ for _ in ()).throw(failure))
            ),
        )
        with pytest.raises(GenerationProviderError) as caught:
            provider.generate_image(_gemini_request())
        assert caught.value.code == expected


@pytest.mark.parametrize(
    ("response", "code"),
    [
        (httpx.Response(302), "malformed_response"),
        (httpx.Response(200, headers={"content-length": "9999"}, json=_gemini_body()), "response_too_large"),
        (httpx.Response(200, headers={"content-length": "bad"}, json=_gemini_body()), "malformed_response"),
        (httpx.Response(200, json={}), "malformed_response"),
        (httpx.Response(200, json={"candidates": [None]}), "malformed_response"),
        (httpx.Response(200, json={"candidates": [{"content": {}}]}), "malformed_response"),
        (httpx.Response(200, json={"candidates": [{"content": {"parts": []}}]}), "malformed_response"),
        (httpx.Response(200, json=_gemini_body(mime_type="image/jpeg")), "non_png_response"),
        (httpx.Response(200, json=_gemini_body("%%%")), "malformed_response"),
        (httpx.Response(200, json=_gemini_body(base64.b64encode(b"not-png").decode())), "non_png_response"),
    ],
)
def test_gemini_rejects_malformed_or_unbounded_responses(
    response: httpx.Response, code: str
) -> None:
    provider = GeminiImageProvider(api_key="secret", timeout_seconds=5, max_image_bytes=1024)
    with pytest.raises(GenerationProviderError) as caught:
        if response.status_code == 302:
            provider = GeminiImageProvider(
                api_key="secret",
                timeout_seconds=5,
                max_image_bytes=1024,
                client_factory=lambda: _client(
                    httpx.MockTransport(lambda _request: response)
                ),
            )
            provider.generate_image(_gemini_request())
        else:
            provider.validate_response(response, _gemini_request())
    assert caught.value.code == code


def test_elevenlabs_generates_one_bounded_mp3_without_leaking_key() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/text-to-speech/voice-safe"
        assert request.url.params["output_format"] == "mp3_44100_128"
        assert request.headers["xi-api-key"] == "eleven-secret"
        assert b"private spoken text" in request.content
        return httpx.Response(
            200,
            headers={"content-type": "audio/mpeg", "request-id": "tts-request-1"},
            content=_TINY_MP3,
        )

    provider = ElevenLabsAudioProvider(
        api_key="eleven-secret",
        timeout_seconds=30,
        max_audio_bytes=1024,
        client_factory=lambda: _client(httpx.MockTransport(respond)),
        now=lambda: NOW,
    )
    audio = provider.generate_audio(
        AudioGenerationRequest(
            text="private spoken text",
            model="eleven_multilingual_v2",
            voice_id="voice-safe",
            request_id="firemark-run-audio",
        )
    )
    assert audio.data == _TINY_MP3
    assert audio.provider == "elevenlabs" and audio.media_type == "audio/mpeg"
    assert "eleven-secret" not in repr(provider)


def test_elevenlabs_rejects_wrong_type_and_oversized_audio() -> None:
    responses = iter(
        [
            httpx.Response(200, headers={"content-type": "application/json"}, content=b"{}"),
            httpx.Response(200, headers={"content-type": "audio/mpeg"}, content=_TINY_MP3),
        ]
    )
    provider = ElevenLabsAudioProvider(
        api_key="secret",
        timeout_seconds=30,
        max_audio_bytes=10,
        client_factory=lambda: _client(httpx.MockTransport(lambda _request: next(responses))),
    )
    request = AudioGenerationRequest(
        text="spoken",
        model="eleven_multilingual_v2",
        voice_id="voice-safe",
        request_id="firemark-run-audio",
    )
    with pytest.raises(GenerationProviderError) as wrong_type:
        provider.generate_audio(request)
    assert wrong_type.value.code == "malformed_response"
    with pytest.raises(GenerationProviderError) as oversized:
        provider.generate_audio(request)
    assert oversized.value.code == "response_too_large"


@pytest.mark.parametrize(
    ("status", "code"),
    [(302, "malformed_response"), (401, "authentication"), (402, "quota_or_billing"), (403, "permission_denied"), (404, "voice_not_found"), (408, "timeout"), (422, "invalid_request"), (429, "rate_limit"), (503, "unavailable")],
)
def test_elevenlabs_normalizes_http_failures(status: int, code: str) -> None:
    provider = ElevenLabsAudioProvider(
        api_key="secret",
        timeout_seconds=5,
        max_audio_bytes=1024,
        client_factory=lambda: _client(
            httpx.MockTransport(lambda _request: httpx.Response(status))
        ),
    )
    with pytest.raises(GenerationProviderError) as caught:
        provider.generate_audio(
            AudioGenerationRequest(
                text="spoken",
                model="eleven-model",
                voice_id="voice-safe",
                request_id="firemark-run-audio",
            )
        )
    assert caught.value.code == code


def test_elevenlabs_default_client_transport_and_malformed_mp3_are_safe() -> None:
    default = ElevenLabsAudioProvider(
        api_key="secret", timeout_seconds=5, max_audio_bytes=1024
    )
    client = default._client()
    assert str(client.base_url) == "https://api.elevenlabs.io"
    client.close()
    request = AudioGenerationRequest(
        text="spoken",
        model="eleven-model",
        voice_id="voice-safe",
        request_id="firemark-run-audio",
    )
    for failure, expected in (
        (httpx.ReadTimeout("timeout"), "timeout"),
        (httpx.ConnectError("offline"), "unavailable"),
    ):
        provider = ElevenLabsAudioProvider(
            api_key="secret",
            timeout_seconds=5,
            max_audio_bytes=1024,
            client_factory=lambda failure=failure: _client(
                httpx.MockTransport(lambda _request: (_ for _ in ()).throw(failure))
            ),
        )
        with pytest.raises(GenerationProviderError) as caught:
            provider.generate_audio(request)
        assert caught.value.code == expected
    malformed = ElevenLabsAudioProvider(
        api_key="secret",
        timeout_seconds=5,
        max_audio_bytes=1024,
        client_factory=lambda: _client(
            httpx.MockTransport(
                lambda _request: httpx.Response(
                    200, headers={"content-type": "audio/mpeg"}, content=b"not-an-mp3"
                )
            )
        ),
    )
    with pytest.raises(GenerationProviderError) as caught:
        malformed.generate_audio(request)
    assert caught.value.code == "non_mp3_response"


def test_audio_models_reject_unsafe_private_and_provider_metadata() -> None:
    with pytest.raises(ValidationError, match="must not be blank"):
        AudioGenerationRequest(
            text=" ", model="eleven-model", voice_id="voice-safe", request_id="run-safe"
        )
    with pytest.raises(ValidationError, match="safe characters"):
        AudioGenerationRequest(
            text="speech", model="unsafe model", voice_id="voice-safe", request_id="run-safe"
        )

    values = {
        "data": _TINY_MP3,
        "provider": "elevenlabs",
        "model": "eleven-model",
        "voice_id": "voice-safe",
        "provider_created_at": NOW,
        "ai_generated": True,
    }
    assert GeneratedAudio(**values).data == _TINY_MP3
    assert GeneratedAudio(**{**values, "data": b"\xff\xe3frame"}).data.startswith(b"\xff")
    for update, message in (
        ({"data": b"not-mp3"}, "not an MP3"),
        ({"provider": " "}, "must not be blank"),
        ({"provider_request_id": "unsafe request"}, "unsafe"),
        ({"safe_generation_metadata": {"api_key_hint": "x"}}, "private field"),
        ({"safe_generation_metadata": {"safe": [object()]}}, "JSON-safe"),
        ({"provider_created_at": datetime(2026, 7, 30)}, "timezone-aware"),
    ):
        with pytest.raises(ValidationError, match=message):
            GeneratedAudio(**{**values, **update})


def test_image_model_rejects_unsafe_metadata_and_naive_time() -> None:
    values = {
        "data": _TINY_PNG,
        "provider": "gemini",
        "model": "gemini-image",
        "provider_created_at": NOW,
        "ai_generated": True,
    }
    for update, message in (
        ({"provider": " "}, "must not be blank"),
        ({"safe_generation_metadata": {"safe": [object()]}}, "JSON-safe"),
        ({"provider_created_at": datetime(2026, 7, 30)}, "timezone-aware"),
    ):
        with pytest.raises(ValidationError, match=message):
            GeneratedImage(**{**values, **update})
