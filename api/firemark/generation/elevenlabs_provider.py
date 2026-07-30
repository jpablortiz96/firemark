"""Bounded ElevenLabs REST adapter for MP3 text-to-speech generation."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime

import httpx

from api.firemark.generation.models import AudioGenerationRequest, GeneratedAudio
from api.firemark.generation.provider import GenerationProviderError, ProviderFailureCode

HTTPClientFactory = Callable[[], httpx.Client]
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
OUTPUT_FORMAT = "mp3_44100_128"


class ElevenLabsAudioProvider:
    """Generate exactly one bounded MP3 using the documented TTS REST endpoint."""

    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: int,
        max_audio_bytes: int,
        client_factory: HTTPClientFactory | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._max_audio_bytes = max_audio_bytes
        self._client_factory = client_factory
        self._now = now or (lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        return "ElevenLabsAudioProvider(api_key=<redacted>)"

    def _client(self) -> httpx.Client:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.Client(
            base_url="https://api.elevenlabs.io",
            follow_redirects=False,
            timeout=float(self._timeout_seconds),
        )

    @staticmethod
    def _failure_code(status: int) -> ProviderFailureCode:
        if status == 401:
            return "authentication"
        if status == 403:
            return "permission_denied"
        if status == 429:
            return "rate_limit"
        if status == 402:
            return "quota_or_billing"
        if status in {400, 404, 422}:
            return "invalid_request"
        if status in {408, 504}:
            return "timeout"
        return "unavailable"

    def generate_audio(self, request: AudioGenerationRequest) -> GeneratedAudio:
        response_headers: httpx.Headers
        data = bytearray()
        try:
            with self._client() as client:
                with client.stream(
                    "POST",
                    f"/v1/text-to-speech/{request.voice_id}",
                    params={"output_format": OUTPUT_FORMAT},
                    headers={
                        "Accept": "audio/mpeg",
                        "Content-Type": "application/json",
                        "xi-api-key": self._api_key,
                    },
                    json={"text": request.text, "model_id": request.model},
                ) as response:
                    if 300 <= response.status_code < 400:
                        raise GenerationProviderError("malformed_response")
                    if not response.is_success:
                        raise GenerationProviderError(self._failure_code(response.status_code))
                    if not response.headers.get("content-type", "").lower().startswith("audio/mpeg"):
                        raise GenerationProviderError("malformed_response")
                    declared = response.headers.get("content-length")
                    if declared is not None and int(declared) > self._max_audio_bytes:
                        raise GenerationProviderError("response_too_large")
                    for chunk in response.iter_bytes():
                        data.extend(chunk)
                        if len(data) > self._max_audio_bytes:
                            raise GenerationProviderError("response_too_large")
                    response_headers = response.headers
        except GenerationProviderError:
            raise
        except httpx.TimeoutException:
            raise GenerationProviderError("timeout") from None
        except (httpx.HTTPError, ValueError):
            raise GenerationProviderError("unavailable") from None
        request_id = response_headers.get("request-id") or response_headers.get("x-request-id")
        safe_request_id = request_id if request_id and _SAFE_REQUEST_ID.fullmatch(request_id) else None
        try:
            return GeneratedAudio(
                data=bytes(data),
                provider="elevenlabs",
                model=request.model,
                voice_id=request.voice_id,
                provider_request_id=safe_request_id,
                provider_created_at=self._now(),
                safe_generation_metadata={"output_format": OUTPUT_FORMAT},
                ai_generated=True,
            )
        except ValueError:
            raise GenerationProviderError("malformed_response") from None
