"""Bounded Gemini REST adapter for native PNG generation."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx

from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.provider import GenerationProviderError, ProviderFailureCode

HTTPClientFactory = Callable[[], httpx.Client]
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SIZE_ASPECT_RATIO = {
    "256x256": "1:1",
    "512x512": "1:1",
    "1024x1024": "1:1",
    "1536x1024": "3:2",
    "1024x1536": "2:3",
    "1792x1024": "16:9",
    "1024x1792": "9:16",
}


class GeminiImageProvider:
    """Generate exactly one PNG through Google's documented generateContent endpoint."""

    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: int,
        max_image_bytes: int,
        client_factory: HTTPClientFactory | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._max_image_bytes = max_image_bytes
        self._client_factory = client_factory
        self._now = now or (lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        return "GeminiImageProvider(api_key=<redacted>)"

    def _client(self) -> httpx.Client:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.Client(
            base_url="https://generativelanguage.googleapis.com",
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
            return "model_or_size_unsupported" if status == 404 else "invalid_request"
        if status in {408, 504}:
            return "timeout"
        return "unavailable"

    @staticmethod
    def build_request_parameters(request: GenerationRequest) -> dict[str, Any]:
        generation_config: dict[str, Any] = {"responseModalities": ["IMAGE"]}
        aspect_ratio = _SIZE_ASPECT_RATIO.get(request.size)
        if aspect_ratio is not None:
            generation_config["responseFormat"] = {
                "image": {"aspectRatio": aspect_ratio, "imageSize": "1K"}
            }
        return {
            "contents": [{"parts": [{"text": request.prompt}]}],
            "generationConfig": generation_config,
        }

    def _request(self, request: GenerationRequest) -> httpx.Response:
        try:
            with self._client() as client:
                response = client.post(
                    f"/v1/models/{request.model}:generateContent",
                    headers={"x-goog-api-key": self._api_key},
                    json=self.build_request_parameters(request),
                )
        except httpx.TimeoutException:
            raise GenerationProviderError("timeout") from None
        except httpx.HTTPError:
            raise GenerationProviderError("unavailable") from None
        if 300 <= response.status_code < 400:
            raise GenerationProviderError("malformed_response")
        if not response.is_success:
            raise GenerationProviderError(self._failure_code(response.status_code))
        return response

    def validate_response(self, response: httpx.Response, request: GenerationRequest) -> GeneratedImage:
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > self._max_image_bytes * 2:
                    raise GenerationProviderError("response_too_large")
            except ValueError:
                raise GenerationProviderError("malformed_response") from None
        try:
            payload = response.json()
            candidates = payload.get("candidates")
            if not isinstance(candidates, list) or len(candidates) != 1:
                raise GenerationProviderError("malformed_response")
            candidate = candidates[0]
            if not isinstance(candidate, dict):
                raise GenerationProviderError("malformed_response")
            content = candidate.get("content")
            parts = content.get("parts") if isinstance(content, dict) else None
            if not isinstance(parts, list):
                raise GenerationProviderError("malformed_response")
            images = [
                part.get("inlineData", part.get("inline_data"))
                for part in parts
                if isinstance(part, dict)
                and isinstance(part.get("inlineData", part.get("inline_data")), dict)
            ]
            if len(images) != 1:
                raise GenerationProviderError("malformed_response")
            image = images[0]
            if not isinstance(image, dict):
                raise GenerationProviderError("malformed_response")
            mime_type = image.get("mimeType", image.get("mime_type"))
            encoded = image.get("data")
            if mime_type != "image/png" or not isinstance(encoded, str):
                raise GenerationProviderError("non_png_response")
            data = base64.b64decode(encoded, validate=True)
        except GenerationProviderError:
            raise
        except (ValueError, TypeError, binascii.Error):
            raise GenerationProviderError("malformed_response") from None
        if len(data) > self._max_image_bytes:
            raise GenerationProviderError("response_too_large")
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise GenerationProviderError("non_png_response")
        request_id = response.headers.get("x-request-id")
        safe_request_id = request_id if request_id and _SAFE_REQUEST_ID.fullmatch(request_id) else None
        return GeneratedImage(
            data=data,
            provider="gemini",
            model=request.model,
            provider_request_id=safe_request_id,
            provider_created_at=self._now(),
            safe_generation_metadata={"output_format": "png", "requested_size": request.size},
            seed=request.seed,
            ai_generated=True,
        )

    def generate_image(self, request: GenerationRequest) -> GeneratedImage:
        return self.validate_response(self._request(request), request)
