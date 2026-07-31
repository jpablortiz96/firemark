"""Bounded Gemini REST adapter for native PNG generation."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.provider import GenerationProviderError, ProviderFailureCode

HTTPClientFactory = Callable[[], httpx.Client]
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PREFLIGHT_RESPONSE_LIMIT = 128 * 1024


@dataclass(frozen=True)
class GeminiModelAccess:
    """Safe model-access result without raw provider fields."""

    model: str
    available: bool
    supports_generate_content: bool | None


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
    def _safe_error_details(response: httpx.Response) -> tuple[str | None, str]:
        reason: str | None = None
        message = ""
        try:
            payload = response.json()
            error = payload.get("error") if isinstance(payload, dict) else None
            if isinstance(error, dict):
                raw_reason = error.get("status")
                if (
                    isinstance(raw_reason, str)
                    and raw_reason.replace("_", "").isalnum()
                    and len(raw_reason) <= 64
                ):
                    reason = raw_reason.upper()
                raw_message = error.get("message")
                if isinstance(raw_message, str):
                    message = raw_message.lower()
        except (ValueError, TypeError):
            pass
        return reason, message

    @classmethod
    def _failure_code(cls, response: httpx.Response) -> ProviderFailureCode:
        status = response.status_code
        reason, message = cls._safe_error_details(response)
        if status == 401:
            return "authentication"
        if status == 403:
            if reason == "RESOURCE_EXHAUSTED" or any(
                token in message for token in ("quota", "billing")
            ):
                return "quota_or_billing"
            return "permission_denied"
        if status == 429:
            if reason == "RESOURCE_EXHAUSTED" and any(
                token in message for token in ("quota", "billing")
            ):
                return "quota_or_billing"
            return "rate_limit"
        if status == 402:
            return "quota_or_billing"
        if status == 404:
            return "model_or_size_unsupported"
        if status in {400, 422}:
            if any(token in message for token in ("safety", "blocked", "prohibited")):
                return "safety_rejection"
            if "model" in message:
                return "model_or_size_unsupported"
            return "invalid_request"
        if status in {408, 504}:
            return "timeout"
        return "unavailable"

    @classmethod
    def _provider_error(cls, response: httpx.Response) -> GenerationProviderError:
        reason, _ = cls._safe_error_details(response)
        return GenerationProviderError(
            cls._failure_code(response),
            status_code=response.status_code,
            safe_reason_code=reason or f"HTTP_{response.status_code}",
        )

    @staticmethod
    def build_request_parameters(request: GenerationRequest) -> dict[str, Any]:
        return {
            "contents": [{"parts": [{"text": request.prompt}]}],
            "generationConfig": {"responseModalities": ["IMAGE"]},
        }

    @staticmethod
    def _buffer_response(response: httpx.Response, *, max_bytes: int) -> httpx.Response:
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > max_bytes:
                    raise GenerationProviderError("response_too_large")
            except ValueError:
                raise GenerationProviderError("malformed_response") from None
        payload = bytearray()
        for chunk in response.iter_bytes():
            payload.extend(chunk)
            if len(payload) > max_bytes:
                raise GenerationProviderError("response_too_large")
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=bytes(payload),
            request=response.request,
        )

    def preflight_model(self, model: str) -> GeminiModelAccess:
        """Read model metadata without performing generation."""
        try:
            with self._client() as client:
                with client.stream(
                    "GET",
                    f"/v1beta/models/{model}",
                    headers={"x-goog-api-key": self._api_key},
                ) as raw_response:
                    response = self._buffer_response(
                        raw_response, max_bytes=_PREFLIGHT_RESPONSE_LIMIT
                    )
        except GenerationProviderError:
            raise
        except httpx.TimeoutException:
            raise GenerationProviderError("timeout") from None
        except httpx.HTTPError:
            raise GenerationProviderError("unavailable") from None
        if 300 <= response.status_code < 400:
            raise GenerationProviderError(
                "malformed_response", status_code=response.status_code
            )
        if not response.is_success:
            raise self._provider_error(response)
        try:
            payload = response.json()
            if not isinstance(payload, dict):
                raise TypeError
            returned_name = payload.get("name")
            if returned_name not in {model, f"models/{model}"}:
                raise ValueError
            methods = payload.get("supportedGenerationMethods")
            if methods is not None and (
                not isinstance(methods, list)
                or not all(isinstance(item, str) for item in methods)
            ):
                raise TypeError
            supports = "generateContent" in methods if isinstance(methods, list) else None
        except (TypeError, ValueError):
            raise GenerationProviderError("malformed_response") from None
        return GeminiModelAccess(
            model=model,
            available=True,
            supports_generate_content=supports,
        )

    def _request(self, request: GenerationRequest) -> httpx.Response:
        try:
            with self._client() as client:
                with client.stream(
                    "POST",
                    f"/v1/models/{request.model}:generateContent",
                    headers={
                        "Content-Type": "application/json",
                        "x-goog-api-key": self._api_key,
                    },
                    json=self.build_request_parameters(request),
                ) as raw_response:
                    response = self._buffer_response(
                        raw_response,
                        max_bytes=self._max_image_bytes * 2 + _PREFLIGHT_RESPONSE_LIMIT,
                    )
        except GenerationProviderError:
            raise
        except httpx.TimeoutException:
            raise GenerationProviderError("timeout") from None
        except httpx.HTTPError:
            raise GenerationProviderError("unavailable") from None
        if 300 <= response.status_code < 400:
            raise GenerationProviderError(
                "malformed_response", status_code=response.status_code
            )
        if not response.is_success:
            raise self._provider_error(response)
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
            if not isinstance(candidates, list) or not candidates:
                raise GenerationProviderError("malformed_response")
            images: list[dict[str, Any]] = []
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    raise GenerationProviderError("malformed_response")
                content = candidate.get("content")
                parts = content.get("parts") if isinstance(content, dict) else None
                if not isinstance(parts, list):
                    raise GenerationProviderError("malformed_response")
                images.extend(
                    image
                    for part in parts
                    if isinstance(part, dict)
                    and isinstance(
                        image := part.get("inlineData", part.get("inline_data")), dict
                    )
                )
            if len(images) != 1:
                raise GenerationProviderError("malformed_response")
            image = images[0]
            mime_type = image.get("mimeType", image.get("mime_type"))
            encoded = image.get("data")
            if mime_type != "image/png":
                raise GenerationProviderError("non_png_response")
            if not isinstance(encoded, str) or not encoded:
                raise GenerationProviderError("malformed_response")
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
