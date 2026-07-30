"""Official OpenAI SDK adapter for bounded PNG generation."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    OpenAI,
    RateLimitError,
)

from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.provider import GenerationProviderError, ProviderFailureCode

ClientFactory = Callable[[], Any]
HTTPClientFactory = Callable[[], httpx.Client]
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ALLOWED_IMAGE_HOST_SUFFIXES = (".openai.com", ".blob.core.windows.net")


def _default_http_client() -> httpx.Client:
    return httpx.Client(follow_redirects=False, timeout=30.0)


class OpenAIImageProvider:
    """Generate one PNG through a lazily constructed official OpenAI client."""

    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: int,
        max_image_bytes: int,
        client_factory: ClientFactory | None = None,
        http_client_factory: HTTPClientFactory = _default_http_client,
    ) -> None:
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._max_image_bytes = max_image_bytes
        self._client_factory = client_factory
        self._http_client_factory = http_client_factory

    def __repr__(self) -> str:
        return "OpenAIImageProvider(api_key=<redacted>)"

    def _client(self) -> Any:
        if self._client_factory is not None:
            return self._client_factory()
        return OpenAI(api_key=self._api_key, timeout=float(self._timeout_seconds))

    @staticmethod
    def _failure_code(exc: Exception) -> ProviderFailureCode:
        if isinstance(exc, AuthenticationError):
            return "authentication"
        if isinstance(exc, RateLimitError):
            return "rate_limit"
        if isinstance(exc, APITimeoutError):
            return "timeout"
        if isinstance(exc, BadRequestError):
            code = str(getattr(exc, "code", "") or "").lower()
            return "safety_rejection" if "safety" in code or "content_policy" in code else "invalid_request"
        if isinstance(exc, (APIConnectionError, APIStatusError)):
            return "unavailable"
        return "malformed_response"

    @staticmethod
    def _validate_download_url(value: str) -> None:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise GenerationProviderError("malformed_response")
        if parsed.username or parsed.password or parsed.fragment:
            raise GenerationProviderError("malformed_response")
        if parsed.port not in (None, 443):
            raise GenerationProviderError("malformed_response")
        hostname = parsed.hostname.lower().rstrip(".")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise GenerationProviderError("malformed_response")
        if not any(hostname.endswith(suffix) for suffix in _ALLOWED_IMAGE_HOST_SUFFIXES):
            raise GenerationProviderError("malformed_response")

    def _download(self, value: str) -> bytes:
        self._validate_download_url(value)
        try:
            with self._http_client_factory() as client:
                with client.stream("GET", value) as response:
                    if 300 <= response.status_code < 400:
                        raise GenerationProviderError("malformed_response")
                    response.raise_for_status()
                    declared = response.headers.get("content-length")
                    if declared is not None and int(declared) > self._max_image_bytes:
                        raise GenerationProviderError("malformed_response")
                    payload = bytearray()
                    for chunk in response.iter_bytes():
                        payload.extend(chunk)
                        if len(payload) > self._max_image_bytes:
                            raise GenerationProviderError("malformed_response")
                    return bytes(payload)
        except GenerationProviderError:
            raise
        except (httpx.HTTPError, ValueError):
            raise GenerationProviderError("unavailable") from None

    def _payload(self, item: Any) -> bytes:
        encoded = getattr(item, "b64_json", None)
        if isinstance(encoded, str) and encoded:
            try:
                payload = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise GenerationProviderError("malformed_response") from exc
        else:
            url = getattr(item, "url", None)
            if not isinstance(url, str) or not url:
                raise GenerationProviderError("malformed_response")
            payload = self._download(url)
        if len(payload) > self._max_image_bytes:
            raise GenerationProviderError("malformed_response")
        return payload

    def generate_image(self, request: GenerationRequest) -> GeneratedImage:
        parameters: dict[str, Any] = {
            "prompt": request.prompt,
            "model": request.model,
            "size": request.size,
            "n": 1,
            "timeout": float(self._timeout_seconds),
        }
        if request.model.startswith("dall-e-"):
            parameters["response_format"] = "b64_json"
        else:
            parameters["output_format"] = "png"
        try:
            response = self._client().images.generate(**parameters)
        except Exception as exc:
            if isinstance(exc, GenerationProviderError):
                raise
            raise GenerationProviderError(self._failure_code(exc)) from None
        data = getattr(response, "data", None)
        if not isinstance(data, list) or len(data) != 1:
            raise GenerationProviderError("malformed_response")
        created = getattr(response, "created", None)
        if not isinstance(created, int) or isinstance(created, bool) or created < 0:
            raise GenerationProviderError("malformed_response")
        request_id = getattr(response, "_request_id", None)
        safe_request_id = (
            request_id
            if isinstance(request_id, str) and _SAFE_REQUEST_ID.fullmatch(request_id)
            else None
        )
        try:
            return GeneratedImage(
                data=self._payload(data[0]),
                provider="openai",
                model=request.model,
                provider_request_id=safe_request_id,
                provider_created_at=datetime.fromtimestamp(created, tz=UTC),
                safe_generation_metadata={
                    "output_format": "png",
                    "requested_size": request.size,
                },
                seed=request.seed,
                ai_generated=True,
            )
        except (OSError, OverflowError, ValueError):
            raise GenerationProviderError("malformed_response") from None
