"""Bounded Google Gemini adapter for the official Interactions API.

FIREMARK calls the Google Gemini API directly with a Google AI Studio key. The
generation contract is the documented Interactions API:

    POST https://generativelanguage.googleapis.com/v1beta/interactions
    x-goog-api-key: <GEMINI_API_KEY>
    {"model": "<model>", "input": [{"type": "text", "text": "<prompt>"}]}

The generated image is returned as ``output_image`` (or an ``image`` content
block inside ``steps``) carrying base64 ``data`` and ``mime_type``. FIREMARK
never contacts GMI Cloud, never sends an ``Authorization`` bearer header, and
never logs or persists a raw provider response.
"""

from __future__ import annotations

import base64
import binascii
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.provider import GenerationProviderError, ProviderFailureCode
from api.firemark.generation.provider_identity import (
    GOOGLE_GEMINI_PROVIDER,
    provider_model_display_name,
)

HTTPClientFactory = Callable[[], httpx.Client]

GEMINI_API_BASE_URL = "https://generativelanguage.googleapis.com"
GEMINI_API_VERSION = "v1beta"
GEMINI_INTERACTIONS_PATH = f"/{GEMINI_API_VERSION}/interactions"
GEMINI_MODELS_PATH = f"/{GEMINI_API_VERSION}/models"
GEMINI_OUTPUT_MIME_TYPE = "image/png"

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_METHOD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
_METADATA_RESPONSE_LIMIT = 512 * 1024
_MODEL_RESOURCE_PREFIX = "models/"
_COMPLETED_STATUS = "completed"
_BUDGET_STATUS = "budget_exceeded"


@dataclass(frozen=True)
class GeminiModelAccess:
    """Safe read-only model metadata result without raw provider fields."""

    model: str
    available: bool
    supported_methods: tuple[str, ...] | None = None
    listed: bool | None = None


class GeminiImageProvider:
    """Generate exactly one PNG through Google's documented Interactions API."""

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
            base_url=GEMINI_API_BASE_URL,
            follow_redirects=False,
            timeout=float(self._timeout_seconds),
        )

    def _headers(self, *, json_body: bool) -> dict[str, str]:
        """Authenticate a Google AI Studio key only through ``x-goog-api-key``."""
        headers = {"x-goog-api-key": self._api_key}
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

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
    def _transport_error(exc: Exception) -> GenerationProviderError:
        """Classify a transport failure without exposing its message."""
        if isinstance(exc, httpx.TimeoutException):
            return GenerationProviderError("timeout", safe_reason_code="TRANSPORT_TIMEOUT")
        if isinstance(exc, httpx.ProxyError):
            return GenerationProviderError(
                "unavailable", safe_reason_code="TRANSPORT_PROXY_FAILURE"
            )
        if isinstance(exc, httpx.ConnectError):
            resolution_failed = isinstance(exc.__cause__, socket.gaierror)
            return GenerationProviderError(
                "unavailable",
                safe_reason_code=(
                    "DNS_RESOLUTION_FAILURE" if resolution_failed else "TRANSPORT_CONNECT_FAILURE"
                ),
            )
        return GenerationProviderError("unavailable", safe_reason_code="TRANSPORT_FAILURE")

    @staticmethod
    def build_request_parameters(request: GenerationRequest) -> dict[str, Any]:
        """Build the documented minimal Interactions request for one PNG."""
        if request.model.startswith(_MODEL_RESOURCE_PREFIX):
            raise GenerationProviderError(
                "invalid_request", safe_reason_code="DUPLICATE_MODEL_PREFIX"
            )
        return {
            "model": request.model,
            "input": [{"type": "text", "text": request.prompt}],
            "response_format": {"type": "image", "mime_type": GEMINI_OUTPUT_MIME_TYPE},
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

    def _read_only_get(self, path: str) -> httpx.Response:
        try:
            with self._client() as client:
                with client.stream("GET", path, headers=self._headers(json_body=False)) as raw:
                    response = self._buffer_response(raw, max_bytes=_METADATA_RESPONSE_LIMIT)
        except GenerationProviderError:
            raise
        except httpx.HTTPError as exc:
            raise self._transport_error(exc) from None
        if 300 <= response.status_code < 400:
            raise GenerationProviderError(
                "malformed_response", status_code=response.status_code
            )
        if not response.is_success:
            raise self._provider_error(response)
        return response

    def list_models(self) -> tuple[str, ...]:
        """Return safe model identifiers from the read-only model listing."""
        response = self._read_only_get(f"{GEMINI_MODELS_PATH}?pageSize=200")
        try:
            payload = response.json()
            if not isinstance(payload, dict):
                raise TypeError
            entries = payload.get("models")
            if not isinstance(entries, list):
                raise TypeError
        except (TypeError, ValueError):
            raise GenerationProviderError("malformed_response") from None
        names: list[str] = []
        for entry in entries:
            name = entry.get("name") if isinstance(entry, dict) else None
            if not isinstance(name, str):
                continue
            candidate = name.removeprefix(_MODEL_RESOURCE_PREFIX)
            if _SAFE_REQUEST_ID.fullmatch(candidate) and candidate not in names:
                names.append(candidate)
        return tuple(names)

    def preflight_model(self, model: str) -> GeminiModelAccess:
        """Read model metadata without generating.

        This is a diagnostic-only capability. A model-listing endpoint can behave
        differently from the Interactions generation endpoint, so its result must
        never gate a production generation request.
        """
        response = self._read_only_get(f"{GEMINI_MODELS_PATH}/{model}")
        try:
            payload = response.json()
            if not isinstance(payload, dict):
                raise TypeError
            returned_name = payload.get("name")
            if returned_name not in {model, f"{_MODEL_RESOURCE_PREFIX}{model}"}:
                raise ValueError
            methods = payload.get("supportedGenerationMethods")
            if methods is None:
                supported: tuple[str, ...] | None = None
            elif isinstance(methods, list) and all(isinstance(item, str) for item in methods):
                supported = tuple(
                    method for method in methods if _SAFE_METHOD_NAME.fullmatch(method)
                )
            else:
                raise TypeError
        except (TypeError, ValueError):
            raise GenerationProviderError("malformed_response") from None
        return GeminiModelAccess(model=model, available=True, supported_methods=supported)

    def _request(self, request: GenerationRequest) -> httpx.Response:
        payload = self.build_request_parameters(request)
        try:
            with self._client() as client:
                with client.stream(
                    "POST",
                    GEMINI_INTERACTIONS_PATH,
                    headers=self._headers(json_body=True),
                    json=payload,
                ) as raw_response:
                    response = self._buffer_response(
                        raw_response,
                        max_bytes=self._max_image_bytes * 2 + _METADATA_RESPONSE_LIMIT,
                    )
        except GenerationProviderError:
            raise
        except httpx.HTTPError as exc:
            raise self._transport_error(exc) from None
        if 300 <= response.status_code < 400:
            raise GenerationProviderError(
                "malformed_response", status_code=response.status_code
            )
        if not response.is_success:
            raise self._provider_error(response)
        return response

    @staticmethod
    def _interaction_images(payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Return the documented image content blocks without inventing a schema."""
        output_image = payload.get("output_image")
        if isinstance(output_image, dict):
            return [output_image]
        steps = payload.get("steps")
        if steps is None:
            return []
        if not isinstance(steps, list):
            raise GenerationProviderError("malformed_response")
        images: list[dict[str, Any]] = []
        for step in steps:
            if not isinstance(step, dict):
                raise GenerationProviderError("malformed_response")
            content = step.get("content")
            if content is None:
                continue
            if not isinstance(content, list):
                raise GenerationProviderError("malformed_response")
            images.extend(
                block
                for block in content
                if isinstance(block, dict) and block.get("type") == "image"
            )
        return images

    @classmethod
    def _reject_incomplete_status(cls, payload: dict[str, Any]) -> None:
        status = payload.get("status")
        if status is None or status == _COMPLETED_STATUS:
            return
        if status == _BUDGET_STATUS:
            raise GenerationProviderError(
                "quota_or_billing", safe_reason_code="BUDGET_EXCEEDED"
            )
        raise GenerationProviderError(
            "malformed_response", safe_reason_code="INTERACTION_NOT_COMPLETED"
        )

    def validate_response(
        self, response: httpx.Response, request: GenerationRequest
    ) -> GeneratedImage:
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > self._max_image_bytes * 2:
                    raise GenerationProviderError("response_too_large")
            except ValueError:
                raise GenerationProviderError("malformed_response") from None
        try:
            payload = response.json()
            if not isinstance(payload, dict):
                raise GenerationProviderError("malformed_response")
            self._reject_incomplete_status(payload)
            images = self._interaction_images(payload)
            if len(images) != 1:
                raise GenerationProviderError("malformed_response")
            image = images[0]
            mime_type = image.get("mime_type", image.get("mimeType"))
            encoded = image.get("data")
            if mime_type != GEMINI_OUTPUT_MIME_TYPE:
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
        safe_request_id = (
            request_id if request_id and _SAFE_REQUEST_ID.fullmatch(request_id) else None
        )
        metadata: dict[str, Any] = {
            "output_format": "png",
            "requested_size": request.size,
            "provider_api": "interactions",
            "provider_api_version": GEMINI_API_VERSION,
        }
        display_name = provider_model_display_name(GOOGLE_GEMINI_PROVIDER, request.model)
        if display_name is not None:
            metadata["provider_model_name"] = display_name
        return GeneratedImage(
            data=data,
            provider=GOOGLE_GEMINI_PROVIDER,
            model=request.model,
            provider_request_id=safe_request_id,
            provider_created_at=self._now(),
            safe_generation_metadata=metadata,
            seed=request.seed,
            ai_generated=True,
        )

    def generate_image(self, request: GenerationRequest) -> GeneratedImage:
        return self.validate_response(self._request(request), request)
