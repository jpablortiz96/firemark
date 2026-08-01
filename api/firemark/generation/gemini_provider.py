"""Bounded Google Gemini adapter for the official Interactions API.

FIREMARK calls the Google Gemini API directly with a Google AI Studio key. The
generation contract is the shape the official ``gemini-3.1-flash-image``
image-generation REST examples use:

    POST https://generativelanguage.googleapis.com/v1beta/interactions
    x-goog-api-key: <GEMINI_API_KEY>
    {"model": "<model>",
     "input": [{"type": "text", "text": "<prompt>"}],
     "response_format": {"type": "image", "mime_type": "image/jpeg",
                         "aspect_ratio": "1:1", "image_size": "1K"}}

The generic Interactions OpenAPI schema advertises more ``ResponseFormat``
capabilities than any single model implements. ``delivery`` in particular is
part of the generic schema but is not present in the documented image-generation
examples, and sending it was rejected with HTTP 400 INVALID_REQUEST. FIREMARK
therefore sends only the fields the model's own examples use and reads the image
inline.

The image arrives as Base64 in ``output_image.data`` or in an ``image`` content
block inside ``steps``. FIREMARK never contacts GMI Cloud, never sends an
``Authorization`` bearer header, never sends the API key anywhere except
``generativelanguage.googleapis.com``, and never logs or persists a raw provider
response, a provider error message, or a request body.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

import httpx

from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.normalization import (
    ImageNormalizationError,
    inspect_image_source,
)
from api.firemark.generation.provider import GenerationProviderError, ProviderFailureCode
from api.firemark.generation.provider_identity import (
    GOOGLE_GEMINI_PROVIDER,
    provider_model_display_name,
)

HTTPClientFactory = Callable[[], httpx.Client]
StageCallback = Callable[[str], None]

GEMINI_API_HOST = "generativelanguage.googleapis.com"
GEMINI_API_BASE_URL = f"https://{GEMINI_API_HOST}"
GEMINI_API_VERSION = "v1beta"
GEMINI_INTERACTIONS_PATH = f"/{GEMINI_API_VERSION}/interactions"
GEMINI_MODELS_PATH = f"/{GEMINI_API_VERSION}/models"
#: The documented image-generation examples request JPEG. ``image/png`` is not a
#: valid ``ImageResponseFormat`` MIME value and is rejected with HTTP 400.
GEMINI_REQUEST_MIME_TYPE: Final = "image/jpeg"
GEMINI_SOURCE_MIME_TYPE: Final = "image/jpeg"
GEMINI_SOURCE_EXTENSION: Final = "jpg"
GEMINI_SEALED_MIME_TYPE: Final = "image/png"
GEMINI_IMAGE_ASPECT_RATIO: Final = "1:1"
GEMINI_IMAGE_SIZE: Final = "1K"

#: Fields the generic Interactions schema exposes that the image model's own
#: documented examples do not use. Sending them produced HTTP 400, so the
#: request builder asserts their absence.
FORBIDDEN_REQUEST_FIELDS: Final = frozenset(
    {
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
        "n",
        "quality",
        "size",
    }
)

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_METHOD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
_SAFE_ERROR_STATUS = re.compile(r"^[A-Z0-9_]{1,64}$")
_SAFE_FIELD_PATH = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,160}$")
_MAX_INVALID_FIELDS = 16
_BAD_REQUEST_TYPE = "google.rpc.BadRequest"
_METADATA_RESPONSE_LIMIT = 512 * 1024
_MODEL_RESOURCE_PREFIX = "models/"
_COMPLETED_STATUS = "completed"
_BUDGET_STATUS = "budget_exceeded"

#: Normalization failures mapped to safe provider failure codes. The reason code
#: preserves the exact structural cause without echoing any image bytes.
_NORMALIZATION_FAILURES: dict[str, ProviderFailureCode] = {
    "unsupported_source_mime": "unsupported_media_type",
    "non_jpeg_source": "unsupported_media_type",
    "malformed_image": "malformed_response",
    "image_dimensions_exceeded": "response_too_large",
    "image_pixels_exceeded": "response_too_large",
    "image_decoding_failure": "malformed_response",
    "png_normalization_failure": "malformed_response",
    "non_png_normalized_output": "non_png_response",
}

#: httpx failure classes mapped to a stable safe reason code. Order matters:
#: the most specific class must be tested first.
_TRANSPORT_REASONS: tuple[tuple[type[Exception], ProviderFailureCode, str], ...] = (
    (httpx.ConnectTimeout, "timeout", "TRANSPORT_CONNECT_TIMEOUT"),
    (httpx.ReadTimeout, "timeout", "TRANSPORT_READ_TIMEOUT"),
    (httpx.WriteTimeout, "timeout", "TRANSPORT_WRITE_TIMEOUT"),
    (httpx.PoolTimeout, "timeout", "TRANSPORT_POOL_TIMEOUT"),
    (httpx.TimeoutException, "timeout", "TRANSPORT_TIMEOUT"),
    (httpx.ProxyError, "unavailable", "TRANSPORT_PROXY_FAILURE"),
    (httpx.ReadError, "unavailable", "TRANSPORT_READ_FAILURE"),
    (httpx.WriteError, "unavailable", "TRANSPORT_WRITE_FAILURE"),
    (httpx.CloseError, "unavailable", "TRANSPORT_CLOSE_FAILURE"),
    (httpx.RemoteProtocolError, "unavailable", "TRANSPORT_REMOTE_PROTOCOL_FAILURE"),
    (httpx.LocalProtocolError, "unavailable", "TRANSPORT_LOCAL_PROTOCOL_FAILURE"),
    (httpx.DecodingError, "unavailable", "TRANSPORT_DECODING_FAILURE"),
    (httpx.UnsupportedProtocol, "unavailable", "TRANSPORT_UNSUPPORTED_PROTOCOL"),
)


def _normalization_error(exc: ImageNormalizationError) -> GenerationProviderError:
    """Translate a normalization failure into a safe provider failure."""
    return GenerationProviderError(
        _NORMALIZATION_FAILURES.get(exc.code, "malformed_response"),
        safe_reason_code=exc.code.upper(),
    )


@dataclass(frozen=True)
class GeminiModelAccess:
    """Safe read-only model metadata result without raw provider fields."""

    model: str
    available: bool
    supported_methods: tuple[str, ...] | None = None
    listed: bool | None = None


@dataclass(frozen=True)
class _InlineImage:
    """One inline image content block extracted from an interaction response."""

    data: str | None = None
    mime_type: str | None = None


@dataclass(frozen=True)
class _DecodedImage:
    data: bytes
    mime_type: str
    sha256: str


class GeminiImageProvider:
    """Generate exactly one inline JPEG through Google's Interactions API."""

    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: int,
        max_image_bytes: int,
        client_factory: HTTPClientFactory | None = None,
        now: Callable[[], datetime] | None = None,
        stage_callback: StageCallback | None = None,
    ) -> None:
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._max_image_bytes = max_image_bytes
        self._client_factory = client_factory
        self._now = now or (lambda: datetime.now(UTC))
        self._stage = stage_callback or (lambda _stage: None)

    def __repr__(self) -> str:
        return "GeminiImageProvider(api_key=<redacted>)"

    def _timeout(self) -> httpx.Timeout:
        """Bound connect, read, write and pool acquisition independently.

        The read timeout covers one image generation; the handshake phases are
        capped much lower so a stalled connection fails fast.
        """
        seconds = float(self._timeout_seconds)
        handshake = min(30.0, seconds)
        return httpx.Timeout(seconds, connect=handshake, write=handshake, pool=handshake)

    def _client(self) -> httpx.Client:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.Client(
            base_url=GEMINI_API_BASE_URL,
            follow_redirects=False,
            timeout=self._timeout(),
            http1=True,
            http2=False,
        )

    def _headers(self, *, json_body: bool) -> dict[str, str]:
        """Authenticate a Google AI Studio key only through ``x-goog-api-key``.

        ``Accept-Encoding: identity`` keeps the streamed byte bound meaningful:
        a compressed body would otherwise expand past the limit after decoding.
        """
        headers = {
            "x-goog-api-key": self._api_key,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    # ------------------------------------------------------------------
    # Safe failure classification
    # ------------------------------------------------------------------

    @classmethod
    def _invalid_fields(cls, error: dict[str, Any]) -> tuple[str, ...]:
        """Extract only allowlisted ``google.rpc.BadRequest`` field paths.

        Field violation descriptions and every other detail payload are dropped.
        A field name is never invented when Google does not supply one.
        """
        details = error.get("details")
        if not isinstance(details, list):
            return ()
        fields: list[str] = []
        for detail in details:
            if not isinstance(detail, dict):
                continue
            detail_type = detail.get("@type")
            if not isinstance(detail_type, str) or _BAD_REQUEST_TYPE not in detail_type:
                continue
            violations = detail.get("fieldViolations", detail.get("field_violations"))
            if not isinstance(violations, list):
                continue
            for violation in violations:
                if not isinstance(violation, dict):
                    continue
                field = violation.get("field")
                if (
                    isinstance(field, str)
                    and _SAFE_FIELD_PATH.fullmatch(field)
                    and field not in fields
                ):
                    fields.append(field)
                if len(fields) >= _MAX_INVALID_FIELDS:
                    return tuple(fields)
        return tuple(fields)

    @classmethod
    def _safe_error_details(
        cls, response: httpx.Response
    ) -> tuple[str | None, str, tuple[str, ...]]:
        """Return the safe status token, a lowercased message used only for
        local classification, and allowlisted invalid field paths.

        The message is never returned to a caller, persisted or printed; it is
        consumed here to choose a normalized failure code and then discarded.
        """
        reason: str | None = None
        message = ""
        fields: tuple[str, ...] = ()
        try:
            payload = response.json()
            error = payload.get("error") if isinstance(payload, dict) else None
            if isinstance(error, dict):
                raw_reason = error.get("status")
                if isinstance(raw_reason, str) and _SAFE_ERROR_STATUS.fullmatch(
                    raw_reason.upper()
                ):
                    reason = raw_reason.upper()
                raw_message = error.get("message")
                if isinstance(raw_message, str):
                    message = raw_message.lower()
                fields = cls._invalid_fields(error)
        except (ValueError, TypeError):
            pass
        return reason, message, fields

    @classmethod
    def _failure_code(cls, response: httpx.Response) -> ProviderFailureCode:
        status = response.status_code
        reason, message, _ = cls._safe_error_details(response)
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
        reason, _, fields = cls._safe_error_details(response)
        return GenerationProviderError(
            cls._failure_code(response),
            status_code=response.status_code,
            safe_reason_code=reason or f"HTTP_{response.status_code}",
            safe_invalid_fields=fields,
        )

    @staticmethod
    def _transport_error(exc: Exception) -> GenerationProviderError:
        """Classify a transport failure without exposing its message.

        Only the exception class name is retained, and only when it appears in
        the shared safe allowlist.
        """
        token = type(exc).__name__
        if isinstance(exc, httpx.ConnectError):
            resolution_failed = isinstance(exc.__cause__, socket.gaierror)
            return GenerationProviderError(
                "unavailable",
                safe_reason_code=(
                    "DNS_RESOLUTION_FAILURE" if resolution_failed else "TRANSPORT_CONNECT_FAILURE"
                ),
                safe_exception_token=token,
            )
        for failure_type, code, reason in _TRANSPORT_REASONS:
            if isinstance(exc, failure_type):
                return GenerationProviderError(
                    code, safe_reason_code=reason, safe_exception_token=token
                )
        return GenerationProviderError(
            "unavailable", safe_reason_code="TRANSPORT_FAILURE", safe_exception_token=token
        )

    # ------------------------------------------------------------------
    # Request construction
    # ------------------------------------------------------------------

    @staticmethod
    def build_request_parameters(request: GenerationRequest) -> dict[str, Any]:
        """Build the minimal documented Interactions request for one inline JPEG."""
        if request.model.startswith(_MODEL_RESOURCE_PREFIX):
            raise GenerationProviderError(
                "invalid_request", safe_reason_code="DUPLICATE_MODEL_PREFIX"
            )
        return {
            "model": request.model,
            "input": [{"type": "text", "text": request.prompt}],
            "response_format": {
                "type": "image",
                "mime_type": GEMINI_REQUEST_MIME_TYPE,
                "aspect_ratio": GEMINI_IMAGE_ASPECT_RATIO,
                "image_size": GEMINI_IMAGE_SIZE,
            },
        }

    # ------------------------------------------------------------------
    # Bounded transport
    # ------------------------------------------------------------------

    @staticmethod
    def _buffer_response(response: httpx.Response, *, max_bytes: int) -> httpx.Response:
        """Read a streamed body while enforcing a hard byte ceiling."""
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

    def _max_response_bytes(self) -> int:
        """Bound the inline JSON body around the Base64-expanded image."""
        return self._max_image_bytes * 2 + _METADATA_RESPONSE_LIMIT

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

    # ------------------------------------------------------------------
    # Read-only diagnostics
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Interaction submission
    # ------------------------------------------------------------------

    def _submit_interaction(self, request: GenerationRequest) -> httpx.Response:
        """Submit one unary interaction and read its bounded streamed body."""
        payload = self.build_request_parameters(request)
        self._stage("interaction_submission")
        try:
            with self._client() as client:
                with client.stream(
                    "POST",
                    GEMINI_INTERACTIONS_PATH,
                    headers=self._headers(json_body=True),
                    json=payload,
                ) as raw_response:
                    response = self._buffer_response(
                        raw_response, max_bytes=self._max_response_bytes()
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

    @staticmethod
    def _image_block(block: dict[str, Any]) -> _InlineImage:
        data = block.get("data")
        mime_type = block.get("mime_type", block.get("mimeType"))
        return _InlineImage(
            data=data if isinstance(data, str) else None,
            mime_type=mime_type if isinstance(mime_type, str) else None,
        )

    @classmethod
    def _interaction_images(cls, payload: dict[str, Any]) -> list[_InlineImage]:
        """Return the documented inline image blocks without inventing a schema."""
        output_image = payload.get("output_image")
        if isinstance(output_image, dict):
            return [cls._image_block(output_image)]
        steps = payload.get("steps")
        if steps is None:
            return []
        if not isinstance(steps, list):
            raise GenerationProviderError("malformed_response")
        images: list[_InlineImage] = []
        for step in steps:
            if not isinstance(step, dict):
                raise GenerationProviderError("malformed_response")
            content = step.get("content")
            if content is None:
                continue
            if not isinstance(content, list):
                raise GenerationProviderError("malformed_response")
            images.extend(
                cls._image_block(block)
                for block in content
                if isinstance(block, dict) and block.get("type") == "image"
            )
        return images

    def _inline_image(self, response: httpx.Response) -> _InlineImage:
        self._stage("inline_metadata_validation")
        try:
            payload = response.json()
        except (ValueError, TypeError):
            raise GenerationProviderError(
                "malformed_response", safe_reason_code="INTERACTION_BODY_NOT_JSON"
            ) from None
        if not isinstance(payload, dict):
            raise GenerationProviderError("malformed_response")
        self._reject_incomplete_status(payload)
        images = self._interaction_images(payload)
        if len(images) != 1:
            raise GenerationProviderError("malformed_response")
        image = images[0]
        if image.data is None:
            raise GenerationProviderError(
                "malformed_response", safe_reason_code="INLINE_IMAGE_MISSING"
            )
        return image

    def _decode_inline_image(self, image: _InlineImage) -> _DecodedImage:
        """Decode bounded Base64 into the exact provider source bytes."""
        self._stage("inline_jpeg_base64_validation")
        if image.mime_type != GEMINI_SOURCE_MIME_TYPE:
            raise GenerationProviderError(
                "unsupported_media_type", safe_reason_code="PROVIDER_SOURCE_MIME_UNSUPPORTED"
            )
        if not image.data:
            raise GenerationProviderError(
                "malformed_response", safe_reason_code="INLINE_IMAGE_EMPTY"
            )
        try:
            data = base64.b64decode(image.data, validate=True)
        except (ValueError, TypeError, binascii.Error):
            raise GenerationProviderError(
                "malformed_response", safe_reason_code="INLINE_IMAGE_BASE64_INVALID"
            ) from None
        if len(data) > self._max_image_bytes:
            raise GenerationProviderError("response_too_large")
        return _DecodedImage(
            data=data,
            mime_type=GEMINI_SOURCE_MIME_TYPE,
            sha256=hashlib.sha256(data).hexdigest(),
        )

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    def validate_response(
        self, response: httpx.Response, request: GenerationRequest
    ) -> GeneratedImage:
        """Turn one interaction response into validated JPEG source bytes."""
        decoded = self._decode_inline_image(self._inline_image(response))
        self._stage("jpeg_validation")
        try:
            facts = inspect_image_source(decoded.data, mime_type=GEMINI_SOURCE_MIME_TYPE)
        except ImageNormalizationError as exc:
            raise _normalization_error(exc) from None
        request_id = response.headers.get("x-request-id")
        safe_request_id = (
            request_id if request_id and _SAFE_REQUEST_ID.fullmatch(request_id) else None
        )
        metadata: dict[str, Any] = {
            "requested_size": request.size,
            "provider_api": "interactions",
            "provider_api_version": GEMINI_API_VERSION,
            "delivery": "inline",
            "aspect_ratio": GEMINI_IMAGE_ASPECT_RATIO,
            "image_size": GEMINI_IMAGE_SIZE,
            "provider_source_mime_type": GEMINI_SOURCE_MIME_TYPE,
            "source_sha256": decoded.sha256,
            "source_byte_size": facts.byte_size,
            "source_width": facts.width,
            "source_height": facts.height,
            "sealed_mime_type": GEMINI_SEALED_MIME_TYPE,
        }
        display_name = provider_model_display_name(GOOGLE_GEMINI_PROVIDER, request.model)
        if display_name is not None:
            metadata["provider_model_name"] = display_name
        return GeneratedImage(
            data=decoded.data,
            source_mime_type=GEMINI_SOURCE_MIME_TYPE,
            source_extension=GEMINI_SOURCE_EXTENSION,
            width=facts.width,
            height=facts.height,
            provider=GOOGLE_GEMINI_PROVIDER,
            model=request.model,
            provider_request_id=safe_request_id,
            provider_created_at=self._now(),
            safe_generation_metadata=metadata,
            seed=request.seed,
            ai_generated=True,
        )

    def generate_image(self, request: GenerationRequest) -> GeneratedImage:
        return self.validate_response(self._submit_interaction(request), request)
