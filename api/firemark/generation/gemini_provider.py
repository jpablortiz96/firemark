"""Bounded Google Gemini adapter for the official Interactions API.

FIREMARK calls the Google Gemini API directly with a Google AI Studio key. The
generation contract is the documented Interactions API:

    POST https://generativelanguage.googleapis.com/v1beta/interactions
    x-goog-api-key: <GEMINI_API_KEY>
    {"model": "<model>",
     "input": [{"type": "text", "text": "<prompt>"}],
     "response_format": {"type": "image", "mime_type": "image/png",
                         "aspect_ratio": "1:1", "image_size": "1K",
                         "delivery": "uri"},
     "stream": false, "background": false, "store": false}

`delivery: "uri"` keeps the synchronous interaction response small. A large
inline Base64 image forces a multi-megabyte body through the same connection
that carries the interaction metadata, and a failure while receiving it cannot
be distinguished from an unfinished generation. Requesting a URI moves the bytes
into a separate, independently bounded download that can fail without making the
interaction outcome ambiguous.

The provider URI is transient private provider data. It is never printed,
logged, persisted, checkpointed, reported, returned in public certificate data,
or attached to an exception. FIREMARK never contacts GMI Cloud, never sends an
``Authorization`` bearer header, and never logs or persists a raw provider
response.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from api.firemark.generation.models import GeneratedImage, GenerationRequest
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
GEMINI_OUTPUT_MIME_TYPE = "image/png"
GEMINI_IMAGE_ASPECT_RATIO = "1:1"
GEMINI_IMAGE_SIZE = "1K"
GEMINI_IMAGE_DELIVERY = "uri"

#: Google-hosted origins that may serve a generated image. The Gemini API host
#: serves Files API downloads; signed media is served from Google storage and
#: user-content origins.
GOOGLE_MEDIA_HOSTS = frozenset({GEMINI_API_HOST, "storage.googleapis.com"})
GOOGLE_MEDIA_HOST_SUFFIXES = (".googleapis.com", ".googleusercontent.com")
#: The API key is presented only to the Gemini API host itself. A signed Google
#: storage or user-content URL already carries its own authorization.
API_KEY_HOSTS = frozenset({GEMINI_API_HOST})
MAX_IMAGE_URI_LENGTH = 2048
MAX_IMAGE_URI_REDIRECTS = 1
#: Binary image types Google documents for generated image delivery. Only PNG is
#: accepted as a FIREMARK source; the others are reported as NON_PNG_RESPONSE.
DOCUMENTED_IMAGE_MIME_TYPES = frozenset({"image/png", "image/jpeg", "image/webp"})

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_METHOD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
_METADATA_RESPONSE_LIMIT = 512 * 1024
_MODEL_RESOURCE_PREFIX = "models/"
_COMPLETED_STATUS = "completed"
_BUDGET_STATUS = "budget_exceeded"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

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


@dataclass(frozen=True)
class GeminiModelAccess:
    """Safe read-only model metadata result without raw provider fields."""

    model: str
    available: bool
    supported_methods: tuple[str, ...] | None = None
    listed: bool | None = None


@dataclass(frozen=True)
class _ImageReference:
    """One final image reference extracted from an interaction response.

    ``uri`` is transient private provider data and never leaves the in-memory
    download operation.
    """

    uri: str | None = None
    data: str | None = None
    mime_type: str | None = None


@dataclass(frozen=True)
class _DownloadedImage:
    data: bytes
    mime_type: str
    sha256: str


class GeminiImageProvider:
    """Generate exactly one PNG through Google's documented Interactions API."""

    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: int,
        max_image_bytes: int,
        client_factory: HTTPClientFactory | None = None,
        download_client_factory: HTTPClientFactory | None = None,
        now: Callable[[], datetime] | None = None,
        stage_callback: StageCallback | None = None,
    ) -> None:
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._max_image_bytes = max_image_bytes
        self._client_factory = client_factory
        self._download_client_factory = download_client_factory
        self._now = now or (lambda: datetime.now(UTC))
        self._stage = stage_callback or (lambda _stage: None)

    def __repr__(self) -> str:
        return "GeminiImageProvider(api_key=<redacted>)"

    def _timeout(self) -> httpx.Timeout:
        """Bound connect, read, write and pool acquisition independently."""
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
        )

    def _download_client(self) -> httpx.Client:
        """Build an independent client for the bounded image download."""
        if self._download_client_factory is not None:
            return self._download_client_factory()
        return httpx.Client(follow_redirects=False, timeout=self._timeout())

    def _headers(self, *, json_body: bool) -> dict[str, str]:
        """Authenticate a Google AI Studio key only through ``x-goog-api-key``."""
        headers = {"x-goog-api-key": self._api_key, "Accept": "application/json"}
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    # ------------------------------------------------------------------
    # Safe failure classification
    # ------------------------------------------------------------------

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
        """Build the documented Interactions request for one PNG delivered by URI."""
        if request.model.startswith(_MODEL_RESOURCE_PREFIX):
            raise GenerationProviderError(
                "invalid_request", safe_reason_code="DUPLICATE_MODEL_PREFIX"
            )
        return {
            "model": request.model,
            "input": [{"type": "text", "text": request.prompt}],
            "response_format": {
                "type": "image",
                "mime_type": GEMINI_OUTPUT_MIME_TYPE,
                "aspect_ratio": GEMINI_IMAGE_ASPECT_RATIO,
                "image_size": GEMINI_IMAGE_SIZE,
                "delivery": GEMINI_IMAGE_DELIVERY,
            },
            "stream": False,
            "background": False,
            "store": False,
        }

    # ------------------------------------------------------------------
    # Read-only diagnostics
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Interaction submission
    # ------------------------------------------------------------------

    def _submit_interaction(self, request: GenerationRequest) -> httpx.Response:
        """Submit one unary interaction and read its small metadata response.

        The response is read without transport streaming because `delivery: uri`
        keeps it small. The buffered body is still bounded afterwards so a
        provider that ignores the requested delivery mode fails closed instead of
        being accepted.
        """
        payload = self.build_request_parameters(request)
        self._stage("interaction_submission")
        try:
            with self._client() as client:
                response = client.post(
                    GEMINI_INTERACTIONS_PATH,
                    headers=self._headers(json_body=True),
                    json=payload,
                )
                body = response.content
        except httpx.HTTPError as exc:
            raise self._transport_error(exc) from None
        if 300 <= response.status_code < 400:
            raise GenerationProviderError(
                "malformed_response", status_code=response.status_code
            )
        if not response.is_success:
            raise self._provider_error(response)
        if len(body) > self._max_image_bytes * 2 + _METADATA_RESPONSE_LIMIT:
            raise GenerationProviderError(
                "response_too_large", safe_reason_code="INTERACTION_BODY_TOO_LARGE"
            )
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
    def _image_block(block: dict[str, Any]) -> _ImageReference:
        uri = block.get("uri")
        data = block.get("data")
        mime_type = block.get("mime_type", block.get("mimeType"))
        return _ImageReference(
            uri=uri if isinstance(uri, str) else None,
            data=data if isinstance(data, str) else None,
            mime_type=mime_type if isinstance(mime_type, str) else None,
        )

    @classmethod
    def _interaction_images(cls, payload: dict[str, Any]) -> list[_ImageReference]:
        """Return the documented final image references without inventing a schema."""
        output_image = payload.get("output_image")
        if isinstance(output_image, dict):
            return [cls._image_block(output_image)]
        steps = payload.get("steps")
        if steps is None:
            return []
        if not isinstance(steps, list):
            raise GenerationProviderError("malformed_response")
        images: list[_ImageReference] = []
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

    def _image_reference(self, response: httpx.Response) -> _ImageReference:
        self._stage("interaction_metadata_validation")
        try:
            payload = response.json()
        except (ValueError, TypeError):
            raise GenerationProviderError("malformed_response") from None
        if not isinstance(payload, dict):
            raise GenerationProviderError("malformed_response")
        self._reject_incomplete_status(payload)
        images = self._interaction_images(payload)
        if len(images) != 1:
            raise GenerationProviderError("malformed_response")
        reference = images[0]
        if reference.uri is None and reference.data is None:
            raise GenerationProviderError(
                "malformed_response", safe_reason_code="IMAGE_REFERENCE_MISSING"
            )
        return reference

    # ------------------------------------------------------------------
    # Transient URI validation and bounded download
    # ------------------------------------------------------------------

    @staticmethod
    def _reject_uri(reason: str) -> GenerationProviderError:
        """Build a URI failure that never contains the URI itself."""
        return GenerationProviderError("malformed_response", safe_reason_code=reason)

    @classmethod
    def _validated_image_uri(cls, uri: str) -> tuple[str, bool]:
        """Validate a transient provider URI and decide whether the key may be sent.

        Returns the accepted URI and whether the Gemini API key may accompany the
        download. The URI is never logged, persisted or placed in an exception.
        """
        if not isinstance(uri, str) or not uri:
            raise cls._reject_uri("IMAGE_URI_MISSING")
        if len(uri) > MAX_IMAGE_URI_LENGTH:
            raise cls._reject_uri("IMAGE_URI_TOO_LONG")
        try:
            parsed = urlsplit(uri)
            hostname = parsed.hostname
            parsed.port  # noqa: B018 - raises ValueError for an invalid port
        except ValueError:
            raise cls._reject_uri("IMAGE_URI_MALFORMED") from None
        if parsed.scheme.lower() != "https":
            raise cls._reject_uri("IMAGE_URI_SCHEME_REJECTED")
        if parsed.username or parsed.password:
            raise cls._reject_uri("IMAGE_URI_CREDENTIALS_REJECTED")
        if parsed.fragment:
            raise cls._reject_uri("IMAGE_URI_FRAGMENT_REJECTED")
        if not hostname:
            raise cls._reject_uri("IMAGE_URI_HOST_MISSING")
        host = hostname.lower()
        if host == "localhost" or host.endswith(".localhost"):
            raise cls._reject_uri("IMAGE_URI_PRIVATE_HOST_REJECTED")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            raise cls._reject_uri("IMAGE_URI_PRIVATE_HOST_REJECTED")
        allowed = host in GOOGLE_MEDIA_HOSTS or host.endswith(GOOGLE_MEDIA_HOST_SUFFIXES)
        if not allowed:
            raise cls._reject_uri("IMAGE_URI_HOST_REJECTED")
        return uri, host in API_KEY_HOSTS

    def _download_image(self, uri: str, *, send_api_key: bool) -> _DownloadedImage:
        """Download the generated image through an independent bounded client."""
        self._stage("image_download")
        target = uri
        authorized = send_api_key
        redirects_remaining = MAX_IMAGE_URI_REDIRECTS
        try:
            with self._download_client() as client:
                while True:
                    headers = {"Accept": ", ".join(sorted(DOCUMENTED_IMAGE_MIME_TYPES))}
                    if authorized:
                        headers["x-goog-api-key"] = self._api_key
                    with client.stream("GET", target, headers=headers) as response:
                        if 300 <= response.status_code < 400:
                            location = response.headers.get("location")
                            if redirects_remaining <= 0 or not isinstance(location, str):
                                raise self._reject_uri("IMAGE_URI_REDIRECT_REJECTED")
                            redirects_remaining -= 1
                            target, authorized = self._validated_image_uri(location)
                            continue
                        if not response.is_success:
                            raise self._provider_error(response)
                        return self._read_image_body(response)
        except GenerationProviderError:
            raise
        except httpx.HTTPError as exc:
            raise self._transport_error(exc) from None
        finally:
            target = ""

    def _read_image_body(self, response: httpx.Response) -> _DownloadedImage:
        content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if content_type not in DOCUMENTED_IMAGE_MIME_TYPES:
            raise GenerationProviderError(
                "malformed_response", safe_reason_code="IMAGE_CONTENT_TYPE_REJECTED"
            )
        if content_type != GEMINI_OUTPUT_MIME_TYPE:
            # Reject before reading the body; FIREMARK adds no lossy conversion.
            raise GenerationProviderError("non_png_response")
        declared_header = response.headers.get("content-length")
        declared: int | None = None
        if declared_header is not None:
            try:
                declared = int(declared_header)
            except ValueError:
                raise GenerationProviderError(
                    "malformed_response", safe_reason_code="IMAGE_CONTENT_LENGTH_INVALID"
                ) from None
            if declared > self._max_image_bytes:
                raise GenerationProviderError("response_too_large")
        digest = hashlib.sha256()
        payload = bytearray()
        for chunk in response.iter_bytes():
            payload.extend(chunk)
            if len(payload) > self._max_image_bytes:
                raise GenerationProviderError("response_too_large")
            digest.update(chunk)
        if declared is not None and len(payload) != declared:
            raise GenerationProviderError(
                "malformed_response", safe_reason_code="IMAGE_DOWNLOAD_TRUNCATED"
            )
        return _DownloadedImage(
            data=bytes(payload), mime_type=content_type, sha256=digest.hexdigest()
        )

    def _decode_inline_image(self, reference: _ImageReference) -> _DownloadedImage:
        """Defensive path for a provider that ignores the requested URI delivery."""
        if reference.mime_type not in DOCUMENTED_IMAGE_MIME_TYPES:
            raise GenerationProviderError(
                "malformed_response", safe_reason_code="IMAGE_CONTENT_TYPE_REJECTED"
            )
        if not reference.data:
            raise GenerationProviderError("malformed_response")
        try:
            data = base64.b64decode(reference.data, validate=True)
        except (ValueError, TypeError, binascii.Error):
            raise GenerationProviderError("malformed_response") from None
        if len(data) > self._max_image_bytes:
            raise GenerationProviderError("response_too_large")
        if reference.mime_type != GEMINI_OUTPUT_MIME_TYPE:
            raise GenerationProviderError("non_png_response")
        return _DownloadedImage(
            data=data,
            mime_type=reference.mime_type,
            sha256=hashlib.sha256(data).hexdigest(),
        )

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    def validate_response(
        self, response: httpx.Response, request: GenerationRequest
    ) -> GeneratedImage:
        """Turn one interaction metadata response into validated PNG bytes."""
        reference = self._image_reference(response)
        if reference.uri is not None:
            self._stage("image_uri_validation")
            uri, send_api_key = self._validated_image_uri(reference.uri)
            downloaded = self._download_image(uri, send_api_key=send_api_key)
            delivery = GEMINI_IMAGE_DELIVERY
        else:
            downloaded = self._decode_inline_image(reference)
            delivery = "inline"
        if not downloaded.data.startswith(_PNG_MAGIC):
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
            "delivery": delivery,
            "aspect_ratio": GEMINI_IMAGE_ASPECT_RATIO,
            "image_size": GEMINI_IMAGE_SIZE,
            "source_sha256": downloaded.sha256,
        }
        display_name = provider_model_display_name(GOOGLE_GEMINI_PROVIDER, request.model)
        if display_name is not None:
            metadata["provider_model_name"] = display_name
        return GeneratedImage(
            data=downloaded.data,
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
