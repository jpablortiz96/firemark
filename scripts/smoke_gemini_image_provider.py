"""Explicit opt-in, isolated Google Gemini image-provider checkpoint.

The checkpoint submits at most one Interactions generation request. A read-only
model preflight is deliberately NOT part of this path; use
``scripts/diagnose_gemini_access.py`` for read-only model diagnostics so a
model-listing endpoint can never block a valid generation.

Generation sends only the minimal request shape the model's own documented
image-generation examples use and reads the JPEG inline. The exact source JPEG
is preserved and normalized deterministically into the sealed PNG carrier.

A prior submission that cannot continue blocks execution and is never retried in
place. An operator may instead archive it and deliberately start a brand-new
billable operation with ``--start-new-operation-after-definitive`` (a provider
refusal) or ``--start-new-operation-after-ambiguous`` (an uncaptured outcome).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal
from uuid import uuid4

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.firemark.generate_and_seal import SEALED_IMAGE_MIME_TYPE
from api.firemark.generation.gemini_provider import (
    FORBIDDEN_REQUEST_FIELDS,
    GEMINI_IMAGE_ASPECT_RATIO,
    GEMINI_IMAGE_SIZE,
    GEMINI_INTERACTIONS_PATH,
    GEMINI_REQUEST_MIME_TYPE,
    GEMINI_SOURCE_EXTENSION,
    GEMINI_SOURCE_MIME_TYPE,
    GeminiImageProvider,
)
from api.firemark.generation.models import PNG_MAGIC, GeneratedImage, GenerationRequest
from api.firemark.generation.normalization import ImageNormalizationError, normalize_to_png
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.generation.provider_identity import (
    GOOGLE_GEMINI_PROVIDER,
    provider_model_display_name,
)
from api.firemark.settings import GeminiImageConfig, Settings

INFORMATIONAL_EXIT_CODE = 2
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
DEFAULT_CHECKPOINT = Path(".artifacts/gemini-image-provider-checkpoint.json")
DEFAULT_CHECKPOINT_ARCHIVE = Path(".artifacts/gemini-image-provider-checkpoints")
DEFAULT_PRIVATE_ROOT = Path(".artifacts/gemini-image-provider-private")
ARCHIVE_PREFIX = "gemini-image-provider-ambiguous-"
SMOKE_REQUEST_ID = "firemark-gemini-provider-smoke"
SMOKE_PROMPT = (
    "A premium forensic fire-shaped authenticity seal on a dark neutral background, "
    "clean geometric design, no text."
)
STAGES = (
    "configuration_validation",
    "request_construction",
    "prior_checkpoint_classification",
    "definitive_checkpoint_archival",
    "checkpoint_before_submission",
    "interaction_submission",
    "inline_metadata_validation",
    "inline_jpeg_base64_validation",
    "jpeg_validation",
    "source_hash",
    "deterministic_png_normalization",
    "normalized_png_validation",
    "checkpoint_completion",
)
#: Stages the provider reports through its stage callback.
PROVIDER_STAGES = frozenset(
    {
        "interaction_submission",
        "inline_metadata_validation",
        "inline_jpeg_base64_validation",
        "jpeg_validation",
    }
)
DEFINITIVE_ARCHIVAL_STAGE = "definitive_checkpoint_archival"
AMBIGUOUS_ARCHIVAL_STAGE = "ambiguous_checkpoint_archival"
DEFINITIVE_ARCHIVE_PREFIX = "gemini-image-provider-definitive-"

SafeCategory = Literal[
    "OK",
    "CONFIGURATION_ERROR",
    "AUTHENTICATION_FAILURE",
    "PERMISSION_DENIED",
    "QUOTA_OR_BILLING_FAILURE",
    "RATE_LIMIT",
    "INVALID_REQUEST",
    "MODEL_UNSUPPORTED",
    "SAFETY_REJECTION",
    "TIMEOUT",
    "PROVIDER_UNAVAILABLE",
    "MALFORMED_RESPONSE",
    "NON_PNG_RESPONSE",
    "RESPONSE_TOO_LARGE",
    "UNSUPPORTED_SOURCE_MIME",
    "NON_JPEG_SOURCE",
    "MALFORMED_IMAGE",
    "IMAGE_DIMENSIONS_EXCEEDED",
    "IMAGE_PIXELS_EXCEEDED",
    "IMAGE_DECODING_FAILURE",
    "PNG_NORMALIZATION_FAILURE",
    "NON_PNG_NORMALIZED_OUTPUT",
    "AMBIGUOUS_PRIOR_SUBMISSION",
    "DEFINITIVE_REJECTION_NOT_AUTHORIZED",
    "NO_AMBIGUOUS_CHECKPOINT",
    "NO_DEFINITIVE_CHECKPOINT",
    "SAFE_UNEXPECTED_FAILURE",
]

#: Normalization failures reported with their exact structural cause.
NORMALIZATION_CATEGORIES: dict[str, SafeCategory] = {
    "unsupported_source_mime": "UNSUPPORTED_SOURCE_MIME",
    "non_jpeg_source": "NON_JPEG_SOURCE",
    "malformed_image": "MALFORMED_IMAGE",
    "image_dimensions_exceeded": "IMAGE_DIMENSIONS_EXCEEDED",
    "image_pixels_exceeded": "IMAGE_PIXELS_EXCEEDED",
    "image_decoding_failure": "IMAGE_DECODING_FAILURE",
    "png_normalization_failure": "PNG_NORMALIZATION_FAILURE",
    "non_png_normalized_output": "NON_PNG_NORMALIZED_OUTPUT",
}

PROVIDER_CATEGORIES: dict[str, SafeCategory] = {
    "authentication": "AUTHENTICATION_FAILURE",
    "permission_denied": "PERMISSION_DENIED",
    "quota_or_billing": "QUOTA_OR_BILLING_FAILURE",
    "rate_limit": "RATE_LIMIT",
    "invalid_request": "INVALID_REQUEST",
    "model_or_size_unsupported": "MODEL_UNSUPPORTED",
    "safety_rejection": "SAFETY_REJECTION",
    "timeout": "TIMEOUT",
    "unavailable": "PROVIDER_UNAVAILABLE",
    "malformed_response": "MALFORMED_RESPONSE",
    "non_png_response": "NON_PNG_RESPONSE",
    "response_too_large": "RESPONSE_TOO_LARGE",
}

#: Only a definitive provider rejection received before any generated bytes may
#: be retried, and only when the operator explicitly authorizes it.
DEFINITIVE_RETRY_CODES = frozenset(
    {
        "authentication",
        "permission_denied",
        "quota_or_billing",
        "invalid_request",
        "model_or_size_unsupported",
    }
)

OperationState = Literal[
    "request_ready",
    "provider_call_started",
    "provider_rejected",
    "generated",
    "complete",
]

PriorCheckpointClass = Literal[
    "none",
    "fresh",
    "recoverable",
    "definitive_rejection",
    "definitive_rejection_exhausted",
    "ambiguous",
    "configuration_mismatch",
]
#: Both definitive classes describe a provider that explicitly refused the
#: request without producing bytes. Only the first may still be retried as the
#: same operation; both may seed a new operator-authorized operation.
DEFINITIVE_CLASSES: Final = frozenset({"definitive_rejection", "definitive_rejection_exhausted"})

CHECKPOINT_SCHEMA_V1: Final = "firemark.gemini-image-provider-checkpoint.v1"
CHECKPOINT_SCHEMA_V2: Final = "firemark.gemini-image-provider-checkpoint.v2"


class SafeSmokeError(RuntimeError):
    """Category-only local failure."""

    def __init__(self, category: SafeCategory) -> None:
        self.category = category
        super().__init__(category)


class GeminiProviderCheckpoint(BaseModel):
    """Closed safe checkpoint; generated bytes live in a separate ignored file.

    Version 1 checkpoints remain readable so a preserved ambiguous operation can
    still be classified and archived without being rewritten.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[
        "firemark.gemini-image-provider-checkpoint.v1",
        "firemark.gemini-image-provider-checkpoint.v2",
    ] = CHECKPOINT_SCHEMA_V2
    operation_state: OperationState
    operation_id: str | None = None
    provider: Literal["google_gemini"] = GOOGLE_GEMINI_PROVIDER
    model: str
    media_type: Literal["image"] = "image"
    #: The distributable sealed carrier FIREMARK produces.
    mime_type: Literal["image/png"] = "image/png"
    #: The exact format the provider delivered. It is never relabelled.
    source_mime_type: str | None = None
    source_extension: str | None = None
    source_byte_size: int | None = Field(default=None, gt=0)
    normalized_sha256: str | None = None
    normalized_byte_count: int | None = Field(default=None, gt=0)
    request_id: str
    created_at: datetime
    new_provider_calls: int = Field(default=0, ge=0, le=1)
    prior_rejected_calls: int = Field(default=0, ge=0)
    provider_failure_code: str | None = None
    provider_failure_status: int | None = None
    provider_safe_reason_code: str | None = None
    provider_exception_token: str | None = None
    #: Structured field paths Google named as invalid. Descriptions are dropped.
    provider_invalid_fields: tuple[str, ...] = ()
    provider_retry_allowed: bool = False
    delivery_mode: str | None = None
    source_sha256: str | None = None
    generated_byte_count: int | None = Field(default=None, gt=0)
    source_path: str | None = None
    current_stage: str | None = None
    stage_results: tuple[dict[str, str], ...] = ()

    @field_validator("created_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Checkpoint timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("source_sha256", "normalized_sha256")
    @classmethod
    def validate_optional_digest(cls, value: str | None) -> str | None:
        if value is not None and (
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("Checkpoint digest is invalid")
        return value

    @property
    def evidence_id(self) -> str:
        return self.operation_id or self.request_id


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class CheckpointStore:
    """Atomic allowlisted checkpoint and private-byte persistence."""

    def __init__(self, path: Path, private_root: Path) -> None:
        self.path = path
        self.private_root = private_root
        #: A preserved checkpoint stays read-only until classification proves it
        #: belongs to the active operation. An ambiguous record is never edited.
        self.writable = False

    def exists(self) -> bool:
        return self.path.is_file()

    def read(self) -> GeminiProviderCheckpoint:
        try:
            return GeminiProviderCheckpoint.model_validate_json(self.path.read_bytes())
        except Exception:
            raise SafeSmokeError("SAFE_UNEXPECTED_FAILURE") from None

    def write(self, checkpoint: GeminiProviderCheckpoint) -> GeminiProviderCheckpoint:
        _atomic_write(
            self.path,
            json.dumps(
                checkpoint.model_dump(mode="json"), ensure_ascii=True, indent=2, sort_keys=True
            ).encode("utf-8"),
        )
        return checkpoint

    def update(self, **values: object) -> GeminiProviderCheckpoint:
        updated = GeminiProviderCheckpoint.model_validate(
            self.read().model_copy(update=values).model_dump()
        )
        return self.write(updated)

    def mark_stage(self, stage: str, completed: Sequence[dict[str, str]]) -> None:
        if self.writable and self.exists():
            self.update(current_stage=stage, stage_results=tuple(completed))

    def persist_generated(self, image: GeneratedImage) -> GeminiProviderCheckpoint:
        """Store the exact provider source bytes before anything else can fail."""
        checkpoint = self.read()
        if (
            checkpoint.new_provider_calls != 1
            or checkpoint.operation_state != "provider_call_started"
        ):
            raise SafeSmokeError("SAFE_UNEXPECTED_FAILURE")
        destination = (
            self.private_root / checkpoint.evidence_id / f"source.{image.source_extension}"
        )
        _atomic_write(destination, image.data)
        delivery = image.safe_generation_metadata.get("delivery")
        return self.update(
            operation_state="generated",
            source_mime_type=image.source_mime_type,
            source_extension=image.source_extension,
            source_sha256=hashlib.sha256(image.data).hexdigest(),
            source_byte_size=len(image.data),
            generated_byte_count=len(image.data),
            source_path=str(destination.resolve()),
            delivery_mode=delivery if isinstance(delivery, str) else None,
            provider_failure_code=None,
            provider_failure_status=None,
            provider_safe_reason_code=None,
            provider_exception_token=None,
            provider_invalid_fields=(),
            provider_retry_allowed=False,
        )

    def persist_provider_failure(self, exc: GenerationProviderError) -> None:
        """Persist only normalized code, status, reason and allowlisted token."""
        checkpoint = self.read()
        if checkpoint.operation_state != "provider_call_started":
            raise SafeSmokeError("SAFE_UNEXPECTED_FAILURE")
        self.update(
            operation_state="provider_rejected",
            prior_rejected_calls=checkpoint.prior_rejected_calls + 1,
            provider_failure_code=exc.code,
            provider_failure_status=exc.status_code,
            provider_safe_reason_code=exc.safe_reason_code,
            provider_exception_token=exc.safe_exception_token,
            provider_invalid_fields=exc.safe_invalid_fields,
            provider_retry_allowed=exc.code in DEFINITIVE_RETRY_CODES,
        )

    def recover_image(self, model: str) -> GeneratedImage:
        """Rebuild the source image from persisted bytes without calling Gemini."""
        checkpoint = self.read()
        if checkpoint.source_path is None or checkpoint.source_sha256 is None:
            raise SafeSmokeError("SAFE_UNEXPECTED_FAILURE")
        try:
            data = Path(checkpoint.source_path).read_bytes()
        except OSError:
            raise SafeSmokeError("SAFE_UNEXPECTED_FAILURE") from None
        if hashlib.sha256(data).hexdigest() != checkpoint.source_sha256:
            raise SafeSmokeError("SAFE_UNEXPECTED_FAILURE")
        return GeneratedImage(
            data=data,
            source_mime_type=checkpoint.source_mime_type or GEMINI_SOURCE_MIME_TYPE,  # type: ignore[arg-type]
            source_extension=checkpoint.source_extension or GEMINI_SOURCE_EXTENSION,  # type: ignore[arg-type]
            provider=GOOGLE_GEMINI_PROVIDER,
            model=model,
            provider_created_at=checkpoint.created_at,
            ai_generated=True,
        )


@dataclass(frozen=True)
class SmokeOutcome:
    category: SafeCategory
    stages: tuple[tuple[str, str], ...]
    config: GeminiImageConfig | None = None
    image: GeneratedImage | None = None
    operation_id: str | None = None
    source_sha256: str | None = None
    source_mime_type: str | None = None
    source_byte_size: int | None = None
    normalized_byte_count: int | None = None
    provider_code: str | None = None
    provider_status: int | None = None
    safe_reason_code: str | None = None
    exception_token: str | None = None
    invalid_fields: tuple[str, ...] = ()
    provider_calls: int = 0
    recovered: bool = False
    retry_permitted: bool = False
    prior_class: PriorCheckpointClass | None = None
    new_operation: bool = False
    archived: bool = False
    delivery_mode: str | None = None


class StageTracker:
    def __init__(self, store: CheckpointStore) -> None:
        self.store = store
        self.current = STAGES[0]
        self.rows: list[tuple[str, str]] = []

    def begin(self, stage: str) -> None:
        if stage != self.current:
            self.rows.append((self.current, "PASS"))
            self.current = stage
            self.store.mark_stage(
                stage, [{"stage": name, "status": result} for name, result in self.rows]
            )

    def success(self) -> tuple[tuple[str, str], ...]:
        self.rows.append((self.current, "PASS"))
        return tuple(self.rows)

    def failure(self) -> tuple[tuple[str, str], ...]:
        self.rows.append((self.current, "FAIL"))
        return tuple(self.rows)


def _load_gemini_config() -> GeminiImageConfig:
    names = {
        "GEMINI_API_KEY": "gemini_api_key",
        "GEMINI_IMAGE_MODEL": "gemini_image_model",
        "FIREMARK_GENERATION_TIMEOUT_SECONDS": "generation_timeout_seconds",
        "FIREMARK_MAX_GENERATED_IMAGE_BYTES": "max_generated_image_bytes",
    }
    values = {
        field: value
        for name, field in names.items()
        if (value := os.getenv(name)) not in (None, "")
    }
    return Settings.model_validate(values).require_gemini_image_config()


def _category(
    exc: Exception, stage: str
) -> tuple[SafeCategory, str | None, int | None, str | None, str | None, tuple[str, ...]]:
    if isinstance(exc, SafeSmokeError):
        return exc.category, None, None, None, None, ()
    if isinstance(exc, ImageNormalizationError):
        return (
            NORMALIZATION_CATEGORIES.get(exc.code, "SAFE_UNEXPECTED_FAILURE"),
            exc.code,
            None,
            exc.code.upper(),
            None,
            (),
        )
    if isinstance(exc, GenerationProviderError):
        return (
            PROVIDER_CATEGORIES.get(exc.code, "SAFE_UNEXPECTED_FAILURE"),
            exc.code,
            exc.status_code,
            exc.safe_reason_code,
            exc.safe_exception_token,
            exc.safe_invalid_fields,
        )
    if stage == "configuration_validation":
        return "CONFIGURATION_ERROR", None, None, None, None, ()
    return "SAFE_UNEXPECTED_FAILURE", None, None, None, None, ()


def expected_request_payload(model: str, prompt: str) -> dict[str, Any]:
    """The documented Interactions request FIREMARK must submit."""
    return {
        "model": model,
        "input": [{"type": "text", "text": prompt}],
        "response_format": {
            "type": "image",
            "mime_type": GEMINI_REQUEST_MIME_TYPE,
            "aspect_ratio": GEMINI_IMAGE_ASPECT_RATIO,
            "image_size": GEMINI_IMAGE_SIZE,
        },
    }


def _request_fields_are_supported(payload: Mapping[str, Any]) -> bool:
    """Reject any generic Interactions field the image model does not document."""
    response_format = payload.get("response_format")
    scopes: list[Mapping[str, Any]] = [payload]
    if isinstance(response_format, Mapping):
        scopes.append(response_format)
    return not any(field in scope for scope in scopes for field in FORBIDDEN_REQUEST_FIELDS)


def _retry_allowed(checkpoint: GeminiProviderCheckpoint) -> bool:
    """Permit retry only after one definitive rejection with no captured bytes."""
    return bool(
        checkpoint.operation_state == "provider_rejected"
        and checkpoint.provider_retry_allowed
        and checkpoint.provider_failure_code in DEFINITIVE_RETRY_CODES
        and checkpoint.prior_rejected_calls == 1
        and checkpoint.source_sha256 is None
        and checkpoint.source_path is None
    )


def _definitively_rejected(checkpoint: GeminiProviderCheckpoint) -> bool:
    """A provider refusal that produced no bytes, whatever its retry budget."""
    return bool(
        checkpoint.operation_state == "provider_rejected"
        and checkpoint.provider_failure_code in DEFINITIVE_RETRY_CODES
        and checkpoint.source_sha256 is None
        and checkpoint.source_path is None
    )


def classify_prior_checkpoint(
    store: CheckpointStore, config: GeminiImageConfig
) -> PriorCheckpointClass:
    """Classify an existing checkpoint without modifying it."""
    if not store.exists():
        return "none"
    checkpoint = store.read()
    if checkpoint.model != config.model:
        return "configuration_mismatch"
    if checkpoint.operation_state in {"generated", "complete"}:
        return "recoverable"
    if checkpoint.operation_state == "request_ready":
        return "fresh"
    if checkpoint.operation_state == "provider_call_started":
        # The submission outcome was never durably captured.
        return "ambiguous"
    if _retry_allowed(checkpoint):
        return "definitive_rejection"
    if _definitively_rejected(checkpoint):
        # The provider explicitly refused and produced nothing, but this
        # operation has already spent its single authorized retry.
        return "definitive_rejection_exhausted"
    return "ambiguous"


def archive_checkpoint(
    store: CheckpointStore,
    archive_directory: Path,
    *,
    prefix: str = ARCHIVE_PREFIX,
    missing_category: SafeCategory = "NO_AMBIGUOUS_CHECKPOINT",
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Path:
    """Atomically move a preserved checkpoint aside, byte for byte.

    The archived file keeps its original semantic state. It is never edited,
    marked retryable, or discarded.
    """
    if not store.exists():
        raise SafeSmokeError(missing_category)
    timestamp = now().astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    archive_directory.mkdir(parents=True, exist_ok=True)
    destination = archive_directory / f"{prefix}{timestamp}.json"
    if destination.exists():
        raise SafeSmokeError("SAFE_UNEXPECTED_FAILURE")
    os.replace(store.path, destination)
    return destination


def archive_ambiguous_checkpoint(
    store: CheckpointStore,
    archive_directory: Path,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Path:
    return archive_checkpoint(store, archive_directory, now=now)


def archive_definitive_checkpoint(
    store: CheckpointStore,
    archive_directory: Path,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Path:
    return archive_checkpoint(
        store,
        archive_directory,
        prefix=DEFINITIVE_ARCHIVE_PREFIX,
        missing_category="NO_DEFINITIVE_CHECKPOINT",
        now=now,
    )


def _new_operation_id() -> str:
    return f"firemark-gemini-op-{uuid4().hex}"


def _prepare_checkpoint(
    store: CheckpointStore,
    config: GeminiImageConfig,
    prior: PriorCheckpointClass,
    *,
    allow_definitive_retry: bool,
) -> GeminiProviderCheckpoint:
    """Load or create the active checkpoint after prior state was classified."""
    if prior == "configuration_mismatch":
        raise SafeSmokeError("CONFIGURATION_ERROR")
    if prior == "ambiguous":
        raise SafeSmokeError("AMBIGUOUS_PRIOR_SUBMISSION")
    if prior == "definitive_rejection_exhausted":
        raise SafeSmokeError("DEFINITIVE_REJECTION_NOT_AUTHORIZED")
    if prior == "definitive_rejection":
        if not allow_definitive_retry:
            raise SafeSmokeError("DEFINITIVE_REJECTION_NOT_AUTHORIZED")
        return store.update(
            operation_state="request_ready",
            new_provider_calls=0,
            provider_failure_code=None,
            provider_failure_status=None,
            provider_safe_reason_code=None,
            provider_exception_token=None,
            provider_invalid_fields=(),
            provider_retry_allowed=False,
            current_stage=None,
        )
    if prior == "none":
        return store.write(
            GeminiProviderCheckpoint(
                operation_state="request_ready",
                operation_id=_new_operation_id(),
                model=config.model,
                request_id=SMOKE_REQUEST_ID,
                created_at=datetime.now(UTC),
            )
        )
    checkpoint = store.read()
    if prior == "fresh" and checkpoint.new_provider_calls != 0:
        raise SafeSmokeError("SAFE_UNEXPECTED_FAILURE")
    return checkpoint


def execute_live(
    *,
    config_loader: Callable[[], GeminiImageConfig] = _load_gemini_config,
    provider_factory: Callable[..., GeminiImageProvider] = GeminiImageProvider,
    checkpoint_path: Path = DEFAULT_CHECKPOINT,
    private_root: Path = DEFAULT_PRIVATE_ROOT,
    archive_directory: Path = DEFAULT_CHECKPOINT_ARCHIVE,
    allow_definitive_retry: bool = False,
    start_new_operation_after_ambiguous: bool = False,
    start_new_operation_after_definitive: bool = False,
) -> SmokeOutcome:
    """Submit at most one Gemini generation request and persist safe state."""
    store = CheckpointStore(checkpoint_path, private_root)
    tracker = StageTracker(store)
    config: GeminiImageConfig | None = None
    image: GeneratedImage | None = None
    digest: str | None = None
    prior: PriorCheckpointClass | None = None
    calls = 0
    recovered = False
    archived = False
    try:
        config = config_loader()
        provider = provider_factory(
            api_key=config.api_key.get_secret_value(),
            timeout_seconds=config.timeout_seconds,
            max_image_bytes=config.max_image_bytes,
            stage_callback=tracker.begin,
        )
        tracker.begin("request_construction")
        request = GenerationRequest(
            prompt=SMOKE_PROMPT,
            model=config.model,
            size="auto",
            request_id=SMOKE_REQUEST_ID,
        )
        payload = GeminiImageProvider.build_request_parameters(request)
        if payload != expected_request_payload(config.model, SMOKE_PROMPT):
            raise SafeSmokeError("INVALID_REQUEST")
        if not _request_fields_are_supported(payload):
            raise SafeSmokeError("INVALID_REQUEST")
        tracker.begin("prior_checkpoint_classification")
        prior = classify_prior_checkpoint(store, config)
        tracker.begin("definitive_checkpoint_archival")
        if start_new_operation_after_ambiguous and start_new_operation_after_definitive:
            raise SafeSmokeError("CONFIGURATION_ERROR")
        if start_new_operation_after_ambiguous:
            if prior != "ambiguous":
                raise SafeSmokeError("NO_AMBIGUOUS_CHECKPOINT")
            archive_ambiguous_checkpoint(store, archive_directory)
            archived = True
            prior = "none"
        elif start_new_operation_after_definitive:
            if prior not in DEFINITIVE_CLASSES:
                raise SafeSmokeError("NO_DEFINITIVE_CHECKPOINT")
            archive_definitive_checkpoint(store, archive_directory)
            archived = True
            prior = "none"
        tracker.begin("checkpoint_before_submission")
        checkpoint = _prepare_checkpoint(
            store, config, prior, allow_definitive_retry=allow_definitive_retry
        )
        store.writable = True
        if checkpoint.operation_state in {"generated", "complete"}:
            recovered = True
            image = store.recover_image(config.model)
        else:
            store.update(operation_state="provider_call_started", new_provider_calls=1)
            calls = 1
            try:
                image = provider.generate_image(request)
            except GenerationProviderError as exc:
                store.persist_provider_failure(exc)
                raise
            checkpoint = store.persist_generated(image)
        if image.provider != GOOGLE_GEMINI_PROVIDER or not image.ai_generated:
            raise SafeSmokeError("MALFORMED_RESPONSE")
        if image.source_mime_type != GEMINI_SOURCE_MIME_TYPE:
            raise SafeSmokeError("UNSUPPORTED_SOURCE_MIME")
        if len(image.data) > config.max_image_bytes:
            raise SafeSmokeError("RESPONSE_TOO_LARGE")
        tracker.begin("source_hash")
        digest = hashlib.sha256(image.data).hexdigest()
        tracker.begin("deterministic_png_normalization")
        normalized = normalize_to_png(image.data, source_mime_type=image.source_mime_type)
        tracker.begin("normalized_png_validation")
        if not normalized.data.startswith(PNG_MAGIC):
            raise SafeSmokeError("NON_PNG_NORMALIZED_OUTPUT")
        if normalized.mime_type != SEALED_IMAGE_MIME_TYPE:
            raise SafeSmokeError("NON_PNG_NORMALIZED_OUTPUT")
        if hashlib.sha256(normalized.data).hexdigest() == digest:
            raise SafeSmokeError("SAFE_UNEXPECTED_FAILURE")
        tracker.begin("checkpoint_completion")
        final = store.update(
            operation_state="complete",
            current_stage=None,
            normalized_sha256=hashlib.sha256(normalized.data).hexdigest(),
            normalized_byte_count=len(normalized.data),
        )
        if final.source_sha256 != digest:
            raise SafeSmokeError("SAFE_UNEXPECTED_FAILURE")
        return SmokeOutcome(
            category="OK",
            stages=tracker.success(),
            config=config,
            image=image,
            operation_id=final.operation_id,
            source_sha256=digest,
            source_mime_type=image.source_mime_type,
            source_byte_size=len(image.data),
            normalized_byte_count=len(normalized.data),
            provider_calls=calls,
            recovered=recovered,
            prior_class=prior,
            new_operation=archived,
            archived=archived,
            delivery_mode=final.delivery_mode,
        )
    except Exception as exc:
        category, code, status, reason, token, fields = _category(exc, tracker.current)
        try:
            active = store.read() if store.exists() else None
        except SafeSmokeError:
            active = None
        return SmokeOutcome(
            category=category,
            stages=tracker.failure(),
            config=config,
            image=image,
            operation_id=active.operation_id if active is not None else None,
            source_sha256=digest,
            source_mime_type=active.source_mime_type if active is not None else None,
            source_byte_size=active.source_byte_size if active is not None else None,
            provider_code=code,
            provider_status=status,
            safe_reason_code=reason,
            exception_token=token,
            invalid_fields=fields or (active.provider_invalid_fields if active else ()),
            provider_calls=calls,
            recovered=recovered,
            retry_permitted=active is not None and _retry_allowed(active),
            prior_class=prior,
            new_operation=archived,
            archived=archived,
            delivery_mode=active.delivery_mode if active is not None else None,
        )


def _print_outcome(outcome: SmokeOutcome) -> None:
    if outcome.config is not None:
        print(f"provider: {GOOGLE_GEMINI_PROVIDER}")
        print(f"configured model: {outcome.config.model}")
        display_name = provider_model_display_name(GOOGLE_GEMINI_PROVIDER, outcome.config.model)
        print(f"provider model name: {display_name or 'UNDECLARED'}")
    print(f"generation endpoint: {GEMINI_INTERACTIONS_PATH}")
    print("requested delivery: inline")
    print(f"requested source MIME: {GEMINI_REQUEST_MIME_TYPE}")
    print(f"sealed MIME: {SEALED_IMAGE_MIME_TYPE}")
    print("read-only model preflight: NOT PERFORMED (diagnostic-only)")
    print(f"operation id: {outcome.operation_id or 'UNAVAILABLE'}")
    print(f"prior checkpoint class: {outcome.prior_class or 'UNCLASSIFIED'}")
    print(f"new operator-authorized operation: {str(outcome.new_operation).lower()}")
    print(f"prior checkpoint archived: {str(outcome.archived).lower()}")
    print(f"new generation requests: {outcome.provider_calls}")
    print(f"recovered from persisted bytes: {str(outcome.recovered).lower()}")
    print(f"inline delivery used: {str(outcome.delivery_mode == 'inline').lower()}")
    print(f"provider source MIME: {outcome.source_mime_type or 'UNAVAILABLE'}")
    if outcome.image is not None:
        print(f"source byte size: {outcome.source_byte_size or len(outcome.image.data)}")
        print(f"source SHA-256: {outcome.source_sha256 or 'UNAVAILABLE'}")
        print(f"normalized PNG byte count: {outcome.normalized_byte_count or 'UNAVAILABLE'}")
        print(f"ai_generated: {str(outcome.image.ai_generated).lower()}")
    print("stage table:")
    for stage, status in outcome.stages:
        print(f"{status}: {stage}")
    print(f"normalized safe category: {outcome.category}")
    if outcome.provider_status is not None:
        print(f"provider HTTP status: {outcome.provider_status}")
    if outcome.safe_reason_code is not None:
        print(f"provider safe reason: {outcome.safe_reason_code}")
    if outcome.safe_reason_code is not None:
        print(f"PROVIDER_ERROR_STATUS={outcome.safe_reason_code}")
    if outcome.invalid_fields:
        print(f"PROVIDER_INVALID_FIELDS={','.join(outcome.invalid_fields)}")
    if outcome.exception_token is not None:
        print(f"provider exception class: {outcome.exception_token}")
    if outcome.category != "OK":
        print(f"manually authorized retry permitted: {str(outcome.retry_permitted).lower()}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one isolated Google Gemini image-provider verification checkpoint."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Allow at most one real Google Gemini Interactions generation request.",
    )
    parser.add_argument(
        "--allow-definitive-retry",
        action="store_true",
        help=(
            "Authorize one retry after a definitive provider rejection that produced "
            "no generated bytes. Ambiguous outcomes are never retried."
        ),
    )
    parser.add_argument(
        "--start-new-operation-after-definitive",
        action="store_true",
        help=(
            "Requires --live. Archive a preserved definitive provider rejection "
            "and begin a brand-new operator-authorized operation. This is a NEW "
            "billable generation, not a retry of the rejected submission."
        ),
    )
    parser.add_argument(
        "--start-new-operation-after-ambiguous",
        action="store_true",
        help=(
            "Requires --live. Archive a preserved ambiguous checkpoint and begin a "
            "brand-new operator-authorized operation. This is a NEW billable "
            "generation, not a retry of the ambiguous submission."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    new_operation = (
        args.start_new_operation_after_ambiguous or args.start_new_operation_after_definitive
    )
    if new_operation and not args.live:
        print("ERROR: --start-new-operation-after-* requires --live.")
        print("INFO: zero network calls were made and no client was constructed.")
        return 1
    if not args.live:
        print("INFO: --live not supplied; zero network calls were made.")
        print("INFO: no Gemini client was constructed and no provider cost was incurred.")
        return INFORMATIONAL_EXIT_CODE
    if new_operation:
        print("NOTICE: starting a NEW operator-authorized Gemini operation.")
        print("NOTICE: this is a NEW billable generation, not a retry of the prior run.")
        print("NOTICE: the previous checkpoint is archived, never discarded.")
    load_dotenv(DEFAULT_ENV_FILE, override=False)
    outcome = execute_live(
        allow_definitive_retry=args.allow_definitive_retry,
        start_new_operation_after_ambiguous=args.start_new_operation_after_ambiguous,
        start_new_operation_after_definitive=args.start_new_operation_after_definitive,
    )
    _print_outcome(outcome)
    return 0 if outcome.category == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
