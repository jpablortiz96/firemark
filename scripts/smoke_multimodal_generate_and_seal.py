"""Recovery-safe live proof for one Gemini image and one ElevenLabs MP3."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, NoReturn
from uuid import uuid4

import httpx
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, field_validator

from api.firemark.b2_storage import (
    B2Error,
    create_assets_client,
    create_vault_client,
    download_bytes_verified,
    head_object_receipt,
    sealed_asset_key,
    upload_bytes_verified,
    verify_locked_object_exact,
)
from api.firemark.bootstrap import build_runtime
from api.firemark.control_plane.models import (
    AssetRecord,
    CustodyRecord,
    DeliveryAuthorization,
    GenerationRunRecord,
    VerificationRequest,
)
from api.firemark.control_plane.repository import RepositoryError
from api.firemark.control_plane.service import (
    AuthorizedDelivery,
    B2DeliveryStorage,
    CertificateService,
)
from api.firemark.control_plane.supabase_repository import SupabaseCertificateRepository
from api.firemark.custody import (
    B2CustodyReceipt,
    B2CustodyWorkflowError,
    PartialB2Object,
    StoredObjectReceipt,
    execute_b2_custody,
)
from api.firemark.genblaze_provenance import parse_complete_manifest_payload
from api.firemark.generate_and_seal import (
    GenerateAndSealRequest,
    GenerateAndSealResult,
    _identifiers,
    _png_dimensions,
    _request_fingerprint,
)
from api.firemark.generate_checkpoint import (
    CheckpointObject,
    CheckpointPartialObject,
    checkpoint_object,
    serialize_checkpoint_payload,
)
from api.firemark.generation.elevenlabs_provider import ElevenLabsAudioProvider
from api.firemark.generation.gemini_provider import GeminiImageProvider
from api.firemark.generation.models import (
    AudioGenerationRequest,
    GeneratedAudio,
    GeneratedImage,
    GenerationRequest,
)
from api.firemark.generation.normalization import normalize_to_png
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.generation.provider_identity import GOOGLE_GEMINI_PROVIDER
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import (
    FiremarkPublicAudioReferenceV1,
    FiremarkPublicCapsuleV1,
    embed_public_capsule_png,
    extract_public_capsule_png,
)
from api.firemark.seal_envelope import SealEnvelopeV1, sign_envelope
from api.firemark.settings import GenerateAndSealConfig, Settings, load_settings
from api.firemark.signer import Ed25519Signer

INFORMATIONAL_EXIT_CODE = 2
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
DEFAULT_REPORT = Path(".artifacts/multimodal-generate-and-seal-report.json")
DEFAULT_GEMINI_CHECKPOINT = Path(".artifacts/gemini-generate-and-seal-checkpoint.json")
DEFAULT_ELEVENLABS_CHECKPOINT = Path(
    ".artifacts/elevenlabs-generate-and-seal-checkpoint.json"
)
DEFAULT_PRIVATE_ROOT = Path(".artifacts/multimodal-generate-and-seal-private")

GEMINI_PROMPT = (
    "A premium forensic fire-shaped authenticity seal on a dark neutral background, "
    "clean geometric design, no text."
)
ELEVENLABS_TEXT = (
    "This AI-generated voice asset is protected by FIREMARK provenance, cryptographic "
    "verification, and durable Backblaze custody."
)

MediaKind = Literal["image", "audio"]

#: Stage names stay provider-neutral labels; the stored identity remains accurate.
STAGE_PREFIXES = {GOOGLE_GEMINI_PROVIDER: "gemini", "elevenlabs": "elevenlabs"}


def _stage_prefix(provider: str) -> str:
    return STAGE_PREFIXES.get(provider, provider)

OperationState = Literal[
    "request_ready",
    "provider_call_started",
    "provider_rejected",
    "generated",
    "prepared",
    "custody_persisted",
    "sealed_persisted",
    "registered",
    "complete",
]

GEMINI_STAGES = (
    "gemini_configuration_validation",
    "gemini_request_construction",
    "gemini_generation",
    "gemini_response_validation",
    "gemini_source_hash",
    "gemini_private_manifest",
    "gemini_canonical_hash",
    "gemini_public_capsule",
    "gemini_sealed_hash",
    "gemini_b2_custody",
    "gemini_envelope_signature",
    "gemini_supabase_registration",
    "gemini_public_certificate",
    "gemini_verify_gate",
    "gemini_delivery",
    "gemini_delivered_integrity",
    "gemini_capsule_verification",
)

ELEVENLABS_STAGES = (
    "elevenlabs_configuration_validation",
    "elevenlabs_request_construction",
    "elevenlabs_generation",
    "elevenlabs_mp3_validation",
    "elevenlabs_source_hash",
    "elevenlabs_private_manifest",
    "elevenlabs_canonical_hash",
    "elevenlabs_sealed_hash",
    "elevenlabs_b2_custody",
    "elevenlabs_envelope_signature",
    "elevenlabs_supabase_registration",
    "elevenlabs_public_certificate",
    "elevenlabs_verify_gate",
    "elevenlabs_delivery",
    "elevenlabs_delivered_integrity",
    "elevenlabs_local_hash_contract",
)

#: Stages that run after both media operations finish. They are reported with
#: their own accurate names so a finalization defect is never mislabelled as a
#: provider configuration failure.
FINALIZATION_STAGES = (
    "multimodal_evidence_validation",
    "report_serialization",
    "report_secret_scan",
    "checkpoint_finalization",
)
ALL_STAGES = frozenset(GEMINI_STAGES) | frozenset(ELEVENLABS_STAGES)

_PROVIDER_CATEGORIES = {
    "authentication": "AUTHENTICATION_FAILURE",
    "permission_denied": "PERMISSION_DENIED",
    "quota_or_billing": "QUOTA_OR_BILLING_FAILURE",
    "rate_limit": "RATE_LIMIT",
    "invalid_request": "INVALID_REQUEST",
    "model_or_size_unsupported": "MODEL_UNSUPPORTED",
    "voice_not_found": "VOICE_NOT_FOUND",
    "safety_rejection": "SAFETY_REJECTION",
    "timeout": "TIMEOUT",
    "unavailable": "PROVIDER_UNAVAILABLE",
    "malformed_response": "MALFORMED_RESPONSE",
    "non_png_response": "NON_PNG_RESPONSE",
    "non_mp3_response": "NON_MP3_RESPONSE",
    "response_too_large": "RESPONSE_TOO_LARGE",
}

_DEFINITIVE_RETRY_CODES = {
    "authentication",
    "permission_denied",
    "quota_or_billing",
    "invalid_request",
    "model_or_size_unsupported",
}

_FORBIDDEN_REPORT_MARKERS = (
    "prompt",
    "tts text",
    "api_key",
    "authorization",
    "bearer",
    "private_manifest",
    "provider_response",
    "presigned",
    "download_url",
    "delivery_url",
    "x-amz-signature",
)


class LiveCheckpointError(RuntimeError):
    """Safe classified failure that never retains a provider or service response."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class MultimodalCheckpoint(BaseModel):
    """Closed safe checkpoint; private bytes live in separate ignored files."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["firemark.multimodal-checkpoint.v1"] = (
        "firemark.multimodal-checkpoint.v1"
    )
    operation_state: OperationState
    media_type: MediaKind
    #: The distributable sealed carrier.
    mime_type: Literal["image/png", "audio/mpeg"]
    file_extension: Literal["png", "mp3"]
    #: The exact format the provider delivered. It is never relabelled and it
    #: defines what private source custody stores.
    source_mime_type: str | None = None
    source_extension: str | None = None
    provider: Literal["google_gemini", "elevenlabs"]
    model: str
    size: str | None = None
    idempotency_key: str
    run_id: str
    asset_id: str
    cert_id: str
    issued_at: datetime
    requested_retention_until: datetime
    signer_key_id: str
    source_sha256: str | None = None
    sealed_sha256: str | None = None
    canonical_hash: str | None = None
    generated_byte_count: int | None = Field(default=None, gt=0)
    source_path: str | None = None
    manifest_path: str | None = None
    generated_metadata_path: str | None = None
    new_provider_calls: int = Field(default=0, ge=0, le=1)
    prior_rejected_calls: int = Field(default=0, ge=0)
    provider_failure_code: str | None = None
    provider_retry_allowed: bool = False
    current_stage: str | None = None
    stage_results: tuple[dict[str, str], ...] = ()
    assets_source: CheckpointObject | None = None
    assets_manifest: CheckpointObject | None = None
    vault_source: CheckpointObject | None = None
    vault_manifest: CheckpointObject | None = None
    sealed_asset: CheckpointObject | None = None
    partial_objects: tuple[CheckpointPartialObject, ...] = ()

    @field_validator("issued_at", "requested_retention_until")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Checkpoint timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("source_sha256", "sealed_sha256", "canonical_hash")
    @classmethod
    def validate_optional_digest(cls, value: str | None) -> str | None:
        if value is not None and (
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("Checkpoint digest is invalid")
        return value

    @property
    def custody_mime_type(self) -> str:
        """The MIME type private source custody stores, never the sealed one."""
        return self.source_mime_type or self.mime_type

    @property
    def custody_extension(self) -> str:
        return self.source_extension or self.file_extension


class CheckpointStore:
    """Atomic allowlisted checkpoint and private-evidence persistence."""

    def __init__(self, path: Path, private_root: Path) -> None:
        self.path = path
        self.private_root = private_root

    def exists(self) -> bool:
        return self.path.is_file()

    def read(self) -> MultimodalCheckpoint:
        try:
            return MultimodalCheckpoint.model_validate_json(self.path.read_bytes())
        except Exception:
            raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE") from None

    def write(self, checkpoint: MultimodalCheckpoint) -> None:
        _atomic_write(self.path, serialize_checkpoint_payload(checkpoint))

    def update(self, **values: object) -> MultimodalCheckpoint:
        checkpoint = self.read().model_copy(update=values)
        checkpoint = MultimodalCheckpoint.model_validate(checkpoint.model_dump())
        self.write(checkpoint)
        return checkpoint

    def mark_stage(self, stage: str, completed: Sequence[dict[str, str]]) -> None:
        if self.exists():
            self.update(current_stage=stage, stage_results=tuple(completed))

    def private_file(self, run_id: str, name: str, payload: bytes) -> Path:
        if not run_id.startswith("firemark-run-"):
            raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
        destination = self.private_root / run_id / name
        _atomic_write(destination, payload)
        return destination.resolve()

    def persist_generated(self, media: GeneratedImage | GeneratedAudio) -> None:
        checkpoint = self.read()
        if (
            checkpoint.new_provider_calls != 1
            or checkpoint.operation_state != "provider_call_started"
        ):
            raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
        source_path = self.private_file(
            checkpoint.run_id,
            f"source.{media.file_extension}",
            media.data,
        )
        metadata: dict[str, object] = {
            "provider": media.provider,
            "model": media.model,
            "provider_request_id": media.provider_request_id,
            "provider_created_at": media.provider_created_at.isoformat(),
            "safe_generation_metadata": media.safe_generation_metadata,
            "ai_generated": media.ai_generated,
        }
        if isinstance(media, GeneratedImage):
            metadata["seed"] = media.seed
            metadata["source_mime_type"] = media.source_mime_type
            metadata["source_extension"] = media.source_extension
            metadata["width"] = media.width
            metadata["height"] = media.height
        else:
            metadata["voice_id"] = media.voice_id
            metadata["duration_ms"] = media.duration_ms
        metadata_path = self.private_file(
            checkpoint.run_id,
            "generated-metadata.json",
            json.dumps(metadata, ensure_ascii=True, sort_keys=True).encode("utf-8"),
        )
        source_updates: dict[str, object] = (
            {
                "source_mime_type": media.source_mime_type,
                "source_extension": media.source_extension,
            }
            if isinstance(media, GeneratedImage)
            else {}
        )
        self.update(
            **source_updates,
            operation_state="generated",
            source_sha256=sha256_bytes(media.data),
            generated_byte_count=len(media.data),
            source_path=str(source_path),
            generated_metadata_path=str(metadata_path),
            provider_failure_code=None,
            provider_retry_allowed=False,
        )

    def persist_provider_failure(self, exc: GenerationProviderError) -> None:
        checkpoint = self.read()
        if checkpoint.operation_state != "provider_call_started":
            raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
        self.update(
            operation_state="provider_rejected",
            prior_rejected_calls=checkpoint.prior_rejected_calls + 1,
            provider_failure_code=exc.code,
            provider_retry_allowed=exc.code in _DEFINITIVE_RETRY_CODES,
        )

    def checkpoint_event(self, event: str, values: dict[str, Any]) -> None:
        checkpoint = self.read()
        if event == "prepared":
            manifest_bytes = values["manifest_bytes"]
            source_bytes = values["source_bytes"]
            if not isinstance(manifest_bytes, bytes) or not isinstance(source_bytes, bytes):
                raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
            if sha256_bytes(source_bytes) != checkpoint.source_sha256:
                raise LiveCheckpointError("VERIFICATION_FAILURE")
            manifest_path = self.private_file(
                checkpoint.run_id, "private-manifest.json", manifest_bytes
            )
            self.update(
                operation_state="prepared",
                source_sha256=values["source_sha256"],
                sealed_sha256=values["sealed_sha256"],
                canonical_hash=values["canonical_hash"],
                issued_at=values["issued_at"],
                requested_retention_until=values["requested_retention_until"],
                signer_key_id=values["signer_key_id"],
                source_mime_type=values.get("source_mime_type"),
                source_extension=values.get("source_extension"),
                manifest_path=str(manifest_path),
            )
            return
        if event == "custody_persisted":
            custody: B2CustodyReceipt = values["custody_receipt"]
            state: OperationState = (
                checkpoint.operation_state
                if checkpoint.operation_state in {"sealed_persisted", "registered", "complete"}
                else "custody_persisted"
            )
            self.update(
                operation_state=state,
                assets_source=checkpoint_object(
                    custody.assets_source, bucket_role="assets", object_kind="source"
                ),
                assets_manifest=checkpoint_object(
                    custody.assets_manifest, bucket_role="assets", object_kind="manifest"
                ),
                vault_source=checkpoint_object(
                    custody.vault_source, bucket_role="vault", object_kind="source"
                ),
                vault_manifest=checkpoint_object(
                    custody.vault_manifest, bucket_role="vault", object_kind="manifest"
                ),
            )
            return
        if event == "sealed_persisted":
            sealed_state: OperationState = (
                checkpoint.operation_state
                if checkpoint.operation_state in {"registered", "complete"}
                else "sealed_persisted"
            )
            self.update(
                operation_state=sealed_state,
                sealed_asset=checkpoint_object(
                    values["sealed_receipt"], bucket_role="assets", object_kind="sealed"
                ),
            )
            return
        if event == "registered":
            self.update(operation_state="registered")
            return
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")

    def persist_partials(self, partials: tuple[PartialB2Object, ...]) -> None:
        projected = tuple(
            CheckpointPartialObject.model_validate(item.__dict__) for item in partials
        )
        self.update(partial_objects=projected)


class StageTracker:
    """Safe stage output with results durably copied into its operation checkpoint."""

    def __init__(self, store: CheckpointStore, prefix: str) -> None:
        self.store = store
        self.prefix = prefix
        checkpoint = store.read() if store.exists() else None
        self.completed = list(checkpoint.stage_results) if checkpoint is not None else []
        self.current: str | None = None

    def begin(self, stage: str) -> None:
        if stage == self.current or self._completed(stage):
            return
        self.complete_current()
        self.current = stage
        self.store.mark_stage(stage, self.completed)

    def complete_current(self) -> None:
        if self.current is None or self._completed(self.current):
            return
        self.completed.append({"stage": self.current, "status": "PASS"})
        print(f"PASS: {self.current}")
        self.store.mark_stage(self.current, self.completed)
        self.current = None

    def _completed(self, stage: str) -> bool:
        return any(item.get("stage") == stage for item in self.completed)

    def core_stage(self, stage: str) -> None:
        mapping = {
            "provider_request_construction": f"{self.prefix}_request_construction",
            "provider_response_validation": (
                "gemini_response_validation"
                if self.prefix == "gemini"
                else "elevenlabs_mp3_validation"
            ),
            "source_hash": f"{self.prefix}_source_hash",
            "genblaze_manifest": f"{self.prefix}_private_manifest",
            "canonical_hash": f"{self.prefix}_canonical_hash",
            "public_capsule_embedding": "gemini_public_capsule",
            "sealed_hash": f"{self.prefix}_sealed_hash",
            "vault_source_upload": f"{self.prefix}_b2_custody",
            "vault_source_hash_verification": f"{self.prefix}_b2_custody",
            "vault_source_retention_verification": f"{self.prefix}_b2_custody",
            "vault_manifest_upload": f"{self.prefix}_b2_custody",
            "vault_manifest_hash_verification": f"{self.prefix}_b2_custody",
            "vault_manifest_retention_readback": f"{self.prefix}_b2_custody",
            "vault_manifest_retention_validation": f"{self.prefix}_b2_custody",
            "checkpoint_after_vault_manifest": f"{self.prefix}_b2_custody",
            "sealed_asset_upload": f"{self.prefix}_b2_custody",
            "sealed_asset_hash_verification": f"{self.prefix}_b2_custody",
            "envelope_signature": f"{self.prefix}_envelope_signature",
            "supabase_registration": f"{self.prefix}_supabase_registration",
        }
        mapped = mapping.get(stage)
        if mapped is not None:
            self.begin(mapped)


class CapturedGeminiProvider:
    def __init__(
        self,
        provider: GeminiImageProvider,
        store: CheckpointStore,
        tracker: StageTracker,
    ) -> None:
        self.provider = provider
        self.store = store
        self.tracker = tracker
        self.calls = 0

    def generate_image(self, request: GenerationRequest) -> GeneratedImage:
        if self.calls or self.store.read().new_provider_calls:
            raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
        self.calls += 1
        self.store.update(operation_state="provider_call_started", new_provider_calls=1)
        self.tracker.begin("gemini_generation")
        try:
            media = self.provider.generate_image(request)
        except GenerationProviderError as exc:
            self.store.persist_provider_failure(exc)
            raise
        self.store.persist_generated(media)
        self.tracker.begin("gemini_response_validation")
        return media


class CapturedElevenLabsProvider:
    def __init__(
        self,
        provider: ElevenLabsAudioProvider,
        store: CheckpointStore,
        tracker: StageTracker,
    ) -> None:
        self.provider = provider
        self.store = store
        self.tracker = tracker
        self.calls = 0

    def generate_audio(self, request: AudioGenerationRequest) -> GeneratedAudio:
        if self.calls or self.store.read().new_provider_calls:
            raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
        self.calls += 1
        self.store.update(operation_state="provider_call_started", new_provider_calls=1)
        self.tracker.begin("elevenlabs_generation")
        try:
            media = self.provider.generate_audio(request)
        except GenerationProviderError as exc:
            self.store.persist_provider_failure(exc)
            raise
        self.store.persist_generated(media)
        self.tracker.begin("elevenlabs_mp3_validation")
        return media


class RecoveredImageProvider:
    def __init__(self, media: GeneratedImage) -> None:
        self.media = media

    def generate_image(self, request: GenerationRequest) -> GeneratedImage:
        if request.model != self.media.model:
            raise LiveCheckpointError("CONFIGURATION_ERROR")
        return self.media


class RecoveredAudioProvider:
    def __init__(self, media: GeneratedAudio) -> None:
        self.media = media

    def generate_audio(self, request: AudioGenerationRequest) -> GeneratedAudio:
        if request.model != self.media.model or request.voice_id != self.media.voice_id:
            raise LiveCheckpointError("CONFIGURATION_ERROR")
        return self.media


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


def _read_generated_media(
    checkpoint: MultimodalCheckpoint,
) -> GeneratedImage | GeneratedAudio:
    if checkpoint.source_path is None or checkpoint.generated_metadata_path is None:
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
    try:
        data = Path(checkpoint.source_path).read_bytes()
        metadata = json.loads(Path(checkpoint.generated_metadata_path).read_text("utf-8"))
        if not isinstance(metadata, dict) or sha256_bytes(data) != checkpoint.source_sha256:
            raise ValueError
        common = {
            "data": data,
            "provider": metadata["provider"],
            "model": metadata["model"],
            "provider_request_id": metadata.get("provider_request_id"),
            "provider_created_at": metadata["provider_created_at"],
            "safe_generation_metadata": metadata.get("safe_generation_metadata", {}),
            "ai_generated": metadata["ai_generated"],
        }
        if checkpoint.media_type == "image":
            return GeneratedImage(
                **common,
                seed=metadata.get("seed"),
                source_mime_type=metadata.get("source_mime_type", "image/png"),
                source_extension=metadata.get("source_extension", "png"),
                width=metadata.get("width"),
                height=metadata.get("height"),
            )
        return GeneratedAudio(
            **common,
            voice_id=metadata["voice_id"],
            duration_ms=metadata.get("duration_ms"),
        )
    except Exception:
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE") from None


def _load_private_evidence(
    checkpoint: MultimodalCheckpoint, *, max_bytes: int
) -> tuple[bytes, bytes, Any]:
    if checkpoint.source_path is None or checkpoint.manifest_path is None:
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
    try:
        source_path = Path(checkpoint.source_path)
        manifest_path = Path(checkpoint.manifest_path)
        if source_path.stat().st_size > max_bytes or manifest_path.stat().st_size > max_bytes:
            raise ValueError
        source = source_path.read_bytes()
        manifest_bytes = manifest_path.read_bytes()
        manifest = parse_complete_manifest_payload(manifest_bytes)
        if len(manifest.run.steps) != 1:
            raise ValueError
        step = manifest.run.steps[0]
        asset = step.assets[0] if len(step.assets) == 1 else None
        if (
            asset is None
            or checkpoint.source_sha256 is None
            or sha256_bytes(source) != checkpoint.source_sha256
            or asset.sha256 != checkpoint.source_sha256
            or manifest.canonical_hash != checkpoint.canonical_hash
            or manifest.run.run_id != checkpoint.run_id
            or str(step.provider).lower() != checkpoint.provider
            or step.model != checkpoint.model
            or dict(step.metadata).get("ai_generated") is not True
            or dict(manifest.run.metadata).get("ai_generated") is not True
        ):
            raise ValueError
        return source, manifest_bytes, step
    except Exception:
        raise LiveCheckpointError("VERIFICATION_FAILURE") from None


def _reconstruct_sealed(
    checkpoint: MultimodalCheckpoint, source: bytes, *, public_base_url: str
) -> tuple[bytes, dict[str, object]]:
    required = (
        checkpoint.source_sha256,
        checkpoint.sealed_sha256,
        checkpoint.canonical_hash,
    )
    if any(value is None for value in required):
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    common = {
        "cert_id": checkpoint.cert_id,
        "asset_id": checkpoint.asset_id,
        "run_id": checkpoint.run_id,
        "canonical_hash": checkpoint.canonical_hash,
        "source_sha256": checkpoint.source_sha256,
        "signer_key_id": checkpoint.signer_key_id,
        "verify_url": f"{public_base_url.rstrip('/')}/v1/certificates/{checkpoint.cert_id}",
        "issued_at": checkpoint.issued_at,
    }
    if checkpoint.media_type == "image":
        capsule = FiremarkPublicCapsuleV1.model_validate(common)
        carrier = (
            source
            if checkpoint.custody_mime_type == "image/png"
            else normalize_to_png(
                source, source_mime_type=checkpoint.custody_mime_type
            ).data
        )
        sealed = embed_public_capsule_png(carrier, capsule)
        public_manifest: dict[str, object] = capsule.model_dump(mode="json")
    else:
        sealed = source
        reference = FiremarkPublicAudioReferenceV1.model_validate(
            {**common, "sealed_sha256": checkpoint.sealed_sha256}
        )
        public_manifest = reference.model_dump(mode="json")
    if sha256_bytes(sealed) != checkpoint.sealed_sha256:
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    return sealed, public_manifest


def _load_or_create_custody(
    checkpoint: MultimodalCheckpoint,
    store: CheckpointStore,
    tracker: StageTracker,
    config: GenerateAndSealConfig,
    assets_client: Any,
    vault_client: Any,
    source: bytes,
    manifest_bytes: bytes,
) -> B2CustodyReceipt:
    if checkpoint.source_sha256 is None or checkpoint.canonical_hash is None:
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    refs = (
        checkpoint.assets_source,
        checkpoint.assets_manifest,
        checkpoint.vault_source,
        checkpoint.vault_manifest,
    )
    tracker.begin(f"{_stage_prefix(checkpoint.provider)}_b2_custody")
    if all(reference is not None for reference in refs):
        assets_source_ref = checkpoint.assets_source
        assets_manifest_ref = checkpoint.assets_manifest
        vault_source_ref = checkpoint.vault_source
        vault_manifest_ref = checkpoint.vault_manifest
        assert assets_source_ref is not None
        assert assets_manifest_ref is not None
        assert vault_source_ref is not None
        assert vault_manifest_ref is not None
        assets_source = head_object_receipt(
            assets_client,
            bucket=assets_source_ref.bucket,
            key=assets_source_ref.key,
            expected_sha256=assets_source_ref.sha256,
            version_id=assets_source_ref.version_id,
        )
        assets_manifest = head_object_receipt(
            assets_client,
            bucket=assets_manifest_ref.bucket,
            key=assets_manifest_ref.key,
            expected_sha256=assets_manifest_ref.sha256,
            version_id=assets_manifest_ref.version_id,
        )
        if assets_source is None or assets_manifest is None:
            raise LiveCheckpointError("B2_CUSTODY_FAILURE")
        download_bytes_verified(
            assets_client,
            bucket=assets_source.bucket,
            key=assets_source.key,
            expected_sha256=assets_source.sha256,
            version_id=assets_source.version_id,
            max_bytes=len(source),
        )
        download_bytes_verified(
            assets_client,
            bucket=assets_manifest.bucket,
            key=assets_manifest.key,
            expected_sha256=assets_manifest.sha256,
            version_id=assets_manifest.version_id,
            max_bytes=len(manifest_bytes),
        )
        vault_source, remote_source = verify_locked_object_exact(
            vault_client,
            bucket=vault_source_ref.bucket,
            key=vault_source_ref.key,
            expected_sha256=vault_source_ref.sha256,
            version_id=vault_source_ref.version_id,
            max_bytes=len(source),
        )
        vault_manifest, remote_manifest = verify_locked_object_exact(
            vault_client,
            bucket=vault_manifest_ref.bucket,
            key=vault_manifest_ref.key,
            expected_sha256=vault_manifest_ref.sha256,
            version_id=vault_manifest_ref.version_id,
            max_bytes=len(manifest_bytes),
        )
        if remote_source != source or remote_manifest != manifest_bytes:
            raise LiveCheckpointError("B2_CUSTODY_FAILURE")
        minimum_retention = checkpoint.requested_retention_until - timedelta(seconds=1)
        if (
            vault_source.retention_mode != "COMPLIANCE"
            or vault_manifest.retention_mode != "COMPLIANCE"
            or vault_source.retention_until < minimum_retention
            or vault_manifest.retention_until < minimum_retention
        ):
            raise LiveCheckpointError("B2_CUSTODY_FAILURE")
        return B2CustodyReceipt(
            source_sha256=checkpoint.source_sha256,
            canonical_hash=checkpoint.canonical_hash,
            assets_source=assets_source,
            assets_manifest=assets_manifest,
            vault_source=vault_source,
            vault_manifest=vault_manifest,
            requested_retention_until=checkpoint.requested_retention_until,
            created_at=checkpoint.issued_at,
            custody_verified=True,
        )
    with tempfile.TemporaryDirectory(prefix="firemark-multimodal-recovery-") as directory:
        source_path = Path(directory) / f"source.{checkpoint.custody_extension}"
        source_path.write_bytes(source)
        custody = execute_b2_custody(
            assets_client=assets_client,
            vault_client=vault_client,
            assets_bucket=config.b2.assets.bucket,
            vault_bucket=config.b2.vault.bucket,
            source_path=source_path,
            manifest_bytes=manifest_bytes,
            source_sha256=checkpoint.source_sha256,
            canonical_hash=checkpoint.canonical_hash,
            run_id=checkpoint.run_id,
            cert_id=checkpoint.cert_id,
            extension=checkpoint.custody_extension,
            retention_until=checkpoint.requested_retention_until,
            source_content_type=checkpoint.custody_mime_type,
            now=checkpoint.issued_at,
            stage_callback=tracker.core_stage,
            persistence_callback=store.persist_partials,
        )
    store.checkpoint_event("custody_persisted", {"custody_receipt": custody})
    return custody


def _load_or_create_sealed(
    checkpoint: MultimodalCheckpoint,
    store: CheckpointStore,
    tracker: StageTracker,
    config: GenerateAndSealConfig,
    assets_client: Any,
    sealed: bytes,
) -> StoredObjectReceipt:
    if checkpoint.sealed_sha256 is None:
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    reference = checkpoint.sealed_asset
    if reference is not None:
        receipt = head_object_receipt(
            assets_client,
            bucket=reference.bucket,
            key=reference.key,
            expected_sha256=checkpoint.sealed_sha256,
            version_id=reference.version_id,
        )
    else:
        key = sealed_asset_key(checkpoint.sealed_sha256, checkpoint.file_extension)
        receipt = head_object_receipt(
            assets_client,
            bucket=config.b2.assets.bucket,
            key=key,
            expected_sha256=checkpoint.sealed_sha256,
        )
        if receipt is None:
            receipt = upload_bytes_verified(
                assets_client,
                bucket=config.b2.assets.bucket,
                key=key,
                data=sealed,
                expected_sha256=checkpoint.sealed_sha256,
                content_type=checkpoint.mime_type,
                metadata={
                    "firemark-kind": "sealed",
                    "firemark-schema": "1",
                    "firemark-cert-id": checkpoint.cert_id,
                },
                known_unlocked=True,
                stage_callback=tracker.core_stage,
                upload_stage="sealed_asset_upload",
                hash_verification_stage="sealed_asset_hash_verification",
            )
    if receipt is None or receipt.version_id is None:
        raise LiveCheckpointError("B2_CUSTODY_FAILURE")
    delivered = download_bytes_verified(
        assets_client,
        bucket=receipt.bucket,
        key=receipt.key,
        expected_sha256=checkpoint.sealed_sha256,
        version_id=receipt.version_id,
        max_bytes=len(sealed),
    )
    if delivered != sealed:
        raise LiveCheckpointError("B2_CUSTODY_FAILURE")
    store.checkpoint_event("sealed_persisted", {"sealed_receipt": receipt})
    return receipt


def _register_recovered(
    checkpoint: MultimodalCheckpoint,
    store: CheckpointStore,
    tracker: StageTracker,
    config: GenerateAndSealConfig,
    repository: Any,
    custody: B2CustodyReceipt,
    sealed_receipt: StoredObjectReceipt,
    public_manifest: dict[str, object],
    step: Any,
    generated_media: GeneratedImage | GeneratedAudio,
    sealed_carrier: bytes,
) -> None:
    if (
        checkpoint.source_sha256 is None
        or checkpoint.sealed_sha256 is None
        or checkpoint.canonical_hash is None
    ):
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    signer = Ed25519Signer.from_private_key_base64(
        config.signing_private_key_b64.get_secret_value(), config.signing_public_key_b64
    )
    if signer.signer_key_id != checkpoint.signer_key_id:
        raise LiveCheckpointError("CONFIGURATION_ERROR")
    tracker.begin(f"{_stage_prefix(checkpoint.provider)}_envelope_signature")
    envelope = SealEnvelopeV1(
        cert_id=checkpoint.cert_id,
        run_id=checkpoint.run_id,
        canonical_hash=checkpoint.canonical_hash,
        source_sha256=checkpoint.source_sha256,
        sealed_sha256=checkpoint.sealed_sha256,
        sealed_asset_bucket=sealed_receipt.bucket,
        sealed_asset_key=sealed_receipt.key,
        public_manifest_bucket=sealed_receipt.bucket,
        public_manifest_key=sealed_receipt.key,
        vault_bucket=custody.vault_source.bucket,
        vault_source_key=custody.vault_source.key,
        vault_source_version_id=custody.vault_source.version_id or "",
        vault_manifest_key=custody.vault_manifest.key,
        vault_manifest_version_id=custody.vault_manifest.version_id or "",
        retention_until=custody.vault_source.retention_until,
        signer_key_id=checkpoint.signer_key_id,
        created_at=checkpoint.issued_at,
    )
    signed = sign_envelope(envelope, signer)
    private_text = GEMINI_PROMPT if checkpoint.media_type == "image" else ELEVENLABS_TEXT
    voice_id = generated_media.voice_id if isinstance(generated_media, GeneratedAudio) else None
    fingerprint = _request_fingerprint(
        {
            "media_type": checkpoint.media_type,
            "provider": checkpoint.provider,
            "private_text": private_text,
            "model": checkpoint.model,
            "size": checkpoint.size,
            "voice_id": voice_id,
        }
    )
    generation_run = GenerationRunRecord(
        run_id=checkpoint.run_id,
        provider=checkpoint.provider,
        model=checkpoint.model,
        ai_generated=True,
        prompt_private=private_text,
        parameters_private={
            "_firemark_request_fingerprint": fingerprint,
            "requested_size": checkpoint.size,
            "voice_id": voice_id,
            "media_type": checkpoint.media_type,
            "provider": dict(step.metadata),
        },
        seed_private=step.seed if checkpoint.media_type == "image" else None,
        canonical_hash=checkpoint.canonical_hash,
        manifest_storage_key=custody.assets_manifest.key,
        manifest_version_id=custody.assets_manifest.version_id,
        created_at=checkpoint.issued_at,
    )
    width: int | None = None
    height: int | None = None
    duration_ms: int | None = None
    if isinstance(generated_media, GeneratedImage):
        width, height = _png_dimensions(sealed_carrier)
    else:
        duration_ms = generated_media.duration_ms
    asset = AssetRecord(
        asset_id=checkpoint.asset_id,
        run_id=checkpoint.run_id,
        asset_type=checkpoint.media_type,
        media_type=checkpoint.mime_type,
        file_extension=checkpoint.file_extension,
        byte_size=sealed_receipt.size_bytes,
        width=width,
        height=height,
        duration_ms=duration_ms,
        source_sha256=checkpoint.source_sha256,
        sealed_sha256=checkpoint.sealed_sha256,
        assets_bucket=sealed_receipt.bucket,
        assets_key=sealed_receipt.key,
        assets_version_id=sealed_receipt.version_id or "",
        vault_bucket=custody.vault_source.bucket,
        vault_key=custody.vault_source.key,
        vault_version_id=custody.vault_source.version_id or "",
        created_at=checkpoint.issued_at,
    )
    custody_record = CustodyRecord(
        asset_id=checkpoint.asset_id,
        custody_receipt=custody,
        retention_mode="COMPLIANCE",
        retention_until=custody.vault_source.retention_until,
        custody_verified=True,
        created_at=checkpoint.issued_at,
    )
    service = CertificateService(repository, public_base_url=config.public_base_url)
    existing = repository.get_certificate(checkpoint.cert_id)
    tracker.begin(f"{_stage_prefix(checkpoint.provider)}_supabase_registration")
    if existing is None:
        service.register_certificate(
            generation_run=generation_run,
            asset=asset,
            custody=custody_record,
            envelope=envelope,
            signature_b64=signed.signature,
            signer_public_key_b64=signer.export_public_key_base64(),
            public_manifest=public_manifest,
            canonical_hash=checkpoint.canonical_hash,
            cert_id=checkpoint.cert_id,
            asset_id=checkpoint.asset_id,
            run_id=checkpoint.run_id,
        )
    elif not _certificate_matches(existing, checkpoint):
        raise LiveCheckpointError("REGISTRATION_FAILURE")
    store.checkpoint_event("registered", {})


def _certificate_matches(certificate: Any, checkpoint: MultimodalCheckpoint) -> bool:
    return bool(
        certificate.cert_id == checkpoint.cert_id
        and certificate.asset_id == checkpoint.asset_id
        and certificate.run_id == checkpoint.run_id
        and certificate.provider == checkpoint.provider
        and certificate.model == checkpoint.model
        and certificate.media_type == checkpoint.media_type
        and certificate.mime_type == checkpoint.mime_type
        and certificate.ai_generated is True
        and certificate.source_sha256 == checkpoint.source_sha256
        and certificate.sealed_sha256 == checkpoint.sealed_sha256
        and certificate.canonical_hash == checkpoint.canonical_hash
        and certificate.signer_key_id == checkpoint.signer_key_id
    )


def _download_delivery(url: str, *, max_bytes: int, timeout: int) -> bytes:
    try:
        with httpx.Client(follow_redirects=False, timeout=float(timeout)) as client:
            with client.stream("GET", url) as response:
                if response.status_code != 200:
                    raise LiveCheckpointError("DELIVERY_FAILURE")
                payload = bytearray()
                for chunk in response.iter_bytes():
                    payload.extend(chunk)
                    if len(payload) > max_bytes:
                        raise LiveCheckpointError("RESPONSE_TOO_LARGE")
                return bytes(payload)
    except LiveCheckpointError:
        raise
    except httpx.TimeoutException:
        raise LiveCheckpointError("TIMEOUT") from None
    except httpx.HTTPError:
        raise LiveCheckpointError("DELIVERY_FAILURE") from None


def _database_secret_scan(
    repository: Any, checkpoint: MultimodalCheckpoint, secret_values: Sequence[str]
) -> None:
    client = repository._get_client()
    targets = (
        ("generation_runs", "run_id", checkpoint.run_id),
        ("assets", "asset_id", checkpoint.asset_id),
        ("custody_records", "asset_id", checkpoint.asset_id),
        ("certificates", "cert_id", checkpoint.cert_id),
        ("verification_events", "cert_id", checkpoint.cert_id),
        ("delivery_events", "cert_id", checkpoint.cert_id),
    )
    rows: list[Any] = []
    for table, field, value in targets:
        response = client.table(table).select("*").eq(field, value).execute()
        rows.extend(response.data or [])
    serialized = json.dumps(rows, default=str, ensure_ascii=True)
    lowered = serialized.lower()
    if any(secret and secret in serialized for secret in secret_values) or any(
        marker in lowered for marker in ("x-amz-signature", "authorization: bearer")
    ):
        raise LiveCheckpointError("VERIFICATION_FAILURE")


def _verify_and_deliver(
    checkpoint: MultimodalCheckpoint,
    store: CheckpointStore,
    tracker: StageTracker,
    config: GenerateAndSealConfig,
    repository: Any,
    assets_client: Any,
    sealed: bytes,
    public_manifest: dict[str, object],
    delivery_ttl_seconds: int,
) -> dict[str, object]:
    if checkpoint.sealed_sha256 is None:
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    service = CertificateService(
        repository,
        public_base_url=config.public_base_url,
        storage=B2DeliveryStorage(assets_client),
        delivery_ttl_seconds=delivery_ttl_seconds,
    )
    tracker.begin(f"{_stage_prefix(checkpoint.provider)}_public_certificate")
    certificate = service.get_public_certificate(checkpoint.cert_id)
    if certificate is None or not _certificate_matches(
        repository.get_certificate(checkpoint.cert_id), checkpoint
    ):
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    tracker.begin(f"{_stage_prefix(checkpoint.provider)}_verify_gate")
    verification = service.verify(
        VerificationRequest(
            cert_id=checkpoint.cert_id, presented_sha256=checkpoint.sealed_sha256
        )
    )
    if not verification.verified or verification.media_type != checkpoint.media_type:
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    tracker.begin(f"{_stage_prefix(checkpoint.provider)}_delivery")
    delivery = service.authorize_delivery(
        checkpoint.cert_id,
        DeliveryAuthorization(presented_sha256=checkpoint.sealed_sha256),
    )
    if not isinstance(delivery, AuthorizedDelivery):
        raise LiveCheckpointError("DELIVERY_FAILURE")
    transient_url = delivery.download.reveal_url()
    try:
        delivered = _download_delivery(
            transient_url,
            max_bytes=(
                config.max_generated_image_bytes
                if checkpoint.media_type == "image"
                else config.max_generated_audio_bytes
            ),
            timeout=config.generation_timeout_seconds,
        )
    finally:
        transient_url = ""
    tracker.begin(f"{_stage_prefix(checkpoint.provider)}_delivered_integrity")
    if delivered != sealed or sha256_bytes(delivered) != checkpoint.sealed_sha256:
        raise LiveCheckpointError("DELIVERY_FAILURE")
    if checkpoint.media_type == "image":
        tracker.begin("gemini_capsule_verification")
        capsule = extract_public_capsule_png(delivered)
        if capsule.model_dump(mode="json") != public_manifest:
            raise LiveCheckpointError("VERIFICATION_FAILURE")
    else:
        tracker.begin("elevenlabs_local_hash_contract")
        reference = FiremarkPublicAudioReferenceV1.model_validate(public_manifest)
        if (
            reference.embedded
            or reference.verification_method != "cert_id+sha256"
            or checkpoint.source_sha256 != checkpoint.sealed_sha256
        ):
            raise LiveCheckpointError("VERIFICATION_FAILURE")
    tracker.complete_current()
    updated = store.update(
        operation_state="complete",
        stage_results=tuple(tracker.completed),
        current_stage=None,
    )
    return _operation_report(updated)


def _operation_report(checkpoint: MultimodalCheckpoint) -> dict[str, object]:
    required_refs = (
        checkpoint.vault_source,
        checkpoint.vault_manifest,
        checkpoint.sealed_asset,
    )
    if any(reference is None for reference in required_refs):
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
    vault_source = checkpoint.vault_source
    vault_manifest = checkpoint.vault_manifest
    sealed_asset = checkpoint.sealed_asset
    assert vault_source is not None
    assert vault_manifest is not None
    assert sealed_asset is not None
    return {
        "provider": checkpoint.provider,
        "model": checkpoint.model,
        "media_type": checkpoint.media_type,
        "mime_type": checkpoint.mime_type,
        "source_mime_type": checkpoint.custody_mime_type,
        "byte_size": sealed_asset.size_bytes,
        "run_id": checkpoint.run_id,
        "asset_id": checkpoint.asset_id,
        "cert_id": checkpoint.cert_id,
        "source_sha256": checkpoint.source_sha256,
        "sealed_sha256": checkpoint.sealed_sha256,
        "canonical_hash": checkpoint.canonical_hash,
        "signer_key_id": checkpoint.signer_key_id,
        "sealed_asset_key": sealed_asset.key,
        "sealed_asset_version_id": sealed_asset.version_id,
        "vault_source_key": vault_source.key,
        "vault_source_version_id": vault_source.version_id,
        "vault_manifest_key": vault_manifest.key,
        "vault_manifest_version_id": vault_manifest.version_id,
        "retention_until": vault_source.retention_until.isoformat()
        if vault_source.retention_until is not None
        else None,
        "ai_generated": True,
        "new_provider_calls": checkpoint.new_provider_calls,
        "stages": list(checkpoint.stage_results),
    }


def _validated_stage_rows(rows: object) -> tuple[str, ...]:
    """Validate stage rows against the declared stage names.

    Stage labels are FIREMARK's own vocabulary, not provider data. Several of
    them legitimately contain words the secret scanner treats as markers -- for
    example ``gemini_private_manifest`` names the step that builds the private
    manifest, it never carries the manifest. Validating the rows against the
    declared stage tuples is strictly stronger than a substring scan, so the
    rows are checked here and excluded from the marker scan below.
    """
    if not isinstance(rows, list):
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
    names: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {"stage", "status"}:
            raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
        stage = row["stage"]
        if stage not in ALL_STAGES or row["status"] != "PASS":
            raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
        names.append(str(stage))
    return tuple(names)


def _scannable_report(report: Mapping[str, object]) -> dict[str, object]:
    """Return a scan copy with validated stage rows reduced to a count."""
    scannable: dict[str, object] = {}
    for key, value in report.items():
        if isinstance(value, Mapping) and "stages" in value:
            operation = dict(value)
            operation["stages"] = len(_validated_stage_rows(operation.pop("stages")))
            scannable[key] = operation
        else:
            scannable[key] = value
    return scannable


def _safe_report_bytes(report: Mapping[str, object]) -> bytes:
    payload = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8")
    scanned = json.dumps(
        _scannable_report(report), ensure_ascii=True, sort_keys=True, default=str
    ).lower()
    if any(marker in scanned for marker in _FORBIDDEN_REPORT_MARKERS):
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
    return payload


def _write_report_bytes(path: Path, payload: bytes, *, force: bool) -> None:
    if path.exists() and not force:
        raise LiveCheckpointError("REPORT_EXISTS")
    _atomic_write(path, payload)


def _write_safe_report(path: Path, report: Mapping[str, object], *, force: bool) -> None:
    _write_report_bytes(path, _safe_report_bytes(report), force=force)


def _initialize_checkpoint(
    store: CheckpointStore,
    *,
    media_type: MediaKind,
    provider: Literal["google_gemini", "elevenlabs"],
    model: str,
    size: str | None,
    signer: Ed25519Signer,
    retention_days: int,
) -> MultimodalCheckpoint:
    issued_at = datetime.now(UTC)
    idempotency_key = f"live-multimodal-{provider}-{uuid4().hex}"
    run_id, asset_id, cert_id = _identifiers(idempotency_key)
    checkpoint = MultimodalCheckpoint(
        operation_state="request_ready",
        media_type=media_type,
        mime_type="image/png" if media_type == "image" else "audio/mpeg",
        file_extension="png" if media_type == "image" else "mp3",
        provider=provider,
        model=model,
        size=size,
        idempotency_key=idempotency_key,
        run_id=run_id,
        asset_id=asset_id,
        cert_id=cert_id,
        issued_at=issued_at,
        requested_retention_until=issued_at + timedelta(days=retention_days),
        signer_key_id=signer.signer_key_id,
    )
    store.write(checkpoint)
    return checkpoint


def _checkpoint_retry_allowed(checkpoint: MultimodalCheckpoint) -> bool:
    """Allow only a definitive rejection with no captured generation evidence."""
    return bool(
        checkpoint.operation_state == "provider_rejected"
        and checkpoint.provider_retry_allowed
        and checkpoint.provider_failure_code in _DEFINITIVE_RETRY_CODES
        and checkpoint.prior_rejected_calls == 1
        and checkpoint.source_sha256 is None
        and checkpoint.source_path is None
        and checkpoint.manifest_path is None
        and checkpoint.generated_metadata_path is None
    )


def _forbidden_openai_provider() -> NoReturn:
    raise LiveCheckpointError("CONFIGURATION_ERROR")


def _build_service_and_generate(
    settings: Settings,
    config: GenerateAndSealConfig,
    repository: Any,
    store: CheckpointStore,
    tracker: StageTracker,
    checkpoint: MultimodalCheckpoint,
    assets_client_holder: dict[str, Any],
    vault_client_holder: dict[str, Any],
) -> GenerateAndSealResult:
    def assets_factory() -> Any:
        if "client" not in assets_client_holder:
            assets_client_holder["client"] = create_assets_client(config.b2.assets)
        return assets_client_holder["client"]

    def vault_factory() -> Any:
        if "client" not in vault_client_holder:
            vault_client_holder["client"] = create_vault_client(config.b2.vault)
        return vault_client_holder["client"]

    def custody_executor(**kwargs: Any) -> B2CustodyReceipt:
        kwargs["persistence_callback"] = store.persist_partials
        return execute_b2_custody(**kwargs)

    if checkpoint.operation_state == "generated":
        recovered = _read_generated_media(checkpoint)
        gemini_factory: Callable[[], Any] | None = (
            (lambda: RecoveredImageProvider(recovered))
            if isinstance(recovered, GeneratedImage)
            else None
        )
        audio_factory: Callable[[], Any] | None = (
            (lambda: RecoveredAudioProvider(recovered))
            if isinstance(recovered, GeneratedAudio)
            else None
        )
    elif checkpoint.operation_state == "request_ready":
        if checkpoint.provider == GOOGLE_GEMINI_PROVIDER:
            if config.gemini_api_key is None:
                raise LiveCheckpointError("CONFIGURATION_ERROR")
            captured_gemini = CapturedGeminiProvider(
                GeminiImageProvider(
                    api_key=config.gemini_api_key.get_secret_value(),
                    timeout_seconds=config.generation_timeout_seconds,
                    max_image_bytes=config.max_generated_image_bytes,
                ),
                store,
                tracker,
            )
            def gemini_factory() -> CapturedGeminiProvider:
                return captured_gemini

            audio_factory = None
        else:
            if config.elevenlabs_api_key is None:
                raise LiveCheckpointError("CONFIGURATION_ERROR")
            captured_audio = CapturedElevenLabsProvider(
                ElevenLabsAudioProvider(
                    api_key=config.elevenlabs_api_key.get_secret_value(),
                    timeout_seconds=config.generation_timeout_seconds,
                    max_audio_bytes=config.max_generated_audio_bytes,
                ),
                store,
                tracker,
            )
            gemini_factory = None
            def audio_factory() -> CapturedElevenLabsProvider:
                return captured_audio
    else:
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
    runtime = build_runtime(
        settings,
        repository=repository,
        production_overrides={
            "provider_factory": _forbidden_openai_provider,
            "gemini_provider_factory": gemini_factory,
            "audio_provider_factory": audio_factory,
            "assets_client_factory": assets_factory,
            "vault_client_factory": vault_factory,
            "custody_executor": custody_executor,
            "stage_callback": tracker.core_stage,
            "checkpoint_callback": store.checkpoint_event,
            "now": lambda: checkpoint.issued_at,
        },
    )
    service = runtime.generate_and_seal_service
    if service is None:
        raise LiveCheckpointError("CONFIGURATION_ERROR")
    request = (
        GenerateAndSealRequest(
            media_type="image",
            provider=GOOGLE_GEMINI_PROVIDER,
            prompt=GEMINI_PROMPT,
            model=config.gemini_image_model,
            size=config.openai_image_size,
        )
        if checkpoint.media_type == "image"
        else GenerateAndSealRequest(
            media_type="audio",
            provider="elevenlabs",
            text=ELEVENLABS_TEXT,
            model_id=config.elevenlabs_model_id,
            voice_id=config.elevenlabs_voice_id,
        )
    )
    return service.generate_and_seal(request, idempotency_key=checkpoint.idempotency_key)


def _run_operation(
    settings: Settings,
    config: GenerateAndSealConfig,
    repository: Any,
    *,
    media_type: MediaKind,
    store: CheckpointStore,
) -> dict[str, object]:
    provider: Literal["google_gemini", "elevenlabs"] = (
        GOOGLE_GEMINI_PROVIDER if media_type == "image" else "elevenlabs"
    )
    model = config.gemini_image_model if media_type == "image" else config.elevenlabs_model_id
    stage_prefix = _stage_prefix(provider)
    tracker = StageTracker(store, stage_prefix)
    tracker.begin(f"{stage_prefix}_configuration_validation")
    signer = Ed25519Signer.from_private_key_base64(
        config.signing_private_key_b64.get_secret_value(), config.signing_public_key_b64
    )
    checkpoint = (
        store.read()
        if store.exists()
        else _initialize_checkpoint(
            store,
            media_type=media_type,
            provider=provider,
            model=model,
            size=config.openai_image_size if media_type == "image" else None,
            signer=signer,
            retention_days=config.b2.vault.retention_days,
        )
    )
    if (
        checkpoint.media_type != media_type
        or checkpoint.provider != provider
        or checkpoint.model != model
        or checkpoint.signer_key_id != signer.signer_key_id
    ):
        raise LiveCheckpointError("CONFIGURATION_ERROR")
    if checkpoint.operation_state == "provider_rejected":
        if not _checkpoint_retry_allowed(checkpoint):
            raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
        checkpoint = store.update(
            operation_state="request_ready",
            new_provider_calls=0,
            provider_failure_code=None,
            provider_retry_allowed=False,
            current_stage=None,
        )
    if checkpoint.operation_state == "request_ready" and checkpoint.new_provider_calls != 0:
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
    if checkpoint.operation_state == "provider_call_started":
        # The previous provider outcome is ambiguous or failed. Never issue a second call.
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
    assets_holder: dict[str, Any] = {}
    vault_holder: dict[str, Any] = {}
    if checkpoint.operation_state in {"request_ready", "generated"}:
        tracker.begin(f"{stage_prefix}_request_construction")
        _build_service_and_generate(
            settings,
            config,
            repository,
            store,
            tracker,
            checkpoint,
            assets_holder,
            vault_holder,
        )
        checkpoint = store.read()
    if checkpoint.operation_state == "request_ready":
        # The process may have lost a provider response before it was durably captured.
        # Fail closed instead of issuing an ambiguous second billable request.
        raise LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
    max_bytes = (
        config.max_generated_image_bytes
        if media_type == "image"
        else config.max_generated_audio_bytes
    )
    source, manifest_bytes, step = _load_private_evidence(checkpoint, max_bytes=max_bytes)
    generated_media = _read_generated_media(checkpoint)
    sealed, public_manifest = _reconstruct_sealed(
        checkpoint, source, public_base_url=config.public_base_url
    )
    assets_client = assets_holder.get("client") or create_assets_client(config.b2.assets)
    vault_client = vault_holder.get("client") or create_vault_client(config.b2.vault)
    custody = _load_or_create_custody(
        checkpoint,
        store,
        tracker,
        config,
        assets_client,
        vault_client,
        source,
        manifest_bytes,
    )
    checkpoint = store.read()
    sealed_receipt = _load_or_create_sealed(
        checkpoint, store, tracker, config, assets_client, sealed
    )
    checkpoint = store.read()
    if checkpoint.operation_state not in {"registered", "complete"}:
        _register_recovered(
            checkpoint,
            store,
            tracker,
            config,
            repository,
            custody,
            sealed_receipt,
            public_manifest,
            step,
            generated_media,
            sealed,
        )
        checkpoint = store.read()
    return _verify_and_deliver(
        checkpoint,
        store,
        tracker,
        config,
        repository,
        assets_client,
        sealed,
        public_manifest,
        settings.delivery_ttl_seconds,
    )


def _secret_values(config: GenerateAndSealConfig) -> list[str]:
    values = [
        config.admin_api_key.get_secret_value(),
        config.delivery_api_key.get_secret_value(),
        config.signing_private_key_b64.get_secret_value(),
        config.supabase.service_role_key.get_secret_value(),
        config.b2.assets.key_id.get_secret_value(),
        config.b2.assets.app_key.get_secret_value(),
        config.b2.vault.key_id.get_secret_value(),
        config.b2.vault.app_key.get_secret_value(),
    ]
    if config.gemini_api_key is not None:
        values.append(config.gemini_api_key.get_secret_value())
    if config.elevenlabs_api_key is not None:
        values.append(config.elevenlabs_api_key.get_secret_value())
    return values


def _run_sequential_operations(
    gemini_runner: Callable[[], dict[str, object]],
    elevenlabs_runner: Callable[[], dict[str, object]],
) -> tuple[dict[str, object], dict[str, object]]:
    """Keep audio uncalled when the prerequisite Gemini proof fails."""
    gemini = gemini_runner()
    elevenlabs = elevenlabs_runner()
    return gemini, elevenlabs


def _validate_multimodal_evidence(
    gemini: Mapping[str, object], elevenlabs: Mapping[str, object]
) -> None:
    """Prove both operations carry complete, distinct production evidence."""
    for operation, provider, media_type in (
        (gemini, GOOGLE_GEMINI_PROVIDER, "image"),
        (elevenlabs, "elevenlabs", "audio"),
    ):
        if operation.get("provider") != provider or operation.get("media_type") != media_type:
            raise LiveCheckpointError("VERIFICATION_FAILURE")
        if operation.get("ai_generated") is not True:
            raise LiveCheckpointError("VERIFICATION_FAILURE")
        for field in (
            "run_id",
            "asset_id",
            "cert_id",
            "source_sha256",
            "sealed_sha256",
            "canonical_hash",
            "signer_key_id",
            "sealed_asset_version_id",
            "vault_source_version_id",
            "vault_manifest_version_id",
        ):
            if not operation.get(field):
                raise LiveCheckpointError("VERIFICATION_FAILURE")
        declared = GEMINI_STAGES if media_type == "image" else ELEVENLABS_STAGES
        if _validated_stage_rows(operation.get("stages")) != declared:
            # Every declared stage must have run, exactly once, in order.
            raise LiveCheckpointError("VERIFICATION_FAILURE")
    if gemini.get("source_sha256") == gemini.get("sealed_sha256"):
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    if elevenlabs.get("source_sha256") != elevenlabs.get("sealed_sha256"):
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    if gemini.get("cert_id") == elevenlabs.get("cert_id"):
        raise LiveCheckpointError("VERIFICATION_FAILURE")


def _build_report(
    gemini: Mapping[str, object],
    elevenlabs: Mapping[str, object],
    *,
    new_gemini_calls: int,
    new_elevenlabs_calls: int,
) -> dict[str, object]:
    """Build the safe report. ``new_*_calls`` counts calls made by this process."""
    return {
        "schema_version": "firemark.multimodal-generate-and-seal-report.v1",
        "package_versions": {
            name: importlib.metadata.version(name)
            for name in ("firemark", "genblaze-core", "boto3", "supabase")
        },
        "gemini": dict(gemini),
        "elevenlabs": dict(elevenlabs),
        "production_gemini_evidence": True,
        "production_elevenlabs_evidence": True,
        "production_multimodal_evidence": True,
        "production_b2_custody_evidence": True,
        "production_supabase_evidence": True,
        "new_gemini_calls": new_gemini_calls,
        "new_elevenlabs_calls": new_elevenlabs_calls,
        "recorded_gemini_calls": gemini.get("new_provider_calls"),
        "recorded_elevenlabs_calls": elevenlabs.get("new_provider_calls"),
    }


def finalize(
    gemini: Mapping[str, object],
    elevenlabs: Mapping[str, object],
    report_path: Path,
    *,
    force: bool,
    new_gemini_calls: int,
    new_elevenlabs_calls: int,
    stage_callback: Callable[[str], None],
) -> dict[str, object]:
    """Validate evidence, serialize, scan and persist the report.

    Every step reports its own stage, so a finalization defect can never be
    attributed to a provider configuration stage.
    """
    stage_callback("multimodal_evidence_validation")
    _validate_multimodal_evidence(gemini, elevenlabs)
    if gemini.get("new_provider_calls") != 1 or elevenlabs.get("new_provider_calls") != 1:
        raise LiveCheckpointError("VERIFICATION_FAILURE")
    stage_callback("report_serialization")
    report = _build_report(
        gemini,
        elevenlabs,
        new_gemini_calls=new_gemini_calls,
        new_elevenlabs_calls=new_elevenlabs_calls,
    )
    stage_callback("report_secret_scan")
    payload = _safe_report_bytes(report)
    stage_callback("checkpoint_finalization")
    _write_report_bytes(report_path, payload, force=force)
    return report


def _checkpoint_failure_stage(path: Path, fallback: str) -> str:
    if not path.is_file():
        return fallback
    try:
        checkpoint = MultimodalCheckpoint.model_validate_json(path.read_bytes())
    except Exception:
        return fallback
    return checkpoint.current_stage or fallback


def resume_existing(report_path: Path, *, force: bool) -> int:
    """Finalize a completed live run without contacting any provider.

    Both checkpoints must already be ``complete``. No Gemini or ElevenLabs
    request is issued, no B2 object is written and no Supabase record is
    created; only the persisted safe evidence is validated and reported.
    """
    stage = "multimodal_evidence_validation"

    def mark(name: str) -> None:
        nonlocal stage
        stage = name
        print(f"PASS: {name}")

    try:
        gemini_store = CheckpointStore(
            DEFAULT_GEMINI_CHECKPOINT, DEFAULT_PRIVATE_ROOT / "gemini"
        )
        elevenlabs_store = CheckpointStore(
            DEFAULT_ELEVENLABS_CHECKPOINT, DEFAULT_PRIVATE_ROOT / "elevenlabs"
        )
        if not gemini_store.exists() or not elevenlabs_store.exists():
            raise LiveCheckpointError("INCOMPLETE_EVIDENCE")
        gemini_checkpoint = gemini_store.read()
        elevenlabs_checkpoint = elevenlabs_store.read()
        if (
            gemini_checkpoint.operation_state != "complete"
            or elevenlabs_checkpoint.operation_state != "complete"
        ):
            raise LiveCheckpointError("INCOMPLETE_EVIDENCE")
        report = finalize(
            _operation_report(gemini_checkpoint),
            _operation_report(elevenlabs_checkpoint),
            report_path,
            force=force,
            new_gemini_calls=0,
            new_elevenlabs_calls=0,
            stage_callback=mark,
        )
        print(f"NEW_GEMINI_CALLS={report['new_gemini_calls']}")
        print(f"NEW_ELEVENLABS_CALLS={report['new_elevenlabs_calls']}")
        print("PASS: safe_report")
        return 0
    except LiveCheckpointError as exc:
        category = exc.category
    except Exception:
        category = "SAFE_UNEXPECTED_FAILURE"
    print(f"FAIL: {stage} (CATEGORY={category})")
    return 1


def run_live(report_path: Path, *, force: bool) -> int:
    current_stage = "gemini_configuration_validation"

    def mark(name: str) -> None:
        nonlocal current_stage
        current_stage = name
        print(f"PASS: {name}")

    try:
        load_dotenv(DEFAULT_ENV_FILE, override=False)
        settings = load_settings()
        config = settings.require_generate_and_seal_config()
        settings.require_gemini_image_config()
        settings.require_elevenlabs_audio_config()
        settings.require_live_supabase_control_plane_config()
        repository = SupabaseCertificateRepository.from_config(config.supabase)
        print("NOTICE: one Gemini image and one ElevenLabs audio request may incur cost.")
        gemini_store = CheckpointStore(
            DEFAULT_GEMINI_CHECKPOINT, DEFAULT_PRIVATE_ROOT / "gemini"
        )
        elevenlabs_store = CheckpointStore(
            DEFAULT_ELEVENLABS_CHECKPOINT, DEFAULT_PRIVATE_ROOT / "elevenlabs"
        )

        def run_gemini() -> dict[str, object]:
            nonlocal current_stage
            current_stage = "gemini_configuration_validation"
            return _run_operation(
                settings, config, repository, media_type="image", store=gemini_store
            )

        def run_elevenlabs() -> dict[str, object]:
            nonlocal current_stage
            current_stage = "elevenlabs_configuration_validation"
            return _run_operation(
                settings,
                config,
                repository,
                media_type="audio",
                store=elevenlabs_store,
            )

        gemini, elevenlabs = _run_sequential_operations(
            run_gemini,
            run_elevenlabs,
        )
        current_stage = "multimodal_database_secret_scan"
        _database_secret_scan(repository, gemini_store.read(), _secret_values(config))
        _database_secret_scan(repository, elevenlabs_store.read(), _secret_values(config))
        report = finalize(
            gemini,
            elevenlabs,
            report_path,
            force=force,
            new_gemini_calls=gemini_store.read().new_provider_calls,
            new_elevenlabs_calls=elevenlabs_store.read().new_provider_calls,
            stage_callback=mark,
        )
        print(f"NEW_GEMINI_CALLS={report['new_gemini_calls']}")
        print(f"NEW_ELEVENLABS_CALLS={report['new_elevenlabs_calls']}")
        print("PASS: safe_report")
        return 0
    except GenerationProviderError as exc:
        category = _PROVIDER_CATEGORIES.get(exc.code, "SAFE_UNEXPECTED_FAILURE")
    except B2CustodyWorkflowError:
        category = "B2_CUSTODY_FAILURE"
    except B2Error:
        category = "B2_CUSTODY_FAILURE"
    except RepositoryError:
        category = "REGISTRATION_FAILURE"
    except LiveCheckpointError as exc:
        category = exc.category
    except (httpx.TimeoutException, TimeoutError):
        category = "TIMEOUT"
    except Exception:
        category = "SAFE_UNEXPECTED_FAILURE"
    if current_stage in FINALIZATION_STAGES or current_stage.startswith("multimodal_"):
        # A terminal defect belongs to its own stage. Reusing a per-operation
        # checkpoint here is what previously reported a completed ElevenLabs run
        # as a configuration failure.
        failure_stage = current_stage
    else:
        checkpoint_path = (
            DEFAULT_ELEVENLABS_CHECKPOINT
            if current_stage.startswith("elevenlabs")
            else DEFAULT_GEMINI_CHECKPOINT
        )
        failure_stage = _checkpoint_failure_stage(checkpoint_path, current_stage)
    print(f"FAIL: {failure_stage} (CATEGORY={category})")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one recovery-safe Gemini image and ElevenLabs audio Generate & Seal checkpoint."
        )
    )
    parser.add_argument("--live", action="store_true", help="Allow real calls and provider cost.")
    parser.add_argument(
        "--output-report", type=Path, default=DEFAULT_REPORT, help="Safe JSON report path."
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing report.")
    parser.add_argument(
        "--resume-existing",
        action="store_true",
        help=(
            "Finalize an already completed run from its persisted checkpoints. "
            "Issues zero Gemini and zero ElevenLabs generation requests. It needs "
            "--live only when a stage is still incomplete and remote reads are required."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.resume_existing and not args.live:
        print("INFO: resuming from persisted checkpoints; no provider request is issued.")
        print("INFO: no Gemini, ElevenLabs, B2, or Supabase client was constructed.")
        return resume_existing(args.output_report, force=args.force)
    if not args.live:
        print("INFO: --live not supplied; zero network calls were made.")
        print("INFO: no Gemini, ElevenLabs, B2, or Supabase client was constructed.")
        return INFORMATIONAL_EXIT_CODE
    if args.resume_existing:
        print("NOTICE: resuming incomplete stages; no new provider request is issued.")
    return run_live(args.output_report, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
