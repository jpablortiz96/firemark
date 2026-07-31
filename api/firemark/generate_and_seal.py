"""Generate & Seal orchestration joining provenance, custody, signing, and registration."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from genblaze_core import Manifest, Modality, RunBuilder, RunStatus, StepBuilder, StepStatus
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator, model_validator

from api.firemark.b2_storage import sealed_asset_key, upload_bytes_verified
from api.firemark.control_plane.models import AssetRecord, CustodyRecord, GenerationRunRecord
from api.firemark.control_plane.service import CertificateService
from api.firemark.custody import B2CustodyReceipt, StoredObjectReceipt, execute_b2_custody
from api.firemark.generation.models import (
    PNG_MAGIC,
    AudioGenerationRequest,
    GeneratedImage,
    GeneratedMedia,
    GenerationRequest,
    MediaType,
)
from api.firemark.generation.normalization import ImageNormalizationError, normalize_to_png
from api.firemark.generation.provider import AudioGenerationProvider, GenerationProvider
from api.firemark.generation.provider_identity import (
    GOOGLE_GEMINI_PROVIDER,
    normalize_provider,
    provider_model_display_name,
)
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import (
    FiremarkPublicAudioReferenceV1,
    FiremarkPublicCapsuleV1,
    embed_public_capsule_png,
)
from api.firemark.seal_envelope import SealEnvelopeV1, sign_envelope
from api.firemark.signer import Ed25519Signer

_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_REQUEST_FINGERPRINT_FIELD = "_firemark_request_fingerprint"


class GenerateAndSealError(RuntimeError):
    """Safe orchestration failure with optional non-secret persisted locations."""

    def __init__(self, code: str, *, partial_keys: tuple[str, ...] = ()) -> None:
        super().__init__(f"Generate & Seal failed: {code}")
        self.code = code
        self.partial_keys = partial_keys


class IdempotencyConflictError(GenerateAndSealError):
    """The idempotency key already identifies a different private request."""

    def __init__(self) -> None:
        super().__init__("IDEMPOTENCY_CONFLICT")


class GenerateAndSealRequest(BaseModel):
    """Private, closed multimedia generation payload."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    media_type: MediaType = "image"
    provider: Literal["openai", "google_gemini", "elevenlabs"] | None = None
    prompt: str | None = Field(default=None, min_length=1, max_length=4000, repr=False)
    text: str | None = Field(default=None, min_length=1, max_length=5000, repr=False)
    model: str | None = None
    model_id: str | None = None
    size: str | None = None
    voice_id: str | None = None

    @field_validator("prompt", "text")
    @classmethod
    def normalize_private_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Generation text must not be blank")
        return normalized

    @field_validator("provider", mode="before")
    @classmethod
    def normalize_provider_alias(cls, value: object) -> object:
        """Accept the historical `gemini` label but store the accurate identity."""
        return normalize_provider(value) if isinstance(value, str) else value

    @field_validator("model", "model_id", "voice_id")
    @classmethod
    def validate_optional_model(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value):
            raise ValueError("Generation model identifier is unsafe")
        return value

    @model_validator(mode="after")
    def validate_media_request(self) -> GenerateAndSealRequest:
        if self.media_type == "image":
            if self.provider == "elevenlabs":
                raise ValueError("Image generation requires OpenAI or Google Gemini")
            if self.prompt is None or self.text is not None:
                raise ValueError("Image generation requires prompt and forbids text")
            if self.voice_id is not None or self.model_id is not None:
                raise ValueError("Image generation forbids audio parameters")
        else:
            if self.provider not in {None, "elevenlabs"}:
                raise ValueError("Audio generation requires ElevenLabs")
            if self.text is None or self.prompt is not None:
                raise ValueError("Audio generation requires text and forbids prompt")
            if self.size is not None or self.model is not None:
                raise ValueError("Audio generation forbids image parameters")
        return self

    @field_validator("size")
    @classmethod
    def validate_optional_size(cls, value: str | None) -> str | None:
        allowed = {
            "auto",
            "256x256",
            "512x512",
            "1024x1024",
            "1536x1024",
            "1024x1536",
            "1792x1024",
            "1024x1792",
        }
        if value is not None and value not in allowed:
            raise ValueError("Generation image size is unsupported")
        return value


class GenerateAndSealResult(BaseModel):
    """Safe completed result returned by the authenticated generation endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["sealed"] = "sealed"
    run_id: str
    asset_id: str
    cert_id: str
    provider: str
    model: str
    provider_model_name: str | None = None
    media_type: MediaType
    mime_type: str
    byte_size: int = Field(gt=0)
    ai_generated: bool
    width: int | None = Field(default=None, gt=0)
    height: int | None = Field(default=None, gt=0)
    duration_ms: int | None = Field(default=None, gt=0)
    source_sha256: str
    sealed_sha256: str
    canonical_hash: str
    certificate_url: AnyHttpUrl
    verify_url: AnyHttpUrl
    delivery_url: None = None


ProviderFactory = Callable[[], GenerationProvider]
AudioProviderFactory = Callable[[], AudioGenerationProvider]
ClientFactory = Callable[[], Any]
SignerFactory = Callable[[], Ed25519Signer]
CustodyExecutor = Callable[..., B2CustodyReceipt]
SealedUploader = Callable[..., StoredObjectReceipt]
StageCallback = Callable[[str], None]
CheckpointCallback = Callable[[str, dict[str, Any]], None]


def _request_fingerprint(
    values: dict[str, str | None] | str,
    model: str | None = None,
    size: str | None = None,
) -> str:
    if isinstance(values, str):
        values = {"model": model, "private_text": values, "size": size}
    payload = json.dumps(
        values,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256_bytes(payload)


def _identifiers(idempotency_key: str) -> tuple[str, str, str]:
    if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
        raise GenerateAndSealError("INVALID_IDEMPOTENCY_KEY")

    def identifier(kind: str) -> str:
        digest = hashlib.sha256(f"firemark:{kind}:{idempotency_key}".encode()).hexdigest()
        return f"firemark-{kind}-{digest[:32]}"

    return identifier("run"), identifier("asset"), identifier("cert")


SEALED_IMAGE_MIME_TYPE = "image/png"
SEALED_IMAGE_EXTENSION = "png"
NORMALIZATION_PURPOSE = "firemark_public_capsule_embedding"


@dataclass(frozen=True)
class _PngCarrier:
    """The PNG bytes the public capsule is embedded into.

    A PNG source is carried through untouched so existing evidence stays byte
    identical. A non-PNG source is decoded and deterministically re-encoded; the
    original source bytes are never modified and still define ``source_sha256``.
    """

    data: bytes
    record: dict[str, str] | None


def _png_carrier(media: GeneratedImage, *, stage_callback: StageCallback) -> _PngCarrier:
    if media.source_mime_type == SEALED_IMAGE_MIME_TYPE:
        return _PngCarrier(data=media.data, record=None)
    stage_callback("deterministic_png_normalization")
    try:
        normalized = normalize_to_png(media.data, source_mime_type=media.source_mime_type)
    except ImageNormalizationError as exc:
        raise GenerateAndSealError(f"IMAGE_NORMALIZATION_{exc.code.upper()}") from None
    stage_callback("normalized_png_validation")
    if not normalized.data.startswith(PNG_MAGIC):
        raise GenerateAndSealError("IMAGE_NORMALIZATION_NON_PNG_NORMALIZED_OUTPUT")
    return _PngCarrier(
        data=normalized.data,
        record={
            "operation": "normalize_image",
            "input_mime_type": media.source_mime_type,
            "output_mime_type": normalized.mime_type,
            "purpose": NORMALIZATION_PURPOSE,
        },
    )


def _build_manifest(
    media: GeneratedMedia,
    private_text: str | GenerationRequest,
    provider_parameters: dict[str, str | int | float | bool] | None = None,
    *,
    run_id: str,
    source_sha256: str,
    normalization: dict[str, str] | None = None,
) -> Manifest:
    if isinstance(private_text, GenerationRequest):
        provider_parameters = private_text.provider_parameters
        private_text = private_text.prompt
    provider_parameters = provider_parameters or {}
    builder = (
        StepBuilder(media.provider, media.model)
        .prompt(private_text)
        .modality(Modality.IMAGE if isinstance(media, GeneratedImage) else Modality.AUDIO)
        .status(StepStatus.SUCCEEDED)
        .params(**provider_parameters)
        .asset(
            f"urn:sha256:{source_sha256}",
            media.media_type,
            sha256=source_sha256,
            size_bytes=len(media.data),
        )
        .meta(
            ai_generated=media.ai_generated,
            provider_request_id=media.provider_request_id,
            provider_created_at=media.provider_created_at.isoformat(),
            **media.safe_generation_metadata,
            **(
                {"firemark_normalization": dict(normalization)}
                if normalization is not None
                else {}
            ),
        )
    )
    if isinstance(media, GeneratedImage) and media.seed is not None:
        builder = builder.seed(media.seed)
    step = builder.build()
    run = (
        RunBuilder("FIREMARK Generate & Seal")
        .run_id(run_id)
        .status(RunStatus.COMPLETED)
        .add_step(step)
        .meta(ai_generated=media.ai_generated, firemark_generate_and_seal=True)
        .build()
    )
    manifest = Manifest.from_run(run)
    if not manifest.verify():
        raise GenerateAndSealError("GENBLAZE_MANIFEST_INVALID")
    return manifest


def _png_dimensions(data: bytes) -> tuple[int, int]:
    """Read the validated PNG IHDR dimensions without decoding pixels."""
    if len(data) < 24 or data[12:16] != b"IHDR":
        raise GenerateAndSealError("GENERATED_IMAGE_MALFORMED")
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    if width < 1 or height < 1:
        raise GenerateAndSealError("GENERATED_IMAGE_MALFORMED")
    return width, height


class GenerateAndSealService:
    """Synchronous production workflow with fully injectable external boundaries."""

    def __init__(
        self,
        *,
        certificate_service: CertificateService,
        provider_factory: ProviderFactory | None,
        signer_factory: SignerFactory,
        assets_client_factory: ClientFactory,
        vault_client_factory: ClientFactory,
        assets_bucket: str,
        vault_bucket: str,
        retention_days: int,
        public_base_url: str,
        default_model: str,
        default_size: str,
        max_generated_image_bytes: int,
        generation_timeout_seconds: int,
        allow_local_fixture: bool = False,
        custody_executor: CustodyExecutor = execute_b2_custody,
        sealed_uploader: SealedUploader = upload_bytes_verified,
        now: Callable[[], datetime] | None = None,
        stage_callback: StageCallback | None = None,
        checkpoint_callback: CheckpointCallback | None = None,
        gemini_provider_factory: ProviderFactory | None = None,
        audio_provider_factory: AudioProviderFactory | None = None,
        default_gemini_model: str = "gemini-3.1-flash-image",
        default_audio_model: str = "eleven_multilingual_v2",
        default_audio_voice_id: str | None = None,
        max_generated_audio_bytes: int = 50 * 1024 * 1024,
    ) -> None:
        self.certificate_service = certificate_service
        self.provider_factory = provider_factory
        self.gemini_provider_factory = gemini_provider_factory
        self.audio_provider_factory = audio_provider_factory
        self.signer_factory = signer_factory
        self.assets_client_factory = assets_client_factory
        self.vault_client_factory = vault_client_factory
        self.assets_bucket = assets_bucket
        self.vault_bucket = vault_bucket
        self.retention_days = retention_days
        self.public_base_url = public_base_url.rstrip("/")
        self.default_model = default_model
        self.default_size = default_size
        self.max_generated_image_bytes = max_generated_image_bytes
        self.max_generated_audio_bytes = max_generated_audio_bytes
        self.default_gemini_model = default_gemini_model
        self.default_audio_model = default_audio_model
        self.default_audio_voice_id = default_audio_voice_id
        self.generation_timeout_seconds = generation_timeout_seconds
        self.allow_local_fixture = allow_local_fixture
        self.custody_executor = custody_executor
        self.sealed_uploader = sealed_uploader
        self._now = now or (lambda: datetime.now(UTC))
        self._stage_callback = stage_callback or (lambda _stage: None)
        self._checkpoint_callback = checkpoint_callback or (lambda _event, _values: None)
        self._lock = threading.Lock()

    def _completed(self, cert_id: str, run_id: str, asset_id: str) -> GenerateAndSealResult | None:
        certificate = self.certificate_service.repository.get_certificate(cert_id)
        if certificate is None:
            return None
        return GenerateAndSealResult.model_validate(
            {
                "run_id": run_id,
                "asset_id": asset_id,
                "cert_id": cert_id,
                "provider": certificate.provider,
                "model": certificate.model,
                "provider_model_name": provider_model_display_name(
                    certificate.provider, certificate.model
                ),
                "media_type": certificate.media_type,
                "mime_type": certificate.mime_type,
                "byte_size": certificate.byte_size,
                "ai_generated": certificate.ai_generated,
                "width": certificate.width,
                "height": certificate.height,
                "duration_ms": certificate.duration_ms,
                "source_sha256": certificate.source_sha256,
                "sealed_sha256": certificate.sealed_sha256,
                "canonical_hash": certificate.canonical_hash,
                "certificate_url": f"{self.public_base_url}/v1/certificates/{cert_id}",
                "verify_url": f"{self.public_base_url}/v1/certificates/{cert_id}",
            }
        )

    def generate_and_seal(
        self,
        request: GenerateAndSealRequest,
        *,
        idempotency_key: str,
    ) -> GenerateAndSealResult:
        media_type = request.media_type
        provider_name = request.provider or ("openai" if media_type == "image" else "elevenlabs")
        if media_type == "image":
            private_text = request.prompt
            assert private_text is not None
            model = request.model or (
                self.default_gemini_model
                if provider_name == GOOGLE_GEMINI_PROVIDER
                else self.default_model
            )
            size = request.size or self.default_size
            voice_id = None
        else:
            private_text = request.text
            assert private_text is not None
            model = request.model_id or self.default_audio_model
            size = None
            voice_id = request.voice_id or self.default_audio_voice_id
            if voice_id is None:
                raise GenerateAndSealError("PROVIDER_NOT_CONFIGURED")
        run_id, asset_id, cert_id = _identifiers(idempotency_key)
        fingerprint = _request_fingerprint(
            {
                "media_type": media_type,
                "provider": provider_name,
                "private_text": private_text,
                "model": model,
                "size": size,
                "voice_id": voice_id,
            }
        )
        with self._lock:
            self._stage_callback("dependency_construction")
            completed = self._completed(cert_id, run_id, asset_id)
            if completed is not None:
                stored = self.certificate_service.repository.get_generation_request_fingerprint(
                    run_id
                )
                if stored is None or not hmac.compare_digest(stored, fingerprint):
                    raise IdempotencyConflictError
                return completed
            timestamp = self._now().astimezone(UTC)
            self._stage_callback("provider_request_construction")
            provider_parameters: dict[str, str | int | float | bool]
            if media_type == "image":
                assert size is not None
                provider_request = GenerationRequest(
                    prompt=private_text,
                    model=model,
                    size=size,
                    request_id=run_id,
                )
                factory = (
                    self.gemini_provider_factory
                    if provider_name == GOOGLE_GEMINI_PROVIDER
                    else self.provider_factory
                )
                if factory is None:
                    raise GenerateAndSealError("PROVIDER_NOT_CONFIGURED")
                media: GeneratedMedia = factory().generate_image(provider_request)
                provider_parameters = {"requested_size": size}
            else:
                assert voice_id is not None
                audio_request = AudioGenerationRequest(
                    text=private_text,
                    model=model,
                    voice_id=voice_id,
                    request_id=run_id,
                )
                if self.audio_provider_factory is None:
                    raise GenerateAndSealError("PROVIDER_NOT_CONFIGURED")
                media = self.audio_provider_factory().generate_audio(audio_request)
                provider_parameters = {"voice_id": voice_id}
            self._stage_callback("provider_response_validation")
            if media.ai_generated and media.provider != provider_name:
                raise GenerateAndSealError("PROVIDER_IDENTITY_MISMATCH")
            if not media.ai_generated and not self.allow_local_fixture:
                raise GenerateAndSealError("NON_PRODUCTION_PROVIDER")
            byte_limit = (
                self.max_generated_image_bytes
                if media_type == "image"
                else self.max_generated_audio_bytes
            )
            if len(media.data) > byte_limit:
                raise GenerateAndSealError("GENERATED_MEDIA_TOO_LARGE")
            self._stage_callback("source_hash")
            source_sha256 = sha256_bytes(media.data)
            carrier = (
                _png_carrier(media, stage_callback=self._stage_callback)
                if isinstance(media, GeneratedImage)
                else None
            )
            self._stage_callback("genblaze_manifest")
            manifest = _build_manifest(
                media,
                private_text,
                provider_parameters,
                run_id=run_id,
                source_sha256=source_sha256,
                normalization=carrier.record if carrier is not None else None,
            )
            manifest_bytes = manifest.to_canonical_json().encode("utf-8")
            self._stage_callback("canonical_hash")
            canonical_hash = manifest.canonical_hash
            signer = self.signer_factory()
            if not signer.can_sign:
                raise GenerateAndSealError("SIGNING_KEY_UNAVAILABLE")
            public_values = {
                "cert_id": cert_id,
                "asset_id": asset_id,
                "run_id": run_id,
                "canonical_hash": canonical_hash,
                "source_sha256": source_sha256,
                "signer_key_id": signer.signer_key_id,
                "verify_url": f"{self.public_base_url}/v1/certificates/{cert_id}",
                "issued_at": timestamp,
            }
            width: int | None
            height: int | None
            if isinstance(media, GeneratedImage):
                assert carrier is not None
                self._stage_callback("public_capsule_embedding")
                capsule = FiremarkPublicCapsuleV1.model_validate(public_values)
                sealed_bytes = embed_public_capsule_png(carrier.data, capsule)
                public_manifest: dict[str, object] = capsule.model_dump(mode="json")
                width, height = _png_dimensions(carrier.data)
                duration_ms = None
                sealed_mime_type = SEALED_IMAGE_MIME_TYPE
                sealed_extension = SEALED_IMAGE_EXTENSION
            else:
                self._stage_callback("public_reference_construction")
                sealed_bytes = media.data
                width = height = None
                duration_ms = media.duration_ms
                sealed_mime_type = media.media_type
                sealed_extension = media.file_extension
            self._stage_callback("sealed_hash")
            sealed_sha256 = sha256_bytes(sealed_bytes)
            if media_type == "image" and hmac.compare_digest(source_sha256, sealed_sha256):
                raise GenerateAndSealError("SEALED_HASH_UNCHANGED")
            if media_type == "audio":
                audio_reference = FiremarkPublicAudioReferenceV1.model_validate(
                    {**public_values, "sealed_sha256": sealed_sha256}
                )
                public_manifest = audio_reference.model_dump(mode="json")
            retention_until = timestamp + timedelta(days=self.retention_days)
            self._checkpoint_callback(
                "prepared",
                {
                    "run_id": run_id,
                    "asset_id": asset_id,
                    "cert_id": cert_id,
                    "source_sha256": source_sha256,
                    "sealed_sha256": sealed_sha256,
                    "canonical_hash": canonical_hash,
                    "issued_at": timestamp,
                    "requested_retention_until": retention_until,
                    "signer_key_id": signer.signer_key_id,
                    "provider": media.provider,
                    "model": media.model,
                    "media_type": media_type,
                    "mime_type": sealed_mime_type,
                    "file_extension": sealed_extension,
                    "source_mime_type": media.media_type,
                    "source_extension": media.file_extension,
                    "size": size,
                    "voice_id": voice_id,
                    "source_bytes": media.data,
                    "manifest_bytes": manifest_bytes,
                },
            )
            self._stage_callback("vault_source_upload")
            assets_client = self.assets_client_factory()
            vault_client = self.vault_client_factory()
            with tempfile.TemporaryDirectory(prefix="firemark-generate-") as directory:
                source_path = Path(directory) / f"source.{media.file_extension}"
                source_path.write_bytes(media.data)
                custody_receipt = self.custody_executor(
                    assets_client=assets_client,
                    vault_client=vault_client,
                    assets_bucket=self.assets_bucket,
                    vault_bucket=self.vault_bucket,
                    source_path=source_path,
                    manifest_bytes=manifest_bytes,
                    source_sha256=source_sha256,
                    canonical_hash=canonical_hash,
                    run_id=run_id,
                    cert_id=cert_id,
                    extension=media.file_extension,
                    retention_until=retention_until,
                    source_content_type=media.media_type,
                    now=timestamp,
                    stage_callback=self._stage_callback,
                )
            self._checkpoint_callback("custody_persisted", {"custody_receipt": custody_receipt})
            self._stage_callback("sealed_asset_upload")
            sealed_key = sealed_asset_key(sealed_sha256, sealed_extension)
            sealed_receipt = self.sealed_uploader(
                assets_client,
                bucket=self.assets_bucket,
                key=sealed_key,
                data=sealed_bytes,
                expected_sha256=sealed_sha256,
                content_type=sealed_mime_type,
                metadata={
                    "firemark-kind": "sealed",
                    "firemark-schema": "1",
                    "firemark-cert-id": cert_id,
                },
                known_unlocked=True,
                stage_callback=self._stage_callback,
                upload_stage="sealed_asset_upload",
                hash_verification_stage="sealed_asset_hash_verification",
            )
            if sealed_receipt.version_id is None:
                raise GenerateAndSealError("SEALED_VERSION_UNAVAILABLE", partial_keys=(sealed_key,))
            self._checkpoint_callback("sealed_persisted", {"sealed_receipt": sealed_receipt})
            self._stage_callback("custody_receipt_construction")
            if sealed_receipt.sha256 != sealed_sha256:
                raise GenerateAndSealError("SEALED_HASH_MISMATCH")
            if not custody_receipt.custody_verified:
                raise GenerateAndSealError("CUSTODY_NOT_VERIFIED")
            vault_source_version = custody_receipt.vault_source.version_id
            vault_manifest_version = custody_receipt.vault_manifest.version_id
            if vault_source_version is None or vault_manifest_version is None:
                raise GenerateAndSealError("CUSTODY_VERSION_UNAVAILABLE")
            self._stage_callback("envelope_signature")
            generation_run = GenerationRunRecord(
                run_id=run_id,
                provider=media.provider,
                model=media.model,
                ai_generated=media.ai_generated,
                prompt_private=private_text,
                parameters_private={
                    _REQUEST_FINGERPRINT_FIELD: fingerprint,
                    "requested_size": size,
                    "voice_id": voice_id,
                    "media_type": media_type,
                    "provider_source_mime_type": (
                        media.source_mime_type if isinstance(media, GeneratedImage) else None
                    ),
                    "normalization": carrier.record if carrier is not None else None,
                    "provider": media.safe_generation_metadata,
                },
                seed_private=media.seed if isinstance(media, GeneratedImage) else None,
                canonical_hash=canonical_hash,
                manifest_storage_key=custody_receipt.assets_manifest.key,
                manifest_version_id=custody_receipt.assets_manifest.version_id,
                created_at=timestamp,
            )
            asset = AssetRecord(
                asset_id=asset_id,
                run_id=run_id,
                asset_type=media_type,
                media_type=sealed_mime_type,
                file_extension=sealed_extension,
                byte_size=len(sealed_bytes),
                width=width,
                height=height,
                duration_ms=duration_ms,
                source_sha256=source_sha256,
                sealed_sha256=sealed_sha256,
                assets_bucket=sealed_receipt.bucket,
                assets_key=sealed_receipt.key,
                assets_version_id=sealed_receipt.version_id,
                vault_bucket=custody_receipt.vault_source.bucket,
                vault_key=custody_receipt.vault_source.key,
                vault_version_id=vault_source_version,
                created_at=timestamp,
            )
            custody = CustodyRecord(
                asset_id=asset_id,
                custody_receipt=custody_receipt,
                retention_mode="COMPLIANCE",
                retention_until=custody_receipt.vault_source.retention_until,
                custody_verified=True,
                created_at=timestamp,
            )
            envelope = SealEnvelopeV1(
                cert_id=cert_id,
                run_id=run_id,
                canonical_hash=canonical_hash,
                source_sha256=source_sha256,
                sealed_sha256=sealed_sha256,
                sealed_asset_bucket=sealed_receipt.bucket,
                sealed_asset_key=sealed_receipt.key,
                public_manifest_bucket=sealed_receipt.bucket,
                public_manifest_key=sealed_receipt.key,
                vault_bucket=custody_receipt.vault_source.bucket,
                vault_source_key=custody_receipt.vault_source.key,
                vault_source_version_id=vault_source_version,
                vault_manifest_key=custody_receipt.vault_manifest.key,
                vault_manifest_version_id=vault_manifest_version,
                retention_until=custody_receipt.vault_source.retention_until,
                signer_key_id=signer.signer_key_id,
                created_at=timestamp,
            )
            signed = sign_envelope(envelope, signer)
            self._stage_callback("supabase_registration")
            try:
                self.certificate_service.register_certificate(
                    generation_run=generation_run,
                    asset=asset,
                    custody=custody,
                    envelope=envelope,
                    signature_b64=signed.signature,
                    signer_public_key_b64=signer.export_public_key_base64(),
                    public_manifest=public_manifest,
                    canonical_hash=canonical_hash,
                    cert_id=cert_id,
                    asset_id=asset_id,
                    run_id=run_id,
                )
                self._checkpoint_callback("registered", {})
            except Exception as exc:
                partial = (
                    sealed_key,
                    custody_receipt.vault_source.key,
                    custody_receipt.vault_manifest.key,
                )
                raise GenerateAndSealError("REGISTRATION_FAILED", partial_keys=partial) from exc
            completed = self._completed(cert_id, run_id, asset_id)
            if completed is None:
                raise GenerateAndSealError("REGISTRATION_NOT_VISIBLE")
            return completed
