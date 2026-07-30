"""Generate & Seal orchestration joining provenance, custody, signing, and registration."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import tempfile
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from genblaze_core import Manifest, Modality, RunBuilder, RunStatus, StepBuilder, StepStatus
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator

from api.firemark.b2_storage import sealed_asset_key, upload_bytes_verified
from api.firemark.control_plane.models import AssetRecord, CustodyRecord, GenerationRunRecord
from api.firemark.control_plane.service import CertificateService
from api.firemark.custody import B2CustodyReceipt, StoredObjectReceipt, execute_b2_custody
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.provider import GenerationProvider
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import FiremarkPublicCapsuleV1, embed_public_capsule_png
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
    """Private HTTP generation payload; prompt is excluded from representations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt: str = Field(min_length=1, max_length=4000, repr=False)
    model: str | None = None
    size: str | None = None

    @field_validator("prompt")
    @classmethod
    def normalize_prompt(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Prompt must not be blank")
        return normalized

    @field_validator("model")
    @classmethod
    def validate_optional_model(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value):
            raise ValueError("Generation model identifier is unsafe")
        return value

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
    source_sha256: str
    sealed_sha256: str
    canonical_hash: str
    certificate_url: AnyHttpUrl
    verify_url: AnyHttpUrl
    delivery_url: None = None


ProviderFactory = Callable[[], GenerationProvider]
ClientFactory = Callable[[], Any]
SignerFactory = Callable[[], Ed25519Signer]
CustodyExecutor = Callable[..., B2CustodyReceipt]
SealedUploader = Callable[..., StoredObjectReceipt]
StageCallback = Callable[[str], None]


def _request_fingerprint(prompt: str, model: str, size: str) -> str:
    payload = json.dumps(
        {"model": model, "prompt": prompt, "size": size},
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


def _build_manifest(
    image: GeneratedImage,
    request: GenerationRequest,
    *,
    run_id: str,
    source_sha256: str,
) -> Manifest:
    builder = (
        StepBuilder(image.provider, image.model)
        .prompt(request.prompt)
        .modality(Modality.IMAGE)
        .status(StepStatus.SUCCEEDED)
        .params(**request.provider_parameters)
        .asset(
            f"urn:sha256:{source_sha256}",
            image.media_type,
            sha256=source_sha256,
            size_bytes=len(image.data),
        )
        .meta(
            ai_generated=image.ai_generated,
            provider_request_id=image.provider_request_id,
            provider_created_at=image.provider_created_at.isoformat(),
            **image.safe_generation_metadata,
        )
    )
    if image.seed is not None:
        builder = builder.seed(image.seed)
    step = builder.build()
    run = (
        RunBuilder("FIREMARK Generate & Seal")
        .run_id(run_id)
        .status(RunStatus.COMPLETED)
        .add_step(step)
        .meta(ai_generated=image.ai_generated, firemark_generate_and_seal=True)
        .build()
    )
    manifest = Manifest.from_run(run)
    if not manifest.verify():
        raise GenerateAndSealError("GENBLAZE_MANIFEST_INVALID")
    return manifest


class GenerateAndSealService:
    """Synchronous production workflow with fully injectable external boundaries."""

    def __init__(
        self,
        *,
        certificate_service: CertificateService,
        provider_factory: ProviderFactory,
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
    ) -> None:
        self.certificate_service = certificate_service
        self.provider_factory = provider_factory
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
        self.generation_timeout_seconds = generation_timeout_seconds
        self.allow_local_fixture = allow_local_fixture
        self.custody_executor = custody_executor
        self.sealed_uploader = sealed_uploader
        self._now = now or (lambda: datetime.now(UTC))
        self._stage_callback = stage_callback or (lambda _stage: None)
        self._lock = threading.Lock()

    def _completed(
        self, cert_id: str, run_id: str, asset_id: str
    ) -> GenerateAndSealResult | None:
        certificate = self.certificate_service.repository.get_certificate(cert_id)
        if certificate is None:
            return None
        return GenerateAndSealResult.model_validate(
            {
                "run_id": run_id,
                "asset_id": asset_id,
                "cert_id": cert_id,
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
        model = request.model or self.default_model
        size = request.size or self.default_size
        run_id, asset_id, cert_id = _identifiers(idempotency_key)
        fingerprint = _request_fingerprint(request.prompt, model, size)
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
            provider_request = GenerationRequest(
                prompt=request.prompt,
                model=model,
                size=size,
                request_id=run_id,
            )
            image = self.provider_factory().generate_image(provider_request)
            self._stage_callback("provider_response_validation")
            if not image.ai_generated and not self.allow_local_fixture:
                raise GenerateAndSealError("NON_PRODUCTION_PROVIDER")
            if len(image.data) > self.max_generated_image_bytes:
                raise GenerateAndSealError("GENERATED_IMAGE_TOO_LARGE")
            self._stage_callback("source_hash")
            source_sha256 = sha256_bytes(image.data)
            self._stage_callback("genblaze_manifest")
            manifest = _build_manifest(
                image,
                provider_request,
                run_id=run_id,
                source_sha256=source_sha256,
            )
            manifest_bytes = manifest.to_canonical_json().encode("utf-8")
            self._stage_callback("canonical_hash")
            canonical_hash = manifest.canonical_hash
            self._stage_callback("public_capsule_embedding")
            signer = self.signer_factory()
            if not signer.can_sign:
                raise GenerateAndSealError("SIGNING_KEY_UNAVAILABLE")
            capsule = FiremarkPublicCapsuleV1.model_validate(
                {
                    "cert_id": cert_id,
                    "asset_id": asset_id,
                    "run_id": run_id,
                    "canonical_hash": canonical_hash,
                    "source_sha256": source_sha256,
                    "signer_key_id": signer.signer_key_id,
                    "verify_url": f"{self.public_base_url}/v1/certificates/{cert_id}",
                    "issued_at": timestamp,
                }
            )
            sealed_bytes = embed_public_capsule_png(image.data, capsule)
            self._stage_callback("sealed_hash")
            sealed_sha256 = sha256_bytes(sealed_bytes)
            if hmac.compare_digest(source_sha256, sealed_sha256):
                raise GenerateAndSealError("SEALED_HASH_UNCHANGED")
            retention_until = timestamp + timedelta(days=self.retention_days)
            self._stage_callback("vault_source_upload")
            assets_client = self.assets_client_factory()
            vault_client = self.vault_client_factory()
            with tempfile.TemporaryDirectory(prefix="firemark-generate-") as directory:
                source_path = Path(directory) / "source.png"
                source_path.write_bytes(image.data)
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
                    extension="png",
                    retention_until=retention_until,
                    source_content_type="image/png",
                    now=timestamp,
                    stage_callback=self._stage_callback,
                )
            self._stage_callback("sealed_asset_upload")
            sealed_key = sealed_asset_key(sealed_sha256)
            sealed_receipt = self.sealed_uploader(
                assets_client,
                bucket=self.assets_bucket,
                key=sealed_key,
                data=sealed_bytes,
                expected_sha256=sealed_sha256,
                content_type="image/png",
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
                raise GenerateAndSealError(
                    "SEALED_VERSION_UNAVAILABLE", partial_keys=(sealed_key,)
                )
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
                provider=image.provider,
                model=image.model,
                prompt_private=request.prompt,
                parameters_private={
                    _REQUEST_FINGERPRINT_FIELD: fingerprint,
                    "requested_size": size,
                    "provider": image.safe_generation_metadata,
                },
                seed_private=image.seed,
                canonical_hash=canonical_hash,
                manifest_storage_key=custody_receipt.assets_manifest.key,
                manifest_version_id=custody_receipt.assets_manifest.version_id,
                created_at=timestamp,
            )
            asset = AssetRecord(
                asset_id=asset_id,
                run_id=run_id,
                media_type="image/png",
                file_extension="png",
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
                    public_manifest=capsule.model_dump(mode="json"),
                    canonical_hash=canonical_hash,
                    cert_id=cert_id,
                    asset_id=asset_id,
                    run_id=run_id,
                )
            except Exception as exc:
                partial = (
                    sealed_key,
                    custody_receipt.vault_source.key,
                    custody_receipt.vault_manifest.key,
                )
                raise GenerateAndSealError(
                    "REGISTRATION_FAILED", partial_keys=partial
                ) from exc
            completed = self._completed(cert_id, run_id, asset_id)
            if completed is None:
                raise GenerateAndSealError("REGISTRATION_NOT_VISIBLE")
            return completed
