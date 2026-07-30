"""Certificate issuance, verification, and delivery gate services."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from api.firemark.b2_storage import (
    RedactedPresignedURL,
    generate_presigned_get,
    head_object_receipt,
)
from api.firemark.control_plane.models import (
    AssetRecord,
    CertificateRecord,
    CustodyRecord,
    DeliveryAuthorization,
    DeliveryResult,
    GenerationRunRecord,
    PublicCertificate,
    VerificationRequest,
    VerificationResult,
    VerificationStatus,
)
from api.firemark.control_plane.repository import (
    CertificateRepository,
    DeliveryStorageError,
    RegistrationValidationError,
)
from api.firemark.public_capsule import (
    FiremarkPublicAudioReferenceV1,
    FiremarkPublicCapsuleV1,
)
from api.firemark.seal_envelope import (
    SealEnvelopeV1,
    SignedSealEnvelopeV1,
    verify_signed_envelope,
)
from api.firemark.signer import Ed25519Signer


class DeliveryStorage(Protocol):
    """Issue one exact private asset download without exposing credentials."""

    def issue_download(self, asset: AssetRecord, *, ttl_seconds: int) -> RedactedPresignedURL: ...


class B2DeliveryStorage:
    """Thin exact-version adapter over the existing private B2 presigner."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def __repr__(self) -> str:
        return "B2DeliveryStorage(client=<redacted>)"

    def issue_download(self, asset: AssetRecord, *, ttl_seconds: int) -> RedactedPresignedURL:
        receipt = head_object_receipt(
            self._client,
            bucket=asset.assets_bucket,
            key=asset.assets_key,
            expected_sha256=asset.sealed_sha256,
            version_id=asset.assets_version_id,
        )
        if receipt is None or receipt.version_id != asset.assets_version_id:
            raise DeliveryStorageError("Exact sealed asset version is unavailable")
        return generate_presigned_get(
            self._client,
            bucket=asset.assets_bucket,
            key=asset.assets_key,
            version_id=asset.assets_version_id,
            ttl_seconds=ttl_seconds,
        )


@dataclass(frozen=True, repr=False)
class AuthorizedDelivery:
    """Internal grant coupling safe persistence data with a redacted URL value."""

    result: DeliveryResult
    download: RedactedPresignedURL

    def __repr__(self) -> str:
        return f"AuthorizedDelivery(result={self.result!r}, download=<redacted>)"


class CertificateService:
    """Application service joining trust, custody, persistence, and delivery."""

    def __init__(
        self,
        repository: CertificateRepository,
        *,
        public_base_url: str = "https://firemark.invalid",
        storage: DeliveryStorage | None = None,
        delivery_ttl_seconds: int = 300,
    ) -> None:
        self.repository = repository
        self.public_base_url = public_base_url.rstrip("/")
        self.storage = storage
        if not 60 <= delivery_ttl_seconds <= 900:
            raise ValueError("Delivery TTL must be between 60 and 900 seconds")
        self.delivery_ttl_seconds = delivery_ttl_seconds

    def _public(self, certificate: CertificateRecord) -> PublicCertificate:
        return PublicCertificate.model_validate(
            {
                "cert_id": certificate.cert_id,
                "asset_id": certificate.asset_id,
                "run_id": certificate.run_id,
                "provider": certificate.provider,
                "model": certificate.model,
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
                "signer_key_id": certificate.signer_key_id,
                "signer_public_key_b64": certificate.signer_public_key_b64,
                "signature_b64": certificate.signature_b64,
                "public_manifest": certificate.public_manifest,
                "certificate_status": certificate.certificate_status,
                "issued_at": certificate.issued_at,
                "verify_url": f"{self.public_base_url}/v1/certificates/{certificate.cert_id}",
            }
        )

    def get_public_certificate(self, cert_id: str) -> PublicCertificate | None:
        certificate = self.repository.get_certificate(cert_id)
        if certificate is None or not self._public_media_projection_valid(certificate):
            return None
        return self._public(certificate)

    @classmethod
    def _public_media_projection_valid(cls, certificate: CertificateRecord) -> bool:
        if cls._contains_private_generation_field(certificate.public_manifest):
            return False
        try:
            schema = certificate.public_manifest.get("schema_version")
            if certificate.media_type == "image" and schema == "firemark.public-capsule.v1":
                projection = FiremarkPublicCapsuleV1.model_validate(certificate.public_manifest)
                return (
                    projection.cert_id == certificate.cert_id
                    and projection.asset_id == certificate.asset_id
                    and projection.run_id == certificate.run_id
                    and projection.source_sha256 == certificate.source_sha256
                    and projection.canonical_hash == certificate.canonical_hash
                    and projection.signer_key_id == certificate.signer_key_id
                )
            if certificate.media_type == "audio":
                projection_audio = FiremarkPublicAudioReferenceV1.model_validate(
                    certificate.public_manifest
                )
                return (
                    projection_audio.cert_id == certificate.cert_id
                    and projection_audio.asset_id == certificate.asset_id
                    and projection_audio.run_id == certificate.run_id
                    and projection_audio.source_sha256 == certificate.source_sha256
                    and projection_audio.sealed_sha256 == certificate.sealed_sha256
                    and projection_audio.canonical_hash == certificate.canonical_hash
                    and projection_audio.signer_key_id == certificate.signer_key_id
                    and not projection_audio.embedded
                )
            return certificate.media_type == "image"
        except ValueError:
            return False

    def register_certificate(
        self,
        *,
        generation_run: GenerationRunRecord,
        asset: AssetRecord,
        custody: CustodyRecord,
        envelope: SealEnvelopeV1,
        signature_b64: str,
        signer_public_key_b64: str,
        public_manifest: dict[str, object],
        canonical_hash: str,
        cert_id: str,
        asset_id: str,
        run_id: str,
    ) -> PublicCertificate:
        """Issue only after independently validating every supplied trust relationship."""
        try:
            verifier = Ed25519Signer.from_public_key_base64(signer_public_key_b64)
            signed = SignedSealEnvelopeV1(
                envelope=SealEnvelopeV1.model_validate(envelope.model_dump()),
                signature=signature_b64,
                public_key_fingerprint=verifier.fingerprint,
            )
        except (TypeError, ValueError) as exc:
            raise RegistrationValidationError("Certificate signature evidence is malformed") from exc
        checks = (
            (verify_signed_envelope(signed, signer_public_key_b64), "Signature verification failed"),
            (cert_id == envelope.cert_id, "cert_id mismatch"),
            (asset_id == asset.asset_id, "asset_id mismatch"),
            (run_id == generation_run.run_id, "run_id mismatch"),
            (generation_run.run_id == asset.run_id == envelope.run_id, "run_id mismatch"),
            (generation_run.provider.strip() != "", "provider missing"),
            (generation_run.model.strip() != "", "model missing"),
            (custody.asset_id == asset.asset_id, "asset_id mismatch"),
            (
                hmac.compare_digest(asset.source_sha256, envelope.source_sha256),
                "source_sha256 mismatch",
            ),
            (
                hmac.compare_digest(asset.sealed_sha256, envelope.sealed_sha256),
                "sealed_sha256 mismatch",
            ),
            (
                generation_run.canonical_hash == envelope.canonical_hash == canonical_hash,
                "canonical_hash mismatch",
            ),
            (custody.custody_verified, "Custody is not verified"),
            (custody.retention_mode == "COMPLIANCE", "Custody is not COMPLIANCE"),
            (
                custody.custody_receipt.source_sha256 == asset.source_sha256,
                "Custody source hash mismatch",
            ),
            (
                custody.custody_receipt.canonical_hash == canonical_hash,
                "Custody canonical hash mismatch",
            ),
            (envelope.signer_key_id == verifier.signer_key_id, "Signer identifier mismatch"),
            (envelope.sealed_asset_bucket == asset.assets_bucket, "Asset bucket mismatch"),
            (envelope.sealed_asset_key == asset.assets_key, "Asset key mismatch"),
            (envelope.vault_bucket == asset.vault_bucket, "Vault bucket mismatch"),
            (envelope.vault_source_key == asset.vault_key, "Vault key mismatch"),
            (envelope.vault_source_version_id == asset.vault_version_id, "Vault version mismatch"),
        )
        for passed, message in checks:
            if not passed:
                raise RegistrationValidationError(message)
        if self._contains_private_generation_field(public_manifest):
            raise RegistrationValidationError("Public manifest contains private generation fields")
        try:
            if asset.asset_type == "image" and public_manifest.get("schema_version") == (
                "firemark.public-capsule.v1"
            ):
                projection = FiremarkPublicCapsuleV1.model_validate(public_manifest)
                public_matches = (
                    projection.cert_id == cert_id
                    and projection.asset_id == asset_id
                    and projection.run_id == run_id
                    and projection.source_sha256 == asset.source_sha256
                    and projection.canonical_hash == canonical_hash
                )
            elif asset.asset_type == "audio":
                audio_projection = FiremarkPublicAudioReferenceV1.model_validate(public_manifest)
                public_matches = (
                    audio_projection.cert_id == cert_id
                    and audio_projection.asset_id == asset_id
                    and audio_projection.run_id == run_id
                    and audio_projection.source_sha256 == asset.source_sha256
                    and audio_projection.sealed_sha256 == asset.sealed_sha256
                    and audio_projection.canonical_hash == canonical_hash
                    and not audio_projection.embedded
                )
            else:
                public_matches = True
        except ValueError as exc:
            raise RegistrationValidationError("Public media projection is malformed") from exc
        if not public_matches:
            raise RegistrationValidationError("Public media projection does not match evidence")
        certificate = CertificateRecord(
            cert_id=envelope.cert_id,
            asset_id=asset.asset_id,
            run_id=envelope.run_id,
            provider=generation_run.provider,
            model=generation_run.model,
            media_type=asset.asset_type,
            mime_type=asset.media_type,
            byte_size=asset.byte_size,
            ai_generated=generation_run.ai_generated,
            width=asset.width,
            height=asset.height,
            duration_ms=asset.duration_ms,
            source_sha256=envelope.source_sha256,
            sealed_sha256=envelope.sealed_sha256,
            canonical_hash=envelope.canonical_hash,
            signer_key_id=envelope.signer_key_id,
            signer_public_key_b64=signer_public_key_b64,
            signature_b64=signature_b64,
            signed_envelope=signed,
            public_manifest=public_manifest,
            issued_at=envelope.created_at,
            asset=asset,
            custody=custody,
        )
        stored = self.repository.register_certificate_bundle(
            generation_run, asset, custody, certificate
        )
        return self._public(stored)

    @classmethod
    def _contains_private_generation_field(cls, value: object) -> bool:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized = key.lower()
                if any(
                    token in normalized
                    for token in (
                        "prompt",
                        "parameter",
                        "seed",
                        "credential",
                        "authorization",
                        "app_key",
                        "presigned",
                    )
                ):
                    return True
                if cls._contains_private_generation_field(nested):
                    return True
        elif isinstance(value, list):
            return any(cls._contains_private_generation_field(item) for item in value)
        return False

    def verify(
        self,
        request: VerificationRequest,
        *,
        now: datetime | None = None,
    ) -> VerificationResult:
        timestamp = (now or datetime.now(UTC)).astimezone(UTC)
        certificate = self.repository.get_certificate(request.cert_id)
        status: VerificationStatus = "certificate_not_found"
        signature_valid = False
        envelope_valid = False
        hash_match: bool | None = None
        custody_valid = False
        reason = "CERTIFICATE_NOT_FOUND"
        event_cert_id: str | None = None
        media_type = None
        mime_type = None
        provider = None
        model = None
        if certificate is not None:
            event_cert_id = certificate.cert_id
            media_type = certificate.media_type
            mime_type = certificate.mime_type
            provider = certificate.provider
            model = certificate.model
            envelope = certificate.signed_envelope.envelope
            envelope_valid = (
                envelope.cert_id == certificate.cert_id
                and envelope.run_id == certificate.run_id
                and envelope.source_sha256 == certificate.source_sha256
                and envelope.sealed_sha256 == certificate.sealed_sha256
                and envelope.canonical_hash == certificate.canonical_hash
                and envelope.signer_key_id == certificate.signer_key_id
                and certificate.signature_b64 == certificate.signed_envelope.signature
                and self._public_media_projection_valid(certificate)
            )
            signature_valid = envelope_valid and verify_signed_envelope(
                certificate.signed_envelope, certificate.signer_public_key_b64
            )
            asset = certificate.asset
            custody = certificate.custody
            custody_valid = (
                asset is not None
                and custody is not None
                and asset.asset_id == certificate.asset_id == custody.asset_id
                and asset.run_id == certificate.run_id
                and asset.source_sha256 == certificate.source_sha256
                and asset.sealed_sha256 == certificate.sealed_sha256
                and custody.custody_verified
                and custody.retention_mode == "COMPLIANCE"
                and custody.custody_receipt.custody_verified
                and custody.custody_receipt.source_sha256 == certificate.source_sha256
                and custody.custody_receipt.canonical_hash == certificate.canonical_hash
                and envelope.vault_bucket == asset.vault_bucket
                and envelope.vault_source_key == asset.vault_key
                and envelope.vault_source_version_id == asset.vault_version_id
            )
            if certificate.certificate_status == "revoked":
                status, reason = "certificate_revoked", "CERTIFICATE_REVOKED"
            elif certificate.certificate_status == "invalid":
                status, reason = "malformed_evidence", "CERTIFICATE_INVALID"
            elif not envelope_valid:
                status, reason = "malformed_evidence", "MALFORMED_EVIDENCE"
            elif not signature_valid:
                status, reason = "signature_invalid", "SIGNATURE_INVALID"
            elif not custody_valid:
                status, reason = "malformed_evidence", "CUSTODY_REFERENCE_INVALID"
            else:
                hash_match = (
                    request.presented_sha256 is None
                    or hmac.compare_digest(request.presented_sha256, certificate.sealed_sha256)
                )
                if hash_match:
                    status, reason = "verified", "VERIFIED"
                else:
                    status, reason = "hash_mismatch", "HASH_MISMATCH"
        event_id = self.repository.record_verification(
            cert_id=event_cert_id,
            presented_sha256=request.presented_sha256,
            status=status,
            signature_valid=signature_valid,
            envelope_valid=envelope_valid,
            hash_match=hash_match,
            custody_reference_valid=custody_valid,
            safe_reason_code=reason,
            created_at=timestamp,
        )
        return VerificationResult(
            verification_event_id=event_id,
            cert_id=request.cert_id,
            media_type=media_type,
            mime_type=mime_type,
            provider=provider,
            model=model,
            status=status,
            verified=status == "verified",
            signature_valid=signature_valid,
            envelope_valid=envelope_valid,
            hash_match=hash_match,
            custody_reference_valid=custody_valid,
            safe_reason_code=reason,
            verified_at=timestamp,
        )

    def authorize_delivery(
        self,
        cert_id: str,
        authorization: DeliveryAuthorization,
        *,
        now: datetime | None = None,
    ) -> AuthorizedDelivery | DeliveryResult:
        timestamp = (now or datetime.now(UTC)).astimezone(UTC)
        verification = self.verify(
            VerificationRequest(cert_id=cert_id, presented_sha256=authorization.presented_sha256),
            now=timestamp,
        )
        if not verification.verified:
            if verification.status == "certificate_not_found":
                return DeliveryResult(
                    delivery_event_id=None,
                    verification_event_id=verification.verification_event_id,
                    cert_id=cert_id,
                    status="blocked",
                    safe_reason_code=verification.safe_reason_code,
                )
            event_id = self.repository.record_delivery(
                cert_id=cert_id,
                verification_event_id=verification.verification_event_id,
                status="blocked",
                safe_reason_code=verification.safe_reason_code,
                expires_at=None,
                created_at=timestamp,
            )
            return DeliveryResult(
                delivery_event_id=event_id,
                verification_event_id=verification.verification_event_id,
                cert_id=cert_id,
                status="blocked",
                safe_reason_code=verification.safe_reason_code,
            )
        certificate = self.repository.get_certificate(cert_id)
        if certificate is None or certificate.asset is None or self.storage is None:
            return self._record_storage_failure(cert_id, verification, timestamp)
        try:
            download = self.storage.issue_download(
                certificate.asset, ttl_seconds=self.delivery_ttl_seconds
            )
        except Exception as exc:
            self._record_storage_failure(cert_id, verification, timestamp)
            raise DeliveryStorageError("Private asset delivery could not be issued") from exc
        expires_at = timestamp + timedelta(seconds=self.delivery_ttl_seconds)
        delivery_id = self.repository.record_delivery(
            cert_id=cert_id,
            verification_event_id=verification.verification_event_id,
            status="issued",
            safe_reason_code="DELIVERY_ISSUED",
            expires_at=expires_at,
            created_at=timestamp,
        )
        return AuthorizedDelivery(
            result=DeliveryResult(
                delivery_event_id=delivery_id,
                verification_event_id=verification.verification_event_id,
                cert_id=cert_id,
                status="issued",
                safe_reason_code="DELIVERY_ISSUED",
                expires_at=expires_at,
            ),
            download=download,
        )

    def _record_storage_failure(
        self,
        cert_id: str,
        verification: VerificationResult,
        timestamp: datetime,
    ) -> DeliveryResult:
        event_id = self.repository.record_delivery(
            cert_id=cert_id,
            verification_event_id=verification.verification_event_id,
            status="storage_failure",
            safe_reason_code="DELIVERY_STORAGE_UNAVAILABLE",
            expires_at=None,
            created_at=timestamp,
        )
        return DeliveryResult(
            delivery_event_id=event_id,
            verification_event_id=verification.verification_event_id,
            cert_id=cert_id,
            status="storage_failure",
            safe_reason_code="DELIVERY_STORAGE_UNAVAILABLE",
        )
