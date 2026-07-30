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
        return self._public(certificate) if certificate is not None else None

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
        certificate = CertificateRecord(
            cert_id=envelope.cert_id,
            asset_id=asset.asset_id,
            run_id=envelope.run_id,
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
        if certificate is not None:
            event_cert_id = certificate.cert_id
            envelope = certificate.signed_envelope.envelope
            envelope_valid = (
                envelope.cert_id == certificate.cert_id
                and envelope.run_id == certificate.run_id
                and envelope.source_sha256 == certificate.source_sha256
                and envelope.sealed_sha256 == certificate.sealed_sha256
                and envelope.canonical_hash == certificate.canonical_hash
                and envelope.signer_key_id == certificate.signer_key_id
                and certificate.signature_b64 == certificate.signed_envelope.signature
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
