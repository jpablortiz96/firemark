"""Typed persistence boundary for FIREMARK certificates and audit events."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from api.firemark.control_plane.models import (
    AssetRecord,
    CertificateRecord,
    CustodyRecord,
    DeliveryStatus,
    GenerationRunRecord,
    VerificationStatus,
)


class ControlPlaneError(RuntimeError):
    """Base class for safe control-plane failures."""


class RepositoryError(ControlPlaneError):
    """Safe normalized persistence failure."""


class BundleConflictError(RepositoryError):
    """An identifier already names different immutable evidence."""


class CertificateNotFoundError(ControlPlaneError):
    """No certificate exists for the requested public identifier."""


class CertificateRevokedError(ControlPlaneError):
    """The requested certificate has been revoked."""


class RegistrationValidationError(ControlPlaneError):
    """Internal evidence did not satisfy the issuance contract."""


class DeliveryStorageError(ControlPlaneError):
    """Private delivery could not be issued safely."""


class CertificateRepository(Protocol):
    """Minimum atomic certificate and append-only event operations."""

    def register_certificate_bundle(
        self,
        generation_run: GenerationRunRecord,
        asset: AssetRecord,
        custody: CustodyRecord,
        certificate: CertificateRecord,
    ) -> CertificateRecord: ...

    def get_certificate(self, cert_id: str) -> CertificateRecord | None: ...

    def get_certificate_by_sealed_sha256(self, sealed_sha256: str) -> CertificateRecord | None: ...

    def record_verification(
        self,
        *,
        cert_id: str | None,
        presented_sha256: str | None,
        status: VerificationStatus,
        signature_valid: bool,
        envelope_valid: bool,
        hash_match: bool | None,
        custody_reference_valid: bool,
        safe_reason_code: str,
        created_at: datetime,
    ) -> UUID: ...

    def record_delivery(
        self,
        *,
        cert_id: str,
        verification_event_id: UUID,
        status: DeliveryStatus,
        safe_reason_code: str,
        expires_at: datetime | None,
        created_at: datetime,
    ) -> UUID: ...

    def revoke_certificate(
        self,
        cert_id: str,
        *,
        reason: str,
        revoked_at: datetime,
    ) -> CertificateRecord: ...
