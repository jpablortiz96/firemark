"""Deterministic zero-network repository for local use and tests."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid5

from api.firemark.control_plane.models import (
    AssetRecord,
    CertificateRecord,
    CustodyRecord,
    DeliveryStatus,
    GenerationRunRecord,
    VerificationStatus,
)
from api.firemark.control_plane.repository import (
    BundleConflictError,
    CertificateNotFoundError,
)

_NAMESPACE = UUID("aee662e9-34dc-4f83-ad6c-0146d27f68da")


class MemoryCertificateRepository:
    """Atomic in-memory persistence with content-sensitive idempotency."""

    def __init__(self) -> None:
        self._runs: dict[str, GenerationRunRecord] = {}
        self._assets: dict[str, AssetRecord] = {}
        self._custody: dict[str, CustodyRecord] = {}
        self._certificates: dict[str, CertificateRecord] = {}
        self.verification_events: list[dict[str, Any]] = []
        self.delivery_events: list[dict[str, Any]] = []

    def __repr__(self) -> str:
        return (
            "MemoryCertificateRepository("
            f"certificates={len(self._certificates)}, "
            f"verification_events={len(self.verification_events)}, "
            f"delivery_events={len(self.delivery_events)})"
        )

    def register_certificate_bundle(
        self,
        generation_run: GenerationRunRecord,
        asset: AssetRecord,
        custody: CustodyRecord,
        certificate: CertificateRecord,
    ) -> CertificateRecord:
        aggregate = certificate.model_copy(update={"asset": asset, "custody": custody})
        existing = self._certificates.get(certificate.cert_id)
        if existing is not None:
            if existing != aggregate:
                raise BundleConflictError("Certificate identifier conflicts with existing evidence")
            return existing
        if generation_run.run_id in self._runs and self._runs[generation_run.run_id] != generation_run:
            raise BundleConflictError("Run identifier conflicts with existing evidence")
        if asset.asset_id in self._assets and self._assets[asset.asset_id] != asset:
            raise BundleConflictError("Asset identifier conflicts with existing evidence")
        if asset.asset_id in self._custody and self._custody[asset.asset_id] != custody:
            raise BundleConflictError("Custody identifier conflicts with existing evidence")
        self._runs[generation_run.run_id] = generation_run
        self._assets[asset.asset_id] = asset
        self._custody[asset.asset_id] = custody
        self._certificates[certificate.cert_id] = aggregate
        return aggregate

    def get_certificate(self, cert_id: str) -> CertificateRecord | None:
        return self._certificates.get(cert_id)

    def get_certificate_by_sealed_sha256(self, sealed_sha256: str) -> CertificateRecord | None:
        return next(
            (
                certificate
                for certificate in self._certificates.values()
                if certificate.sealed_sha256 == sealed_sha256
            ),
            None,
        )

    def get_generation_request_fingerprint(self, run_id: str) -> str | None:
        run = self._runs.get(run_id)
        if run is None:
            return None
        value = run.parameters_private.get("_firemark_request_fingerprint")
        return value if isinstance(value, str) else None

    def _event_id(self, kind: str, index: int) -> UUID:
        return uuid5(_NAMESPACE, f"{kind}:{index}")

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
    ) -> UUID:
        event_id = self._event_id("verification", len(self.verification_events))
        self.verification_events.append(
            {
                "id": event_id,
                "cert_id": cert_id,
                "presented_sha256": presented_sha256,
                "verification_status": status,
                "signature_valid": signature_valid,
                "envelope_valid": envelope_valid,
                "hash_match": hash_match,
                "custody_reference_valid": custody_reference_valid,
                "safe_reason_code": safe_reason_code,
                "created_at": created_at,
            }
        )
        return event_id

    def record_delivery(
        self,
        *,
        cert_id: str,
        verification_event_id: UUID,
        status: DeliveryStatus,
        safe_reason_code: str,
        expires_at: datetime | None,
        created_at: datetime,
    ) -> UUID:
        event_id = self._event_id("delivery", len(self.delivery_events))
        self.delivery_events.append(
            {
                "id": event_id,
                "cert_id": cert_id,
                "verification_event_id": verification_event_id,
                "delivery_status": status,
                "safe_reason_code": safe_reason_code,
                "expires_at": expires_at,
                "created_at": created_at,
            }
        )
        return event_id

    def revoke_certificate(
        self,
        cert_id: str,
        *,
        reason: str,
        revoked_at: datetime,
    ) -> CertificateRecord:
        current = self._certificates.get(cert_id)
        if current is None:
            raise CertificateNotFoundError("Certificate not found")
        if not reason.strip():
            raise ValueError("Revocation reason must not be blank")
        revoked = current.model_copy(
            update={
                "certificate_status": "revoked",
                "revoked_at": revoked_at,
                "revocation_reason": reason,
            }
        )
        revoked = CertificateRecord.model_validate(revoked.model_dump())
        self._certificates[cert_id] = revoked
        return revoked
