"""Lazy service-role Supabase adapter using one atomic registration RPC."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from pydantic import SecretStr

from api.firemark.control_plane.models import (
    AssetRecord,
    CertificateRecord,
    CustodyRecord,
    DeliveryStatus,
    GenerationRunRecord,
    VerificationStatus,
)
from api.firemark.control_plane.repository import CertificateNotFoundError, RepositoryError
from api.firemark.settings import SupabaseConfig

ClientFactory = Callable[[str, str], Any]


class SupabaseCertificateRepository:
    """Production adapter whose constructor performs no network operation."""

    def __init__(
        self,
        url: str,
        service_role_key: SecretStr,
        *,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self._url = url
        self._service_role_key = service_role_key
        self._client_factory = client_factory
        self._client: Any | None = None

    @classmethod
    def from_config(
        cls,
        config: SupabaseConfig,
        *,
        client_factory: ClientFactory | None = None,
    ) -> SupabaseCertificateRepository:
        return cls(config.url, config.service_role_key, client_factory=client_factory)

    def __repr__(self) -> str:
        return "SupabaseCertificateRepository(url=<redacted>, service_role_key=<redacted>)"

    def _get_client(self) -> Any:
        if self._client is None:
            factory = self._client_factory
            if factory is None:
                from supabase import create_client

                factory = cast(ClientFactory, create_client)
            self._client = factory(self._url, self._service_role_key.get_secret_value())
        return self._client

    @staticmethod
    def _execute(builder: Any, operation: str) -> Any:
        try:
            return builder.execute()
        except Exception as exc:
            raise RepositoryError(f"Supabase {operation} failed") from exc

    @staticmethod
    def _row(response: Any) -> Mapping[str, Any] | None:
        data = getattr(response, "data", None)
        if isinstance(data, Mapping):
            return data
        if isinstance(data, list) and data and isinstance(data[0], Mapping):
            return cast(Mapping[str, Any], data[0])
        return None

    def register_certificate_bundle(
        self,
        generation_run: GenerationRunRecord,
        asset: AssetRecord,
        custody: CustodyRecord,
        certificate: CertificateRecord,
    ) -> CertificateRecord:
        payload = {
            "p_generation_run": generation_run.model_dump(mode="json"),
            "p_asset": asset.model_dump(mode="json"),
            "p_custody": custody.model_dump(mode="json"),
            "p_certificate": certificate.model_dump(
                mode="json", exclude={"asset", "custody"}
            ),
        }
        client = self._get_client()
        self._execute(
            client.rpc("register_firemark_certificate_bundle", payload),
            "atomic certificate registration",
        )
        return certificate.model_copy(update={"asset": asset, "custody": custody})

    def _certificate_from_row(self, row: Mapping[str, Any]) -> CertificateRecord:
        values = dict(row)
        asset_value = values.pop("assets", values.pop("asset", None))
        custody_value: Any = None
        asset: AssetRecord | None = None
        if isinstance(asset_value, Mapping):
            asset_data = dict(asset_value)
            custody_value = asset_data.pop("custody_records", None)
            for key in ("id",):
                asset_data.pop(key, None)
            asset = AssetRecord.model_validate(asset_data)
        custody: CustodyRecord | None = None
        if isinstance(custody_value, list):
            custody_value = custody_value[0] if custody_value else None
        if isinstance(custody_value, Mapping):
            custody_data = dict(custody_value)
            custody_data.pop("id", None)
            custody = CustodyRecord.model_validate(custody_data)
        for key in ("id",):
            values.pop(key, None)
        values["asset"] = asset
        values["custody"] = custody
        return CertificateRecord.model_validate(values)

    def _find(self, field: str, value: str) -> CertificateRecord | None:
        client = self._get_client()
        query = (
            client.table("certificates")
            .select("*,assets(*,custody_records(*))")
            .eq(field, value)
            .maybe_single()
        )
        row = self._row(self._execute(query, "certificate read"))
        return self._certificate_from_row(row) if row is not None else None

    def get_certificate(self, cert_id: str) -> CertificateRecord | None:
        return self._find("cert_id", cert_id)

    def get_certificate_by_sealed_sha256(self, sealed_sha256: str) -> CertificateRecord | None:
        return self._find("sealed_sha256", sealed_sha256)

    def get_generation_request_fingerprint(self, run_id: str) -> str | None:
        client = self._get_client()
        query = (
            client.table("generation_runs")
            .select("parameters_private")
            .eq("run_id", run_id)
            .maybe_single()
        )
        row = self._row(self._execute(query, "generation idempotency read"))
        if row is None:
            return None
        parameters = row.get("parameters_private")
        if not isinstance(parameters, Mapping):
            return None
        value = parameters.get("_firemark_request_fingerprint")
        return str(value) if isinstance(value, str) else None

    def _insert_event(self, table: str, payload: dict[str, Any]) -> UUID:
        client = self._get_client()
        response = self._execute(client.table(table).insert(payload), f"{table} append")
        row = self._row(response)
        if row is None or "id" not in row:
            raise RepositoryError(f"Supabase {table} append returned no identifier")
        try:
            return UUID(str(row["id"]))
        except ValueError as exc:
            raise RepositoryError(f"Supabase {table} returned an invalid identifier") from exc

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
        return self._insert_event(
            "verification_events",
            {
                "cert_id": cert_id,
                "presented_sha256": presented_sha256,
                "verification_status": status,
                "signature_valid": signature_valid,
                "envelope_valid": envelope_valid,
                "hash_match": hash_match,
                "custody_reference_valid": custody_reference_valid,
                "safe_reason_code": safe_reason_code,
                "created_at": created_at.isoformat(),
            },
        )

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
        return self._insert_event(
            "delivery_events",
            {
                "cert_id": cert_id,
                "verification_event_id": str(verification_event_id),
                "delivery_status": status,
                "safe_reason_code": safe_reason_code,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "created_at": created_at.isoformat(),
            },
        )

    def revoke_certificate(
        self,
        cert_id: str,
        *,
        reason: str,
        revoked_at: datetime,
    ) -> CertificateRecord:
        client = self._get_client()
        query = (
            client.table("certificates")
            .update(
                {
                    "certificate_status": "revoked",
                    "revoked_at": revoked_at.isoformat(),
                    "revocation_reason": reason,
                }
            )
            .eq("cert_id", cert_id)
            .select("*,assets(*,custody_records(*))")
        )
        response = self._execute(query, "certificate revocation")
        row = self._row(response)
        if row is None:
            raise CertificateNotFoundError("Certificate not found")
        return self._certificate_from_row(row)
