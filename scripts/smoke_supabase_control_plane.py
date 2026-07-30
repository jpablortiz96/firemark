"""Bounded live verification for the FIREMARK Supabase Control Plane."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from dotenv import load_dotenv
from pydantic import ValidationError

from api.firemark.control_plane.memory_repository import MemoryCertificateRepository
from api.firemark.control_plane.models import (
    AssetRecord,
    CustodyRecord,
    GenerationRunRecord,
    VerificationRequest,
)
from api.firemark.control_plane.repository import RepositoryError
from api.firemark.control_plane.service import CertificateService
from api.firemark.control_plane.supabase_repository import SupabaseCertificateRepository
from api.firemark.custody import B2CustodyReceipt, LockedObjectReceipt, StoredObjectReceipt
from api.firemark.seal_envelope import SealEnvelopeV1, sign_envelope
from api.firemark.settings import LiveSupabaseControlPlaneConfig, Settings, load_settings
from api.firemark.signer import Ed25519Signer

DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
INFORMATIONAL_EXIT_CODE = 2
SOURCE_SHA256 = "1" * 64
SEALED_SHA256 = "2" * 64
CANONICAL_HASH = "3" * 64
MANIFEST_SHA256 = "4" * 64
PRIVATE_TABLES = (
    "generation_runs",
    "assets",
    "custody_records",
    "certificates",
    "verification_events",
    "delivery_events",
)
PUBLIC_RPC_NAME = "get_firemark_public_certificate"
PUBLIC_RPC_FIELDS = frozenset(
    {
        "cert_id",
        "asset_id",
        "run_id",
        "sealed_sha256",
        "canonical_hash",
        "signer_key_id",
        "signer_public_key_b64",
        "signature_b64",
        "public_manifest",
        "certificate_status",
        "issued_at",
    }
)
PRIVATE_PROJECTION_FIELDS = frozenset(
    {
        "prompt",
        "prompt_private",
        "parameters",
        "parameters_private",
        "seed",
        "seed_private",
        "source_sha256",
        "assets_bucket",
        "assets_key",
        "assets_version_id",
        "vault_bucket",
        "vault_key",
        "vault_version_id",
        "custody_receipt",
        "manifest_storage_key",
        "manifest_version_id",
        "signed_envelope",
        "service_role_key",
        "presigned_url",
        "authorization",
    }
)
PRIVATE_PROJECTION_TOKENS = (
    "prompt",
    "parameter",
    "seed",
    "vault_key",
    "vault_version",
    "custody",
    "private_manifest",
    "service_key",
    "service_role",
    "presigned",
    "authorization",
)
FORBIDDEN_DATABASE_NAMES = frozenset(
    {
        "application_key",
        "app_key",
        "secret_key",
        "service_role_key",
        "authorization_header",
        "presigned_url",
        "provider_credentials",
        "private_signing_key",
        "private_key",
    }
)
FORBIDDEN_DATABASE_VALUE_MARKERS = (
    "sb_secret_",
    "authorization: bearer",
    "x-amz-signature",
    "presigned_url",
    "provider_credentials",
    "private_signing_key",
    "private_key",
)
RLS_DENIAL_CODES = frozenset({"401", "403", "42501", "PGRST301", "PGRST302"})
STAGES = (
    "configuration_validation",
    "secret_client_construction",
    "publishable_client_construction",
    "private_table_rls_probe",
    "public_certificate_rpc_probe",
    "atomic_bundle_registration",
    "idempotent_registration",
    "conflicting_duplicate_rejection",
    "public_certificate_projection",
    "verification_event_append",
    "delivery_event_append",
    "certificate_revocation",
    "revoked_public_projection",
    "database_secret_scan",
    "write_safe_report",
)

ClientFactory = Callable[[str, str], Any]


class LiveCheckpointError(RuntimeError):
    """Safe checkpoint failure carrying only an allowlisted stage and reason code."""

    def __init__(self, stage: str, reason_code: str) -> None:
        super().__init__(f"{stage}:{reason_code}")
        self.stage = stage
        self.reason_code = reason_code


@dataclass(frozen=True)
class SmokeEvidence:
    """Synthetic, internally consistent evidence created only in memory."""

    generation_run: GenerationRunRecord
    asset: AssetRecord
    custody: CustodyRecord
    envelope: SealEnvelopeV1
    signature_b64: str
    signer_public_key_b64: str
    public_manifest: dict[str, object]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify FIREMARK against an explicitly configured disposable Supabase project.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Opt in to real Supabase reads, writes, event appends, and certificate revocation.",
    )
    parser.add_argument(
        "--output-report",
        type=Path,
        help="Optional path for a safe JSON report containing no credentials or private evidence.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing output report during an explicit live run.",
    )
    return parser


def _default_client_factory(url: str, key: str) -> Any:
    from supabase import create_client

    return create_client(url, key)


def _execute(builder: Any, stage: str, reason_code: str) -> Any:
    try:
        return builder.execute()
    except Exception as exc:
        raise LiveCheckpointError(stage, reason_code) from exc


def _rows(response: Any, stage: str, reason_code: str) -> list[Mapping[str, Any]]:
    data = getattr(response, "data", None)
    if data is None:
        return []
    if isinstance(data, Mapping):
        return [cast(Mapping[str, Any], data)]
    if isinstance(data, list) and all(isinstance(row, Mapping) for row in data):
        return cast(list[Mapping[str, Any]], data)
    raise LiveCheckpointError(stage, reason_code)


def _error_markers(exc: Exception) -> set[str]:
    markers: set[str] = set()
    for name in ("code", "status", "status_code"):
        value = getattr(exc, name, None)
        if value is not None:
            markers.add(str(value).upper())
    for value in exc.args:
        if isinstance(value, Mapping):
            for name in ("code", "status", "status_code"):
                item = value.get(name)
                if item is not None:
                    markers.add(str(item).upper())
    return markers


def classify_rls_probe(response: Any | None = None, error: Exception | None = None) -> str:
    """Accept only an empty RLS result or a recognized safe authorization denial."""
    if error is not None:
        if _error_markers(error) & RLS_DENIAL_CODES:
            return "authorization_denied"
        raise LiveCheckpointError("private_table_rls_probe", "UNSAFE_RLS_PROBE_FAILURE")
    rows = _rows(response, "private_table_rls_probe", "INVALID_RLS_RESPONSE")
    if rows:
        raise LiveCheckpointError("private_table_rls_probe", "PRIVATE_ROWS_EXPOSED")
    return "empty_rls_result"


def _probe_private_tables(publishable_client: Any) -> dict[str, str]:
    results: dict[str, str] = {}
    for table in PRIVATE_TABLES:
        try:
            response = publishable_client.table(table).select("id").limit(1).execute()
        except Exception as exc:
            results[table] = classify_rls_probe(error=exc)
        else:
            results[table] = classify_rls_probe(response=response)
    return results


def _public_rpc_rows(client: Any, cert_id: str, stage: str) -> list[Mapping[str, Any]]:
    response = _execute(
        client.rpc(PUBLIC_RPC_NAME, {"p_cert_id": cert_id}),
        stage,
        "PUBLIC_RPC_FAILED",
    )
    return _rows(response, stage, "INVALID_PUBLIC_RPC_RESPONSE")


def _build_evidence(identifier: str, now: datetime) -> SmokeEvidence:
    run_id = f"firemark-supabase-smoke-run-{identifier}"
    asset_id = f"firemark-supabase-smoke-asset-{identifier}"
    cert_id = f"firemark-supabase-smoke-cert-{identifier}"
    signer = Ed25519Signer.generate()
    retention_until = now + timedelta(days=30)
    assets_source = StoredObjectReceipt(
        bucket="synthetic-assets-bucket",
        key=f"local-fixture/{identifier}/source.png",
        sha256=SOURCE_SHA256,
        content_type="image/png",
        size_bytes=128,
        version_id="synthetic-assets-source-v1",
        created_at=now,
    )
    assets_manifest = StoredObjectReceipt(
        bucket="synthetic-assets-bucket",
        key=f"local-fixture/{identifier}/manifest.json",
        sha256=MANIFEST_SHA256,
        content_type="application/json",
        size_bytes=256,
        version_id="synthetic-assets-manifest-v1",
        created_at=now,
    )
    vault_source = LockedObjectReceipt(
        **assets_source.model_dump(exclude={"bucket", "key", "version_id"}),
        bucket="synthetic-vault-bucket",
        key=f"local-fixture/{identifier}/vault-source.png",
        version_id="synthetic-vault-source-v1",
        retention_until=retention_until,
    )
    vault_manifest = LockedObjectReceipt(
        **assets_manifest.model_dump(exclude={"bucket", "key", "version_id"}),
        bucket="synthetic-vault-bucket",
        key=f"local-fixture/{identifier}/vault-manifest.json",
        version_id="synthetic-vault-manifest-v1",
        retention_until=retention_until,
    )
    receipt = B2CustodyReceipt(
        source_sha256=SOURCE_SHA256,
        canonical_hash=CANONICAL_HASH,
        assets_source=assets_source,
        assets_manifest=assets_manifest,
        vault_source=vault_source,
        vault_manifest=vault_manifest,
        requested_retention_until=retention_until,
        created_at=now,
        custody_verified=True,
    )
    generation_run = GenerationRunRecord(
        run_id=run_id,
        provider="none-local-fixture",
        model="deterministic-control-plane-smoke",
        prompt_private="Synthetic local fixture; no provider generation claim.",
        parameters_private={"local_fixture": True, "provider_generated": False},
        seed_private=0,
        canonical_hash=CANONICAL_HASH,
        manifest_storage_key=assets_manifest.key,
        manifest_version_id=assets_manifest.version_id,
        created_at=now,
    )
    asset = AssetRecord(
        asset_id=asset_id,
        run_id=run_id,
        media_type="image/png",
        file_extension="png",
        source_sha256=SOURCE_SHA256,
        sealed_sha256=SEALED_SHA256,
        assets_bucket=assets_source.bucket,
        assets_key=f"local-fixture/{identifier}/sealed.png",
        assets_version_id="synthetic-sealed-assets-v1",
        vault_bucket=vault_source.bucket,
        vault_key=vault_source.key,
        vault_version_id=cast(str, vault_source.version_id),
        created_at=now,
    )
    custody = CustodyRecord(
        asset_id=asset_id,
        custody_receipt=receipt,
        retention_mode="COMPLIANCE",
        retention_until=retention_until,
        custody_verified=True,
        created_at=now,
    )
    envelope = SealEnvelopeV1(
        cert_id=cert_id,
        run_id=run_id,
        canonical_hash=CANONICAL_HASH,
        source_sha256=SOURCE_SHA256,
        sealed_sha256=SEALED_SHA256,
        sealed_asset_bucket=asset.assets_bucket,
        sealed_asset_key=asset.assets_key,
        public_manifest_bucket="synthetic-public-bucket",
        public_manifest_key=f"local-fixture/{identifier}/pointer.json",
        vault_bucket=asset.vault_bucket,
        vault_source_key=asset.vault_key,
        vault_source_version_id=asset.vault_version_id,
        vault_manifest_key=vault_manifest.key,
        vault_manifest_version_id=cast(str, vault_manifest.version_id),
        retention_until=retention_until,
        signer_key_id=signer.signer_key_id,
        created_at=now,
    )
    signed = sign_envelope(envelope, signer)
    return SmokeEvidence(
        generation_run=generation_run,
        asset=asset,
        custody=custody,
        envelope=envelope,
        signature_b64=signed.signature,
        signer_public_key_b64=signer.export_public_key_base64(),
        public_manifest={
            "schema_version": "1.0",
            "canonical_hash": CANONICAL_HASH,
            "local_fixture": True,
            "ai_generated": False,
            "provider_generated": False,
        },
    )


def _register(service: CertificateService, evidence: SmokeEvidence) -> None:
    service.register_certificate(
        generation_run=evidence.generation_run,
        asset=evidence.asset,
        custody=evidence.custody,
        envelope=evidence.envelope,
        signature_b64=evidence.signature_b64,
        signer_public_key_b64=evidence.signer_public_key_b64,
        public_manifest=evidence.public_manifest,
        canonical_hash=CANONICAL_HASH,
        cert_id=evidence.envelope.cert_id,
        asset_id=evidence.asset.asset_id,
        run_id=evidence.generation_run.run_id,
    )


def _query_rows(client: Any, table: str, field: str, value: str, stage: str) -> list[Mapping[str, Any]]:
    response = _execute(
        client.table(table).select("*").eq(field, value).limit(2),
        stage,
        "SERVICE_QUERY_FAILED",
    )
    return _rows(response, stage, "INVALID_SERVICE_RESPONSE")


def _bundle_row_counts(client: Any, evidence: SmokeEvidence, stage: str) -> dict[str, int]:
    filters = {
        "generation_runs": ("run_id", evidence.generation_run.run_id),
        "assets": ("asset_id", evidence.asset.asset_id),
        "custody_records": ("asset_id", evidence.asset.asset_id),
        "certificates": ("cert_id", evidence.envelope.cert_id),
    }
    return {
        table: len(_query_rows(client, table, field, value, stage))
        for table, (field, value) in filters.items()
    }


def require_atomic_bundle_counts(counts: Mapping[str, int], stage: str) -> None:
    """Reject both missing and duplicate rows; a partial bundle never passes."""
    if set(counts) != {"generation_runs", "assets", "custody_records", "certificates"}:
        raise LiveCheckpointError(stage, "INCOMPLETE_BUNDLE_RESULT")
    if any(count != 1 for count in counts.values()):
        raise LiveCheckpointError(stage, "PARTIAL_OR_DUPLICATE_BUNDLE")


def _projection_leaks(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).lower()
            if (
                normalized in PRIVATE_PROJECTION_FIELDS
                or any(token in normalized for token in PRIVATE_PROJECTION_TOKENS)
                or _projection_leaks(nested)
            ):
                return True
    elif isinstance(value, list):
        return any(_projection_leaks(item) for item in value)
    return False


def require_public_projection(row: Mapping[str, Any], evidence: SmokeEvidence) -> None:
    if set(row) != PUBLIC_RPC_FIELDS:
        raise LiveCheckpointError("public_certificate_projection", "PUBLIC_ALLOWLIST_MISMATCH")
    if _projection_leaks(row):
        raise LiveCheckpointError("public_certificate_projection", "PRIVATE_FIELD_LEAK")
    expected = {
        "cert_id": evidence.envelope.cert_id,
        "asset_id": evidence.asset.asset_id,
        "run_id": evidence.generation_run.run_id,
        "sealed_sha256": SEALED_SHA256,
        "canonical_hash": CANONICAL_HASH,
        "signer_key_id": evidence.envelope.signer_key_id,
        "signer_public_key_b64": evidence.signer_public_key_b64,
        "signature_b64": evidence.signature_b64,
        "public_manifest": evidence.public_manifest,
        "certificate_status": "active",
    }
    if any(row.get(key) != value for key, value in expected.items()):
        raise LiveCheckpointError("public_certificate_projection", "PUBLIC_VALUE_MISMATCH")


def _require_single_event(
    client: Any,
    *,
    table: str,
    event_id: UUID,
    reason: str,
    stage: str,
) -> Mapping[str, Any]:
    rows = _query_rows(client, table, "id", str(event_id), stage)
    if len(rows) != 1 or rows[0].get("safe_reason_code") != reason:
        raise LiveCheckpointError(stage, "EVENT_NOT_PERSISTED")
    return rows[0]


def _scan_names(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_DATABASE_NAMES or _scan_names(nested):
                return True
    elif isinstance(value, list):
        return any(_scan_names(item) for item in value)
    return False


def require_safe_database_rows(
    rows_by_table: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    credentials: Sequence[str],
) -> int:
    """Inspect smoke-row keys and values without returning or printing their contents."""
    scanned = 0
    for rows in rows_by_table.values():
        for row in rows:
            scanned += 1
            if _scan_names(row):
                raise LiveCheckpointError("database_secret_scan", "SENSITIVE_COLUMN_NAME")
            serialized = json.dumps(row, default=str, ensure_ascii=False).lower()
            if any(marker in serialized for marker in FORBIDDEN_DATABASE_VALUE_MARKERS):
                raise LiveCheckpointError("database_secret_scan", "SENSITIVE_VALUE_MARKER")
            if any(credential and credential.lower() in serialized for credential in credentials):
                raise LiveCheckpointError("database_secret_scan", "CREDENTIAL_VALUE_PRESENT")
    return scanned


def _package_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for package in ("supabase", "postgrest", "cryptography", "firemark"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "not-installed"
    return versions


def build_safe_report(
    *,
    config: LiveSupabaseControlPlaneConfig,
    evidence: SmokeEvidence,
    stages: Sequence[Mapping[str, str]],
    row_counts: Mapping[str, int],
    rls_results: Mapping[str, str],
    scanned_rows: int,
) -> dict[str, Any]:
    hostname = urlsplit(config.url).hostname
    if hostname is None:
        raise LiveCheckpointError("write_safe_report", "INVALID_PROJECT_HOSTNAME")
    return {
        "ai_generated": False,
        "conflicting_duplicate_rejected": True,
        "database_secret_scan": {"passed": True, "smoke_rows_scanned": scanned_rows},
        "event_results": {"delivery_event_stored": True, "verification_event_stored": True},
        "idempotent_registration": True,
        "local_fixture": True,
        "package_versions": _package_versions(),
        "production_supabase_evidence": True,
        "project_hostname": hostname,
        "public_rpc_exact_allowlist": True,
        "revocation": {"public_status": "revoked", "verification_authorized": False},
        "rls_results": dict(rls_results),
        "smoke_identifiers": {
            "asset_id": evidence.asset.asset_id,
            "cert_id": evidence.envelope.cert_id,
            "run_id": evidence.generation_run.run_id,
        },
        "stages": [dict(stage) for stage in stages],
        "table_row_counts": dict(row_counts),
    }


def _write_report(path: Path, report: Mapping[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise LiveCheckpointError("write_safe_report", "OUTPUT_EXISTS")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        temporary.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    except OSError as exc:
        raise LiveCheckpointError("write_safe_report", "REPORT_WRITE_FAILED") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _record_stage(results: list[dict[str, str]], stage: str) -> None:
    expected = STAGES[len(results)]
    if stage != expected:
        raise LiveCheckpointError(stage, "STAGE_ORDER_VIOLATION")
    results.append({"name": stage, "result": "PASS"})
    print(f"{stage}: PASS")


def run_checkpoint(
    settings: Settings,
    *,
    client_factory: ClientFactory = _default_client_factory,
    output_report: Path | None = None,
    force: bool = False,
    identifier: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Run the exact live stages with injectable zero-network clients for tests."""
    stages: list[dict[str, str]] = []
    try:
        config = settings.require_live_supabase_control_plane_config()
    except ValueError as exc:
        raise LiveCheckpointError("configuration_validation", "INVALID_LIVE_CONFIGURATION") from exc
    _record_stage(stages, "configuration_validation")

    try:
        secret_client = client_factory(config.url, config.service_role_key.get_secret_value())
    except Exception as exc:
        raise LiveCheckpointError("secret_client_construction", "CLIENT_CONSTRUCTION_FAILED") from exc
    _record_stage(stages, "secret_client_construction")
    try:
        publishable_client = client_factory(config.url, config.publishable_key)
    except Exception as exc:
        raise LiveCheckpointError(
            "publishable_client_construction", "CLIENT_CONSTRUCTION_FAILED"
        ) from exc
    _record_stage(stages, "publishable_client_construction")

    rls_results = _probe_private_tables(publishable_client)
    _record_stage(stages, "private_table_rls_probe")
    nonexistent = f"firemark-supabase-missing-{uuid4().hex[:12]}"
    if _public_rpc_rows(publishable_client, nonexistent, "public_certificate_rpc_probe"):
        raise LiveCheckpointError("public_certificate_rpc_probe", "NONEXISTENT_CERTIFICATE_FOUND")
    _record_stage(stages, "public_certificate_rpc_probe")

    timestamp = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    evidence = _build_evidence(identifier or uuid4().hex[:12], timestamp)
    repository = SupabaseCertificateRepository(
        config.url,
        config.service_role_key,
        client_factory=lambda _url, _key: secret_client,
    )
    service = CertificateService(
        repository,
        public_base_url=config.public_base_url,
        delivery_ttl_seconds=config.delivery_ttl_seconds,
    )
    _register(service, evidence)
    row_counts = _bundle_row_counts(secret_client, evidence, "atomic_bundle_registration")
    require_atomic_bundle_counts(row_counts, "atomic_bundle_registration")
    _record_stage(stages, "atomic_bundle_registration")

    _register(service, evidence)
    idempotent_counts = _bundle_row_counts(secret_client, evidence, "idempotent_registration")
    require_atomic_bundle_counts(idempotent_counts, "idempotent_registration")
    _record_stage(stages, "idempotent_registration")

    conflict = SmokeEvidence(
        generation_run=evidence.generation_run.model_copy(
            update={"model": "deliberate-conflicting-local-fixture"}
        ),
        asset=evidence.asset,
        custody=evidence.custody,
        envelope=evidence.envelope,
        signature_b64=evidence.signature_b64,
        signer_public_key_b64=evidence.signer_public_key_b64,
        public_manifest=evidence.public_manifest,
    )
    try:
        _register(service, conflict)
    except RepositoryError:
        pass
    else:
        raise LiveCheckpointError(
            "conflicting_duplicate_rejection", "CONFLICTING_DUPLICATE_ACCEPTED"
        )
    conflict_counts = _bundle_row_counts(
        secret_client, evidence, "conflicting_duplicate_rejection"
    )
    require_atomic_bundle_counts(conflict_counts, "conflicting_duplicate_rejection")
    unchanged_run = _query_rows(
        secret_client,
        "generation_runs",
        "run_id",
        evidence.generation_run.run_id,
        "conflicting_duplicate_rejection",
    )
    if len(unchanged_run) != 1 or unchanged_run[0].get("model") != evidence.generation_run.model:
        raise LiveCheckpointError(
            "conflicting_duplicate_rejection", "CONFLICT_MUTATED_EXISTING_ROW"
        )
    _record_stage(stages, "conflicting_duplicate_rejection")

    public_rows = _public_rpc_rows(
        publishable_client, evidence.envelope.cert_id, "public_certificate_projection"
    )
    if len(public_rows) != 1:
        raise LiveCheckpointError("public_certificate_projection", "PUBLIC_ROW_COUNT_MISMATCH")
    require_public_projection(public_rows[0], evidence)
    _record_stage(stages, "public_certificate_projection")

    verification = service.verify(
        VerificationRequest(cert_id=evidence.envelope.cert_id, presented_sha256=SEALED_SHA256),
        now=timestamp + timedelta(seconds=1),
    )
    if not verification.verified or verification.safe_reason_code != "VERIFIED":
        raise LiveCheckpointError("verification_event_append", "VERIFICATION_DID_NOT_PASS")
    _require_single_event(
        secret_client,
        table="verification_events",
        event_id=verification.verification_event_id,
        reason="VERIFIED",
        stage="verification_event_append",
    )
    _record_stage(stages, "verification_event_append")

    delivery_reason = "SMOKE_CHECKPOINT_NO_EXTERNAL_DELIVERY"
    delivery_id = repository.record_delivery(
        cert_id=evidence.envelope.cert_id,
        verification_event_id=verification.verification_event_id,
        status="blocked",
        safe_reason_code=delivery_reason,
        expires_at=None,
        created_at=timestamp + timedelta(seconds=2),
    )
    delivery_row = _require_single_event(
        secret_client,
        table="delivery_events",
        event_id=delivery_id,
        reason=delivery_reason,
        stage="delivery_event_append",
    )
    if any("url" in str(key).lower() for key in delivery_row):
        raise LiveCheckpointError("delivery_event_append", "DELIVERY_URL_COLUMN_PRESENT")
    if any("presigned" in str(value).lower() for value in delivery_row.values()):
        raise LiveCheckpointError("delivery_event_append", "PRESIGNED_URL_VALUE_PRESENT")
    _record_stage(stages, "delivery_event_append")

    revocation_reason = "SMOKE_CHECKPOINT_REVOCATION"
    revoked = repository.revoke_certificate(
        evidence.envelope.cert_id,
        reason=revocation_reason,
        revoked_at=timestamp + timedelta(seconds=3),
    )
    if (
        revoked.certificate_status != "revoked"
        or revoked.revoked_at is None
        or revoked.revocation_reason != revocation_reason
    ):
        raise LiveCheckpointError("certificate_revocation", "REVOCATION_NOT_PERSISTED")
    _record_stage(stages, "certificate_revocation")

    revoked_rows = _public_rpc_rows(
        publishable_client, evidence.envelope.cert_id, "revoked_public_projection"
    )
    if len(revoked_rows) != 1 or revoked_rows[0].get("certificate_status") != "revoked":
        raise LiveCheckpointError("revoked_public_projection", "PUBLIC_REVOCATION_MISMATCH")
    local_repository = MemoryCertificateRepository()
    local_repository.register_certificate_bundle(
        evidence.generation_run, evidence.asset, evidence.custody, revoked
    )
    local_verification = CertificateService(local_repository).verify(
        VerificationRequest(cert_id=evidence.envelope.cert_id, presented_sha256=SEALED_SHA256),
        now=timestamp + timedelta(seconds=4),
    )
    if local_verification.verified or local_verification.status != "certificate_revoked":
        raise LiveCheckpointError("revoked_public_projection", "REVOKED_CERTIFICATE_AUTHORIZED")
    _record_stage(stages, "revoked_public_projection")

    smoke_filters = {
        "generation_runs": ("run_id", evidence.generation_run.run_id),
        "assets": ("asset_id", evidence.asset.asset_id),
        "custody_records": ("asset_id", evidence.asset.asset_id),
        "certificates": ("cert_id", evidence.envelope.cert_id),
        "verification_events": ("id", str(verification.verification_event_id)),
        "delivery_events": ("id", str(delivery_id)),
    }
    rows_by_table = {
        table: _query_rows(secret_client, table, field, value, "database_secret_scan")
        for table, (field, value) in smoke_filters.items()
    }
    if any(len(rows) != 1 for rows in rows_by_table.values()):
        raise LiveCheckpointError("database_secret_scan", "SMOKE_ROW_COUNT_MISMATCH")
    scanned_rows = require_safe_database_rows(
        rows_by_table,
        credentials=(
            config.publishable_key,
            config.service_role_key.get_secret_value(),
        ),
    )
    _record_stage(stages, "database_secret_scan")

    final_counts = {table: len(rows) for table, rows in rows_by_table.items()}
    report_stages = [
        *stages,
        {"name": "write_safe_report", "result": "PASS"},
    ]
    report = build_safe_report(
        config=config,
        evidence=evidence,
        stages=report_stages,
        row_counts=final_counts,
        rls_results=rls_results,
        scanned_rows=scanned_rows,
    )
    if output_report is not None:
        _write_report(output_report.resolve(), report, force=force)
    _record_stage(stages, "write_safe_report")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    """Refuse all Supabase traffic unless the owner explicitly supplies --live."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.force and args.output_report is None:
        parser.error("--force requires --output-report")
    if not args.live:
        print("FIREMARK Supabase Control Plane smoke: network disabled (no --live).")
        print("No Supabase client was constructed and no database operation was attempted.")
        print("Review the disposable project and ignored .env, then rerun explicitly with --live.")
        return INFORMATIONAL_EXIT_CODE
    if args.output_report is not None and args.output_report.exists() and not args.force:
        print("FAIL: write_safe_report (OUTPUT_EXISTS)")
        return 1
    if not DEFAULT_ENV_FILE.is_file():
        print("FAIL: configuration_validation (INVALID_LIVE_CONFIGURATION)")
        return 3
    load_dotenv(dotenv_path=DEFAULT_ENV_FILE, override=False)
    try:
        settings = load_settings()
        report = run_checkpoint(
            settings,
            output_report=args.output_report,
            force=args.force,
        )
    except (LiveCheckpointError, ValidationError) as exc:
        if isinstance(exc, LiveCheckpointError):
            print(f"FAIL: {exc.stage} ({exc.reason_code})")
        else:
            print("FAIL: configuration_validation (INVALID_LIVE_CONFIGURATION)")
        return 1
    except Exception:
        print("FAIL: checkpoint_internal (SAFE_UNEXPECTED_FAILURE)")
        return 1
    print(f"Project hostname: {report['project_hostname']}")
    print("Local fixture: YES")
    print("AI-generated content: NO")
    print("Provider generation evidence: NO")
    print("Production Supabase evidence: YES")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
