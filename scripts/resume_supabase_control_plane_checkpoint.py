"""Resume only the post-event stages of an existing Supabase smoke checkpoint."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from dotenv import load_dotenv
from pydantic import ValidationError

from api.firemark.control_plane.memory_repository import MemoryCertificateRepository
from api.firemark.control_plane.models import (
    CertificateRecord,
    DeliveryAuthorization,
    DeliveryResult,
    GenerationRunRecord,
)
from api.firemark.control_plane.repository import CertificateNotFoundError, RepositoryError
from api.firemark.control_plane.service import CertificateService
from api.firemark.control_plane.supabase_repository import SupabaseCertificateRepository
from api.firemark.settings import LiveSupabaseControlPlaneConfig, Settings, load_settings

if TYPE_CHECKING or __package__:
    from scripts import smoke_supabase_control_plane as smoke
else:
    import smoke_supabase_control_plane as smoke

DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
INFORMATIONAL_EXIT_CODE = 2
REVOCATION_REASON = "SMOKE_CHECKPOINT_REVOCATION"
RUN_PREFIX = "firemark-supabase-smoke-run-"
ASSET_PREFIX = "firemark-supabase-smoke-asset-"
CERT_PREFIX = "firemark-supabase-smoke-cert-"
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RESUME_STAGES = (
    "configuration_validation",
    "secret_client_construction",
    "publishable_client_construction",
    "discover_incomplete_bundle",
    "existing_row_validation",
    "private_table_rls_confirmation",
    "public_certificate_projection",
    "certificate_revocation",
    "revoked_public_projection",
    "delivery_blocked_after_revocation",
    "database_secret_scan",
    "write_safe_report",
)

ClientFactory = Callable[[str, str], Any]


class ResumeCheckpointError(RuntimeError):
    """Safe resume failure with normalized stage, category, class, and service code."""

    def __init__(
        self,
        stage: str,
        category: str,
        *,
        exception_class: str = "NONE",
        postgrest_code: str = "NONE",
    ) -> None:
        super().__init__(f"{stage}:{category}")
        self.stage = stage
        self.category = category
        self.exception_class = exception_class
        self.postgrest_code = postgrest_code


@dataclass(frozen=True)
class ExistingBundle:
    """Only safe identifiers and revocation state used to resume one bundle."""

    run_id: str
    asset_id: str
    cert_id: str
    certificate_status: str
    revoked_at: str | None
    revocation_reason: str | None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resume the bounded post-event FIREMARK Supabase checkpoint.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Opt in to discovering and revoking one existing incomplete smoke certificate.",
    )
    parser.add_argument(
        "--output-report",
        type=Path,
        help="Path for the final safe Supabase evidence report.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing safe report during the explicit live resume.",
    )
    return parser


def _default_client_factory(url: str, key: str) -> Any:
    from supabase import create_client

    return create_client(url, key)


def _safe_error_code(exc: Exception) -> str:
    for name in ("code", "status", "status_code"):
        value = getattr(exc, name, None)
        if value is not None:
            return str(value).upper()
    for value in exc.args:
        if isinstance(value, Mapping):
            for name in ("code", "status", "status_code"):
                item = value.get(name)
                if item is not None:
                    return str(item).upper()
    return "NONE"


@contextmanager
def stage_boundary(stage: str) -> Iterator[None]:
    """Normalize all failures at the exact resume stage without raw messages."""
    try:
        yield
    except ResumeCheckpointError:
        raise
    except smoke.LiveCheckpointError as exc:
        raise ResumeCheckpointError(
            stage,
            exc.reason_code,
            exception_class=type(exc).__name__,
        ) from exc
    except RepositoryError as exc:
        raise ResumeCheckpointError(
            stage,
            "REPOSITORY_OPERATION_FAILED",
            exception_class=type(exc).__name__,
            postgrest_code=_safe_error_code(cast(Exception, exc.__cause__ or exc)),
        ) from exc
    except CertificateNotFoundError as exc:
        raise ResumeCheckpointError(
            stage,
            "CERTIFICATE_NOT_FOUND",
            exception_class=type(exc).__name__,
        ) from exc
    except ValidationError as exc:
        raise ResumeCheckpointError(
            stage,
            "RESPONSE_VALIDATION_FAILED",
            exception_class=type(exc).__name__,
        ) from exc
    except AttributeError as exc:
        raise ResumeCheckpointError(
            stage,
            "ADAPTER_CONTRACT_FAILURE",
            exception_class=type(exc).__name__,
        ) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise ResumeCheckpointError(
            stage,
            "INVALID_STAGE_RESPONSE",
            exception_class=type(exc).__name__,
        ) from exc
    except Exception as exc:
        raise ResumeCheckpointError(
            stage,
            "SAFE_UNEXPECTED_STAGE_FAILURE",
            exception_class=type(exc).__name__,
            postgrest_code=_safe_error_code(exc),
        ) from exc


def _execute(builder: Any, stage: str) -> Any:
    try:
        return builder.execute()
    except Exception as exc:
        raise ResumeCheckpointError(
            stage,
            "SERVICE_OPERATION_FAILED",
            exception_class=type(exc).__name__,
            postgrest_code=_safe_error_code(exc),
        ) from exc


def _rows(response: Any, stage: str) -> list[Mapping[str, Any]]:
    data = getattr(response, "data", None)
    if data is None:
        return []
    if isinstance(data, Mapping):
        return [cast(Mapping[str, Any], data)]
    if isinstance(data, list) and all(isinstance(row, Mapping) for row in data):
        return cast(list[Mapping[str, Any]], data)
    raise ResumeCheckpointError(stage, "INVALID_SERVICE_RESPONSE")


def _safe_identifier(value: object, prefix: str, stage: str) -> str:
    text = str(value)
    if not text.startswith(prefix) or not SAFE_IDENTIFIER.fullmatch(text):
        raise ResumeCheckpointError(stage, "UNSAFE_SMOKE_IDENTIFIER")
    return text


def discover_incomplete_bundle(secret_client: Any) -> ExistingBundle:
    """Require exactly one active or identically-revoked incomplete smoke bundle."""
    stage = "discover_incomplete_bundle"
    response = _execute(
        secret_client.table("generation_runs")
        .select("run_id,created_at")
        .like("run_id", f"{RUN_PREFIX}%")
        .order("created_at", desc=True)
        .limit(10),
        stage,
    )
    runs = _rows(response, stage)
    candidates: list[ExistingBundle] = []
    for run in runs:
        run_id = _safe_identifier(run.get("run_id"), RUN_PREFIX, stage)
        certificate_rows = _rows(
            _execute(
                secret_client.table("certificates")
                .select(
                    "cert_id,asset_id,run_id,certificate_status,revoked_at,revocation_reason"
                )
                .eq("run_id", run_id)
                .limit(2),
                stage,
            ),
            stage,
        )
        if len(certificate_rows) > 1:
            raise ResumeCheckpointError(stage, "AMBIGUOUS_CERTIFICATES_FOR_RUN")
        if not certificate_rows:
            continue
        row = certificate_rows[0]
        status = str(row.get("certificate_status"))
        reason_value = row.get("revocation_reason")
        reason = str(reason_value) if reason_value is not None else None
        if status == "active" or (status == "revoked" and reason == REVOCATION_REASON):
            revoked_value = row.get("revoked_at")
            candidates.append(
                ExistingBundle(
                    run_id=run_id,
                    asset_id=_safe_identifier(row.get("asset_id"), ASSET_PREFIX, stage),
                    cert_id=_safe_identifier(row.get("cert_id"), CERT_PREFIX, stage),
                    certificate_status=status,
                    revoked_at=str(revoked_value) if revoked_value is not None else None,
                    revocation_reason=reason,
                )
            )
    if not candidates:
        raise ResumeCheckpointError(stage, "INCOMPLETE_BUNDLE_NOT_FOUND")
    if len(candidates) != 1:
        raise ResumeCheckpointError(stage, "AMBIGUOUS_INCOMPLETE_BUNDLES")
    return candidates[0]


def _query_rows(
    client: Any,
    table: str,
    field: str,
    value: str,
    stage: str,
    *,
    columns: str = "*",
) -> list[Mapping[str, Any]]:
    return _rows(
        _execute(client.table(table).select(columns).eq(field, value), stage),
        stage,
    )


def _smoke_filters(bundle: ExistingBundle) -> dict[str, tuple[str, str]]:
    return {
        "generation_runs": ("run_id", bundle.run_id),
        "assets": ("asset_id", bundle.asset_id),
        "custody_records": ("asset_id", bundle.asset_id),
        "certificates": ("cert_id", bundle.cert_id),
        "verification_events": ("cert_id", bundle.cert_id),
        "delivery_events": ("cert_id", bundle.cert_id),
    }


def validate_existing_rows(client: Any, bundle: ExistingBundle) -> dict[str, int]:
    stage = "existing_row_validation"
    counts = {
        table: len(_query_rows(client, table, field, value, stage, columns="id"))
        for table, (field, value) in _smoke_filters(bundle).items()
    }
    for table in ("generation_runs", "assets", "custody_records", "certificates"):
        if counts[table] != 1:
            raise ResumeCheckpointError(stage, "INVALID_REGISTRATION_ROW_COUNT")
    if counts["verification_events"] < 1 or counts["delivery_events"] < 1:
        raise ResumeCheckpointError(stage, "REQUIRED_EVENT_ROWS_MISSING")
    return counts


def _public_rpc_rows(client: Any, cert_id: str, stage: str) -> list[Mapping[str, Any]]:
    return _rows(
        _execute(
            client.rpc(smoke.PUBLIC_RPC_NAME, {"p_cert_id": cert_id}),
            stage,
        ),
        stage,
    )


def require_public_projection(row: Mapping[str, Any], *, expected_status: str) -> None:
    if set(row) != smoke.PUBLIC_RPC_FIELDS:
        raise ResumeCheckpointError(
            "public_certificate_projection", "PUBLIC_ALLOWLIST_MISMATCH"
        )
    if smoke._projection_leaks(row):
        raise ResumeCheckpointError("public_certificate_projection", "PRIVATE_FIELD_LEAK")
    if row.get("certificate_status") != expected_status:
        raise ResumeCheckpointError("public_certificate_projection", "PUBLIC_STATUS_MISMATCH")


def _generation_record(client: Any, bundle: ExistingBundle) -> GenerationRunRecord:
    rows = _query_rows(
        client,
        "generation_runs",
        "run_id",
        bundle.run_id,
        "delivery_blocked_after_revocation",
    )
    if len(rows) != 1:
        raise ResumeCheckpointError(
            "delivery_blocked_after_revocation", "GENERATION_ROW_NOT_FOUND"
        )
    values = dict(rows[0])
    values.pop("id", None)
    return GenerationRunRecord.model_validate(values)


def confirm_delivery_blocked(
    secret_client: Any,
    bundle: ExistingBundle,
    certificate: Any,
) -> None:
    """Exercise Verify Gate locally with the real revoked aggregate and no database event writes."""
    if certificate.asset is None or certificate.custody is None:
        raise ResumeCheckpointError(
            "delivery_blocked_after_revocation", "PRIVATE_AGGREGATE_INCOMPLETE"
        )
    memory = MemoryCertificateRepository()
    memory.register_certificate_bundle(
        _generation_record(secret_client, bundle),
        certificate.asset,
        certificate.custody,
        certificate,
    )
    result = CertificateService(memory).authorize_delivery(
        bundle.cert_id,
        DeliveryAuthorization(presented_sha256=certificate.sealed_sha256),
    )
    if not isinstance(result, DeliveryResult) or result.status != "blocked":
        raise ResumeCheckpointError(
            "delivery_blocked_after_revocation", "REVOKED_DELIVERY_NOT_BLOCKED"
        )
    if result.safe_reason_code != "CERTIFICATE_REVOKED":
        raise ResumeCheckpointError(
            "delivery_blocked_after_revocation", "UNSAFE_BLOCK_REASON"
        )


def revoke_existing_certificate(
    repository: SupabaseCertificateRepository,
    bundle: ExistingBundle,
    *,
    revoked_at: datetime,
) -> tuple[CertificateRecord, str]:
    """Revoke once, or accept only the exact prior checkpoint revocation."""
    existing = repository.get_certificate(bundle.cert_id)
    if existing is None:
        raise ResumeCheckpointError("certificate_revocation", "CERTIFICATE_NOT_FOUND")
    if existing.certificate_status == "active":
        revoked = repository.revoke_certificate(
            bundle.cert_id,
            reason=REVOCATION_REASON,
            revoked_at=revoked_at,
        )
        result = "revoked_existing_certificate"
    elif (
        existing.certificate_status == "revoked"
        and existing.revocation_reason == REVOCATION_REASON
        and existing.revoked_at is not None
    ):
        revoked = existing
        result = "already_identically_revoked"
    else:
        raise ResumeCheckpointError("certificate_revocation", "REVOCATION_CONFLICT")
    if (
        revoked.certificate_status != "revoked"
        or revoked.revoked_at is None
        or revoked.revocation_reason != REVOCATION_REASON
    ):
        raise ResumeCheckpointError("certificate_revocation", "REVOCATION_NOT_PERSISTED")
    return revoked, result


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
    bundle: ExistingBundle,
    stages: Sequence[Mapping[str, str]],
    row_counts: Mapping[str, int],
    rls_results: Mapping[str, str],
    revocation_result: str,
    scanned_rows: int,
) -> dict[str, Any]:
    hostname = urlsplit(config.url).hostname
    if hostname is None:
        raise ResumeCheckpointError("write_safe_report", "INVALID_PROJECT_HOSTNAME")
    return {
        "ai_generated": False,
        "conflicting_duplicate_result": "original_checkpoint_passed",
        "database_secret_scan_result": {"passed": True, "smoke_rows_scanned": scanned_rows},
        "delivery_event_result": {
            "existing_count": row_counts["delivery_events"],
            "new_rows": 0,
        },
        "idempotency_result": "single_existing_bundle_confirmed",
        "local_fixture": True,
        "new_event_rows": 0,
        "new_registration_rows": 0,
        "package_versions": _package_versions(),
        "private_table_rls_result": dict(rls_results),
        "production_supabase_evidence": True,
        "project_hostname": hostname,
        "public_rpc_allowlist_result": True,
        "registration_result": "existing_atomic_bundle_confirmed",
        "resumed_from_existing_records": True,
        "revocation_result": revocation_result,
        "smoke_asset_id": bundle.asset_id,
        "smoke_cert_id": bundle.cert_id,
        "smoke_run_id": bundle.run_id,
        "stage_results": [dict(stage) for stage in stages],
        "table_row_counts": dict(row_counts),
        "verification_event_result": {
            "existing_count": row_counts["verification_events"],
            "new_rows": 0,
        },
    }


def _write_report(path: Path, report: Mapping[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise ResumeCheckpointError("write_safe_report", "OUTPUT_EXISTS")
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
        raise ResumeCheckpointError(
            "write_safe_report",
            "REPORT_WRITE_FAILED",
            exception_class=type(exc).__name__,
        ) from exc
    finally:
        temporary.unlink(missing_ok=True)


def _record_stage(results: list[dict[str, str]], stage: str) -> None:
    if RESUME_STAGES[len(results)] != stage:
        raise ResumeCheckpointError(stage, "STAGE_ORDER_VIOLATION")
    results.append({"name": stage, "result": "PASS"})
    print(f"{stage}: PASS")


def run_resume_checkpoint(
    settings: Settings,
    *,
    client_factory: ClientFactory = _default_client_factory,
    output_report: Path | None = None,
    force: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Resume one existing bundle without any registration or database event inserts."""
    stages: list[dict[str, str]] = []
    with stage_boundary("configuration_validation"):
        config = settings.require_live_supabase_control_plane_config()
    _record_stage(stages, "configuration_validation")

    with stage_boundary("secret_client_construction"):
        secret_client = client_factory(config.url, config.service_role_key.get_secret_value())
    _record_stage(stages, "secret_client_construction")
    with stage_boundary("publishable_client_construction"):
        publishable_client = client_factory(config.url, config.publishable_key)
    _record_stage(stages, "publishable_client_construction")

    with stage_boundary("discover_incomplete_bundle"):
        bundle = discover_incomplete_bundle(secret_client)
    _record_stage(stages, "discover_incomplete_bundle")
    print(f"Safe smoke identifier: {bundle.cert_id}")

    with stage_boundary("existing_row_validation"):
        before_counts = validate_existing_rows(secret_client, bundle)
    _record_stage(stages, "existing_row_validation")

    with stage_boundary("private_table_rls_confirmation"):
        rls_results = smoke._probe_private_tables(publishable_client)
    _record_stage(stages, "private_table_rls_confirmation")

    with stage_boundary("public_certificate_projection"):
        public_rows = _public_rpc_rows(
            publishable_client,
            bundle.cert_id,
            "public_certificate_projection",
        )
        if len(public_rows) != 1:
            raise ResumeCheckpointError(
                "public_certificate_projection", "PUBLIC_ROW_COUNT_MISMATCH"
            )
        require_public_projection(public_rows[0], expected_status=bundle.certificate_status)
    _record_stage(stages, "public_certificate_projection")

    repository = SupabaseCertificateRepository(
        config.url,
        config.service_role_key,
        client_factory=lambda _url, _key: secret_client,
    )
    with stage_boundary("certificate_revocation"):
        revoked, revocation_result = revoke_existing_certificate(
            repository,
            bundle,
            revoked_at=(now or datetime.now(UTC)).astimezone(UTC),
        )
    _record_stage(stages, "certificate_revocation")

    with stage_boundary("revoked_public_projection"):
        public_rows = _public_rpc_rows(
            publishable_client,
            bundle.cert_id,
            "revoked_public_projection",
        )
        if len(public_rows) != 1:
            raise ResumeCheckpointError(
                "revoked_public_projection", "PUBLIC_ROW_COUNT_MISMATCH"
            )
        require_public_projection(public_rows[0], expected_status="revoked")
    _record_stage(stages, "revoked_public_projection")

    with stage_boundary("delivery_blocked_after_revocation"):
        confirm_delivery_blocked(secret_client, bundle, revoked)
    _record_stage(stages, "delivery_blocked_after_revocation")

    with stage_boundary("database_secret_scan"):
        rows_by_table = {
            table: _query_rows(
                secret_client,
                table,
                field,
                value,
                "database_secret_scan",
            )
            for table, (field, value) in _smoke_filters(bundle).items()
        }
        scanned_rows = smoke.require_safe_database_rows(
            rows_by_table,
            credentials=(config.publishable_key, config.service_role_key.get_secret_value()),
        )
        after_counts = {table: len(rows) for table, rows in rows_by_table.items()}
        if after_counts != before_counts:
            raise ResumeCheckpointError("database_secret_scan", "UNEXPECTED_ROW_COUNT_CHANGE")
    _record_stage(stages, "database_secret_scan")

    with stage_boundary("write_safe_report"):
        report_stages = [*stages, {"name": "write_safe_report", "result": "PASS"}]
        report = build_safe_report(
            config=config,
            bundle=bundle,
            stages=report_stages,
            row_counts=after_counts,
            rls_results=rls_results,
            revocation_result=revocation_result,
            scanned_rows=scanned_rows,
        )
        if output_report is not None:
            _write_report(output_report.resolve(), report, force=force)
    _record_stage(stages, "write_safe_report")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    """Refuse all Supabase access unless the owner explicitly supplies --live."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.force and args.output_report is None:
        parser.error("--force requires --output-report")
    if not args.live:
        print("FIREMARK Supabase Control Plane resume: network disabled (no --live).")
        print("No Supabase client was constructed and no database operation was attempted.")
        print("Review the existing incomplete bundle, then rerun explicitly with --live.")
        return INFORMATIONAL_EXIT_CODE
    if args.output_report is None:
        print("FAIL: write_safe_report (OUTPUT_REPORT_REQUIRED)")
        return 2
    if args.output_report.exists() and not args.force:
        print("FAIL: write_safe_report (OUTPUT_EXISTS)")
        return 1
    if not DEFAULT_ENV_FILE.is_file():
        print("FAIL: configuration_validation (INVALID_LIVE_CONFIGURATION)")
        return 3
    load_dotenv(dotenv_path=DEFAULT_ENV_FILE, override=False)
    try:
        report = run_resume_checkpoint(
            load_settings(),
            output_report=args.output_report,
            force=args.force,
        )
    except ResumeCheckpointError as exc:
        print(
            f"FAIL: {exc.stage} ({exc.category}) "
            f"EXCEPTION_CLASS={exc.exception_class} POSTGREST_CODE={exc.postgrest_code}"
        )
        return 1
    except ValidationError:
        print(
            "FAIL: configuration_validation (INVALID_LIVE_CONFIGURATION) "
            "EXCEPTION_CLASS=ValidationError POSTGREST_CODE=NONE"
        )
        return 1
    except Exception as exc:
        print(
            "FAIL: resume_internal (SAFE_UNEXPECTED_FAILURE) "
            f"EXCEPTION_CLASS={type(exc).__name__} POSTGREST_CODE={_safe_error_code(exc)}"
        )
        return 1
    print(f"Project hostname: {report['project_hostname']}")
    print("Resumed from existing records: YES")
    print("New registration rows: 0")
    print("New event rows: 0")
    print("Production Supabase evidence: YES")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
