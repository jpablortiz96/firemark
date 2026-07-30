"""Zero-network tests for resuming the existing Supabase Control Plane checkpoint."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

import scripts.resume_supabase_control_plane_checkpoint as resume
import scripts.smoke_supabase_control_plane as smoke
from api.firemark.control_plane.models import VerificationRequest
from api.firemark.control_plane.service import CertificateService
from api.firemark.control_plane.supabase_repository import SupabaseCertificateRepository
from tests.test_smoke_supabase_control_plane import (
    PUBLISHABLE_KEY,
    SECRET_KEY,
    FakeBackend,
    FakeClient,
    FakeServiceError,
    live_settings,
)

NOW = datetime(2026, 7, 29, 20, 0, tzinfo=UTC)


def seed_incomplete_bundle(
    backend: FakeBackend,
    identifier: str = "resume",
) -> tuple[resume.ExistingBundle, SupabaseCertificateRepository]:
    evidence = smoke._build_evidence(identifier, NOW)
    client = FakeClient(backend, publishable=False)
    repository = SupabaseCertificateRepository(
        "https://project.supabase.co",
        SecretStr(SECRET_KEY),
        client_factory=lambda *_: client,
    )
    service = CertificateService(repository, public_base_url="https://verify.firemark.test")
    smoke._register(service, evidence)
    verification = service.verify(
        VerificationRequest(
            cert_id=evidence.envelope.cert_id,
            presented_sha256=evidence.asset.sealed_sha256,
        ),
        now=NOW + timedelta(seconds=1),
    )
    repository.record_delivery(
        cert_id=evidence.envelope.cert_id,
        verification_event_id=verification.verification_event_id,
        status="blocked",
        safe_reason_code="SMOKE_CHECKPOINT_NO_EXTERNAL_DELIVERY",
        expires_at=None,
        created_at=NOW + timedelta(seconds=2),
    )
    return (
        resume.ExistingBundle(
            run_id=evidence.generation_run.run_id,
            asset_id=evidence.asset.asset_id,
            cert_id=evidence.envelope.cert_id,
            certificate_status="active",
            revoked_at=None,
            revocation_reason=None,
        ),
        repository,
    )


def test_non_live_resume_is_zero_network_and_informational(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        resume,
        "_default_client_factory",
        lambda *_: pytest.fail("non-live resume must not construct a client"),
    )
    assert resume.main([]) == 2
    output = capsys.readouterr().out
    assert "network disabled" in output
    assert "No Supabase client was constructed" in output


def test_discovery_finds_one_existing_incomplete_bundle() -> None:
    backend = FakeBackend()
    expected, _ = seed_incomplete_bundle(backend)
    discovered = resume.discover_incomplete_bundle(FakeClient(backend, publishable=False))
    assert discovered == expected


def test_discovery_rejects_missing_and_ambiguous_bundles() -> None:
    empty = FakeBackend()
    with pytest.raises(resume.ResumeCheckpointError, match="INCOMPLETE_BUNDLE_NOT_FOUND"):
        resume.discover_incomplete_bundle(FakeClient(empty, publishable=False))

    ambiguous = FakeBackend()
    seed_incomplete_bundle(ambiguous, "first")
    seed_incomplete_bundle(ambiguous, "second")
    with pytest.raises(resume.ResumeCheckpointError, match="AMBIGUOUS_INCOMPLETE_BUNDLES"):
        resume.discover_incomplete_bundle(FakeClient(ambiguous, publishable=False))


def test_existing_row_validation_requires_bundle_and_event_rows() -> None:
    backend = FakeBackend()
    bundle, _ = seed_incomplete_bundle(backend)
    counts = resume.validate_existing_rows(FakeClient(backend, publishable=False), bundle)
    assert counts == {
        "generation_runs": 1,
        "assets": 1,
        "custody_records": 1,
        "certificates": 1,
        "verification_events": 1,
        "delivery_events": 1,
    }
    backend.tables["delivery_events"].clear()
    with pytest.raises(resume.ResumeCheckpointError, match="REQUIRED_EVENT_ROWS_MISSING"):
        resume.validate_existing_rows(FakeClient(backend, publishable=False), bundle)


def test_resume_revokes_projects_blocks_scans_and_writes_safe_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    backend = FakeBackend(rls_mode="denied")
    bundle, _ = seed_incomplete_bundle(backend)
    backend.operations.clear()
    report_path = tmp_path / "supabase-report.json"
    report = resume.run_resume_checkpoint(
        live_settings(),
        client_factory=backend.client_factory,
        output_report=report_path,
        now=NOW + timedelta(minutes=1),
    )
    assert [stage["name"] for stage in report["stage_results"]] == list(
        resume.RESUME_STAGES
    )
    assert report["revocation_result"] == "revoked_existing_certificate"
    assert report["public_rpc_allowlist_result"] is True
    assert report["database_secret_scan_result"] == {
        "passed": True,
        "smoke_rows_scanned": 6,
    }
    assert report["new_registration_rows"] == 0
    assert report["new_event_rows"] == 0
    assert report["resumed_from_existing_records"] is True
    assert report["table_row_counts"]["verification_events"] == 1
    assert report["table_row_counts"]["delivery_events"] == 1
    certificate = backend.tables["certificates"][0]
    assert certificate["certificate_status"] == "revoked"
    assert certificate["revocation_reason"] == resume.REVOCATION_REASON
    public = backend.public_certificate(bundle.cert_id)
    assert public[0]["certificate_status"] == "revoked"
    assert not any(
        operation[0] == "rpc" and operation[1] == "register_firemark_certificate_bundle"
        for operation in backend.operations
    )
    assert not any(
        operation[0] == "insert"
        and operation[1] in {"verification_events", "delivery_events"}
        for operation in backend.operations
    )
    persisted = report_path.read_text(encoding="utf-8")
    output = capsys.readouterr().out
    for credential in (PUBLISHABLE_KEY, SECRET_KEY):
        assert credential not in persisted
        assert credential not in output
    assert "private prompt" not in persisted
    assert "signed_envelope" not in persisted
    assert json.loads(persisted) == report


def test_already_identically_revoked_is_idempotent_without_second_update() -> None:
    backend = FakeBackend()
    bundle, repository = seed_incomplete_bundle(backend)
    repository.revoke_certificate(
        bundle.cert_id,
        reason=resume.REVOCATION_REASON,
        revoked_at=NOW + timedelta(minutes=1),
    )
    backend.operations.clear()
    report = resume.run_resume_checkpoint(
        live_settings(),
        client_factory=backend.client_factory,
        now=NOW + timedelta(minutes=2),
    )
    assert report["revocation_result"] == "already_identically_revoked"
    assert not any(operation[0] == "update" for operation in backend.operations)


def test_revocation_conflict_fails_closed() -> None:
    backend = FakeBackend()
    bundle, repository = seed_incomplete_bundle(backend)
    certificate = backend.tables["certificates"][0]
    certificate.update(
        {
            "certificate_status": "revoked",
            "revoked_at": (NOW + timedelta(minutes=1)).isoformat(),
            "revocation_reason": "DIFFERENT_SAFE_REASON",
        }
    )
    with pytest.raises(resume.ResumeCheckpointError, match="REVOCATION_CONFLICT"):
        resume.revoke_existing_certificate(
            repository,
            bundle,
            revoked_at=NOW + timedelta(minutes=2),
        )


def test_safe_exception_normalization_never_prints_raw_service_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    raw_message = f"raw service message {SECRET_KEY}"

    class ExplodingBuilder:
        def execute(self) -> Any:
            raise FakeServiceError("PGRST_TEST") from RuntimeError(raw_message)

    with pytest.raises(resume.ResumeCheckpointError) as raised:
        resume._execute(ExplodingBuilder(), "database_secret_scan")
    assert raised.value.stage == "database_secret_scan"
    assert raised.value.category == "SERVICE_OPERATION_FAILED"
    assert raised.value.exception_class == "FakeServiceError"
    assert raised.value.postgrest_code == "PGRST_TEST"
    assert raw_message not in str(raised.value)
    assert SECRET_KEY not in capsys.readouterr().out


def test_resume_source_has_no_registration_or_database_event_insert_calls() -> None:
    source = Path(resume.__file__).read_text(encoding="utf-8")
    assert "register_firemark_certificate_bundle" not in source
    assert '.table("verification_events").insert' not in source
    assert '.table("delivery_events").insert' not in source
