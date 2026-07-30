"""Tests for immutable B2 custody receipts and the four-object workflow."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from api.firemark.custody import (
    B2CustodyReceipt,
    B2CustodyWorkflowError,
    LockedDeleteProof,
    LockedObjectReceipt,
    StoredObjectReceipt,
    execute_b2_custody,
)
from api.firemark.hashing import sha256_bytes, sha256_file
from scripts.smoke_b2_custody import main as smoke_main
from scripts.smoke_genblaze_roundtrip import (
    LOCAL_RUN_ID,
    build_local_fixture_manifest,
    create_deterministic_png,
)
from tests.conftest import FakeS3Client, service_error


def _stored(*, bucket: str, key: str, digest: str) -> StoredObjectReceipt:
    return StoredObjectReceipt(
        bucket=bucket,
        key=key,
        sha256=digest,
        content_type="application/octet-stream",
        size_bytes=12,
        version_id="version-1",
        etag='"not-a-sha"',
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _locked(*, bucket: str, key: str, digest: str) -> LockedObjectReceipt:
    return LockedObjectReceipt(
        **_stored(bucket=bucket, key=key, digest=digest).model_dump(),
        retention_until=datetime(2030, 1, 1, tzinfo=UTC),
        retention_verified=True,
    )


def _receipt() -> B2CustodyReceipt:
    source_digest = "a" * 64
    manifest_digest = "b" * 64
    return B2CustodyReceipt(
        source_sha256=source_digest,
        canonical_hash="c" * 64,
        assets_source=_stored(bucket="assets-test", key="assets/source.png", digest=source_digest),
        assets_manifest=_stored(
            bucket="assets-test", key="manifests/run.json", digest=manifest_digest
        ),
        vault_source=_locked(bucket="vault-test", key="vault/source.png", digest=source_digest),
        vault_manifest=_locked(
            bucket="vault-test", key="vault/manifest.json", digest=manifest_digest
        ),
        requested_retention_until=datetime(2029, 12, 31, tzinfo=UTC),
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        custody_verified=True,
    )


def test_receipts_are_frozen_forbid_extra_and_redact_no_hidden_data() -> None:
    receipt = _receipt()
    with pytest.raises(ValidationError, match="frozen"):
        receipt.custody_verified = False
    values = receipt.model_dump()
    values["presigned_url"] = "https://must-not-appear.invalid"
    with pytest.raises(ValidationError, match="Extra inputs"):
        B2CustodyReceipt.model_validate(values)
    serialized = receipt.canonical_bytes().decode("utf-8")
    assert "X-Amz" not in serialized
    assert "application_key" not in serialized
    assert "prompt" not in serialized


def test_canonical_bytes_are_deterministic_sorted_and_utc() -> None:
    receipt = _receipt()
    first = receipt.canonical_bytes()
    second = B2CustodyReceipt.model_validate(
        dict(reversed(list(receipt.model_dump().items())))
    ).canonical_bytes()
    assert first == second
    decoded = json.loads(first)
    assert decoded["created_at"] == "2026-01-01T00:00:00.000000Z"
    assert first.index(b'"assets_manifest"') < first.index(b'"assets_source"')


def test_timestamps_normalize_and_naive_values_are_rejected() -> None:
    values = _stored(bucket="assets-test", key="key", digest="a" * 64).model_dump()
    values["created_at"] = datetime(2025, 12, 31, 19, tzinfo=timezone(timedelta(hours=-5)))
    assert StoredObjectReceipt.model_validate(values).created_at == datetime(2026, 1, 1, tzinfo=UTC)
    values["created_at"] = datetime(2026, 1, 1)
    with pytest.raises(ValidationError, match="timezone-aware"):
        StoredObjectReceipt.model_validate(values)


@pytest.mark.parametrize(
    "mutation",
    [
        {"source_sha256": "d" * 64},
        {"canonical_hash": "UPPER"},
        {"custody_verified": True, "vault_source": None},
    ],
)
def test_receipt_relationships_fail_closed(mutation: dict[str, object]) -> None:
    values = _receipt().model_dump()
    values.update(mutation)
    with pytest.raises(ValidationError):
        B2CustodyReceipt.model_validate(values)


def test_duplicate_locations_and_mismatched_manifest_bytes_are_rejected() -> None:
    receipt = _receipt()
    values = receipt.model_dump()
    values["vault_manifest"]["key"] = receipt.vault_source.key
    values["vault_manifest"]["sha256"] = receipt.vault_source.sha256
    with pytest.raises(ValidationError):
        B2CustodyReceipt.model_validate(values)

    values = receipt.model_dump()
    values["vault_manifest"]["sha256"] = "d" * 64
    with pytest.raises(ValidationError, match="manifest bytes"):
        B2CustodyReceipt.model_validate(values)


def test_locked_receipt_and_delete_proof_cannot_be_forged() -> None:
    values = _locked(bucket="vault-test", key="vault/key", digest="a" * 64).model_dump()
    values["version_id"] = None
    with pytest.raises(ValidationError, match="VersionId"):
        LockedObjectReceipt.model_validate(values)
    values = _locked(bucket="vault-test", key="vault/key", digest="a" * 64).model_dump()
    values["retention_mode"] = "GOVERNANCE"
    with pytest.raises(ValidationError):
        LockedObjectReceipt.model_validate(values)
    values = LockedDeleteProof(
        bucket="vault-test",
        key="vault/key",
        version_id="version-1",
        error_code="AccessDenied",
        safe_error_category="active_compliance_retention",
        retention_mode="COMPLIANCE",
        retention_until=datetime(2030, 1, 1, tzinfo=UTC),
        object_exists_after_attempt=True,
        retention_exists_after_attempt=True,
        verified=True,
    ).model_dump()
    values["verified"] = False
    with pytest.raises(ValidationError):
        LockedDeleteProof.model_validate(values)


def _fixture_manifest(tmp_path: Path) -> tuple[Path, str, bytes, str]:
    source = tmp_path / "fixture.png"
    create_deterministic_png(source)
    source_digest = sha256_file(source)
    manifest = build_local_fixture_manifest(source, source_digest)
    return source, source_digest, manifest.to_canonical_json().encode(), manifest.canonical_hash


def test_complete_custody_workflow_verifies_four_objects(tmp_path: Path) -> None:
    source, source_digest, manifest_bytes, canonical_hash = _fixture_manifest(tmp_path)
    assets = FakeS3Client()
    vault = FakeS3Client()
    persisted: list[tuple[object, ...]] = []
    receipt = execute_b2_custody(
        assets_client=assets,
        vault_client=vault,
        assets_bucket="assets-test",
        vault_bucket="vault-test",
        source_path=source,
        manifest_bytes=manifest_bytes,
        source_sha256=source_digest,
        canonical_hash=canonical_hash,
        run_id=LOCAL_RUN_ID,
        cert_id="cert-1",
        extension="png",
        retention_until=datetime.now(UTC) + timedelta(days=1),
        source_content_type="image/png",
        now=datetime(2026, 1, 1, tzinfo=UTC),
        persistence_callback=persisted.append,
    )
    assert receipt.custody_verified is True
    assert receipt.source_sha256 == source_digest
    assert receipt.canonical_hash == canonical_hash
    assert receipt.assets_manifest.sha256 == sha256_bytes(manifest_bytes)
    assert receipt.vault_manifest.sha256 == sha256_bytes(manifest_bytes)
    assert len(assets.objects) == 2
    assert len(vault.objects) == 2
    assert [len(snapshot) for snapshot in persisted] == [1, 2, 3, 4]
    assert persisted[-1][-1].bucket_role == "vault"
    assert persisted[-1][-1].object_kind == "manifest"
    assert persisted[-1][-1].version_id == receipt.vault_manifest.version_id

    second = execute_b2_custody(
        assets_client=assets,
        vault_client=vault,
        assets_bucket="assets-test",
        vault_bucket="vault-test",
        source_path=source,
        manifest_bytes=manifest_bytes,
        source_sha256=source_digest,
        canonical_hash=canonical_hash,
        run_id=LOCAL_RUN_ID,
        cert_id="cert-1",
        extension="png",
        retention_until=receipt.requested_retention_until,
        source_content_type="image/png",
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert second.canonical_bytes() == receipt.canonical_bytes()
    assert len(assets.objects) == 2
    assert len(vault.objects) == 2


def test_workflow_rejects_source_and_manifest_conflicts(tmp_path: Path) -> None:
    source, source_digest, manifest_bytes, canonical_hash = _fixture_manifest(tmp_path)
    common = {
        "assets_client": FakeS3Client(),
        "vault_client": FakeS3Client(),
        "assets_bucket": "assets-test",
        "vault_bucket": "vault-test",
        "source_path": source,
        "manifest_bytes": manifest_bytes,
        "source_sha256": source_digest,
        "canonical_hash": canonical_hash,
        "run_id": LOCAL_RUN_ID,
        "cert_id": "cert-1",
        "extension": "png",
        "retention_until": datetime.now(UTC) + timedelta(days=1),
        "source_content_type": "image/png",
    }
    with pytest.raises(B2CustodyWorkflowError, match="source_sha256"):
        execute_b2_custody(**{**common, "source_sha256": "0" * 64})
    with pytest.raises(B2CustodyWorkflowError, match="canonical_hash"):
        execute_b2_custody(**{**common, "canonical_hash": "0" * 64})


def test_partial_workflow_failure_cleans_assets_but_never_vault(tmp_path: Path) -> None:
    source, source_digest, manifest_bytes, canonical_hash = _fixture_manifest(tmp_path)
    assets = FakeS3Client()
    assets.delete_error_code = None
    vault = FakeS3Client()
    vault.raise_for["put_object"] = service_error("AccessDenied", "PutObject")
    with pytest.raises(B2CustodyWorkflowError) as captured:
        execute_b2_custody(
            assets_client=assets,
            vault_client=vault,
            assets_bucket="assets-test",
            vault_bucket="vault-test",
            source_path=source,
            manifest_bytes=manifest_bytes,
            source_sha256=source_digest,
            canonical_hash=canonical_hash,
            run_id=LOCAL_RUN_ID,
            cert_id="cert-1",
            extension="png",
            retention_until=datetime.now(UTC) + timedelta(days=1),
            source_content_type="image/png",
        )
    assert len(captured.value.partial_keys) == 2
    assert [name for name, _ in assets.calls].count("delete_object") == 2
    assert all(values.get("VersionId") for name, values in assets.calls if name == "delete_object")
    assert "delete_object" not in [name for name, _ in vault.calls]


def test_non_live_smoke_refuses_network_without_claiming_pass(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert smoke_main([]) == 2
    output = capsys.readouterr().out
    assert "network disabled" in output
    assert "--live" in output
    assert "PASS" not in output
    assert "application key" not in output.lower()
    assert "X-Amz" not in output
