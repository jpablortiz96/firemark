"""Zero-network tests for the isolated Generate & Seal B2 checkpoint."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from pydantic import SecretStr

import scripts.smoke_generate_and_seal_b2 as smoke
from api.firemark.b2_storage import (
    B2IntegrityError,
    B2InvalidMetadataError,
    B2OperationError,
    B2PersistedObjectError,
    B2RetentionError,
    B2VersionIdError,
    upload_bytes_verified,
)
from api.firemark.custody import LockedObjectReceipt, StoredObjectReceipt
from api.firemark.settings import B2AssetsConfig, B2VaultConfig, CompleteB2Config

NOW = datetime(2026, 7, 30, 12, tzinfo=UTC)


def config() -> CompleteB2Config:
    return CompleteB2Config(
        assets=B2AssetsConfig(
            endpoint="https://s3.test.invalid",
            region="test-region",
            bucket="assets-test",
            key_id=SecretStr("assets-key-id-private"),
            app_key=SecretStr("assets-app-key-private"),
            presigned_url_ttl_seconds=300,
        ),
        vault=B2VaultConfig(
            endpoint="https://s3.test.invalid",
            region="test-region",
            bucket="vault-test",
            key_id=SecretStr("vault-key-id-private"),
            app_key=SecretStr("vault-app-key-private"),
            retention_days=90,
        ),
    )


def wrapped_service_error(code: str) -> B2OperationError:
    response = {"Error": {"Code": code, "Message": "private raw service message"}}
    cause = ClientError(response, "PutObject")
    try:
        raise cause
    except ClientError as exc:
        try:
            raise B2OperationError("safe operation") from exc
        except B2OperationError as wrapped:
            return wrapped


def persisted_hash_error() -> B2PersistedObjectError:
    try:
        raise B2IntegrityError("private hash mismatch")
    except B2IntegrityError as exc:
        try:
            raise B2PersistedObjectError(
                key="vault/sources/safe.png",
                version_id="persisted-version-exact",
                retained=True,
            ) from exc
        except B2PersistedObjectError as wrapped:
            return wrapped


class Harness:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        failure_stage: str | None = None,
        error: Exception | None = None,
        missing_kind: str | None = None,
        wrong_bucket: bool = False,
    ) -> None:
        self.assets_client = object()
        self.vault_client = object()
        self.calls: list[tuple[str, Any, dict[str, Any]]] = []
        self.failure_stage = failure_stage
        self.error = error or RuntimeError("private raw service message")
        self.missing_kind = missing_kind
        self.wrong_bucket = wrong_bucket

        def locked(client: Any, **kwargs: Any) -> LockedObjectReceipt:
            kind = kwargs["metadata"]["firemark-kind"]
            self.calls.append((f"locked_{kind}", client, kwargs))
            assert client is self.vault_client
            assert kwargs["bucket"] == "vault-test"
            assert kwargs["content_type"] in {"image/png", "application/json"}
            assert kwargs["retention_until"] == NOW + timedelta(days=90)
            assert all(isinstance(value, str) for value in kwargs["metadata"].values())
            prefix = f"vault_{kind}"
            for stage in (
                f"{prefix}_upload",
                f"{prefix}_hash_verification",
                f"{prefix}_retention_verification",
            ):
                kwargs["stage_callback"](stage)
                if self.failure_stage == stage:
                    raise self.error
            if self.missing_kind == kind:
                raise B2VersionIdError("missing exact version")
            bucket = "wrong-vault" if self.wrong_bucket else kwargs["bucket"]
            return LockedObjectReceipt(
                bucket=bucket,
                key=kwargs["key"],
                sha256=kwargs["expected_sha256"],
                content_type=kwargs["content_type"],
                size_bytes=len(kwargs["data"]),
                version_id=f"{kind}-version-exact",
                created_at=NOW,
                retention_until=kwargs["retention_until"],
            )

        def sealed(client: Any, **kwargs: Any) -> StoredObjectReceipt:
            self.calls.append(("sealed", client, kwargs))
            assert client is self.assets_client
            assert kwargs["bucket"] == "assets-test"
            assert "ObjectLockMode" not in kwargs
            for stage in ("sealed_asset_upload", "sealed_asset_hash_verification"):
                kwargs["stage_callback"](stage)
                if self.failure_stage == stage:
                    raise self.error
            return StoredObjectReceipt(
                bucket="wrong-assets" if self.wrong_bucket else kwargs["bucket"],
                key=kwargs["key"],
                sha256=kwargs["expected_sha256"],
                content_type="image/png",
                size_bytes=len(kwargs["data"]),
                version_id=None if self.missing_kind == "sealed" else "sealed-version-exact",
                created_at=NOW,
            )

        def cleanup(client: Any, **kwargs: Any) -> bool:
            self.calls.append(("cleanup", client, kwargs))
            assert client is self.assets_client
            assert kwargs["version_id"] == "sealed-version-exact"
            assert kwargs["known_unlocked"] is True
            return True

        monkeypatch.setattr(smoke, "upload_locked_bytes", locked)
        monkeypatch.setattr(smoke, "upload_bytes_verified", sealed)
        monkeypatch.setattr(smoke, "delete_unlocked_version_verified", cleanup)

    def execute(self) -> smoke.CheckpointOutcome:
        return smoke.execute_checkpoint(
            config(),
            assets_factory=lambda _config: self.assets_client,
            vault_factory=lambda _config: self.vault_client,
            now=lambda: NOW,
            identifiers=lambda: (
                "firemark-run-b2-test",
                "firemark-asset-b2-test",
                "firemark-cert-b2-test",
            ),
        )


def test_non_live_is_informational_and_constructs_no_clients(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        smoke,
        "run_live",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("live path")),
    )
    assert smoke.main([]) == 2
    output = capsys.readouterr().out
    assert "zero network calls" in output
    assert "no B2 client was constructed" in output
    assert "OpenAI and Supabase were not called" in output


def test_success_uses_correct_clients_buckets_lock_scope_and_exact_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(monkeypatch)
    outcome = harness.execute()
    assert outcome.category == "OK"
    assert outcome.proof is not None
    assert tuple(row["stage"] for row in outcome.stages) == smoke.STAGES
    assert [name for name, _client, _kwargs in harness.calls] == [
        "locked_source",
        "locked_manifest",
        "sealed",
        "cleanup",
    ]
    assert all(client is harness.vault_client for name, client, _ in harness.calls if name.startswith("locked"))
    assert all(client is not harness.vault_client for name, client, _ in harness.calls if name in {"sealed", "cleanup"})


@pytest.mark.parametrize(
    ("stage", "error", "category"),
    [
        ("vault_source_upload", wrapped_service_error("AccessDenied"), "PERMISSION_DENIED"),
        ("vault_source_hash_verification", B2IntegrityError("private"), "HASH_MISMATCH"),
        (
            "vault_source_retention_verification",
            B2RetentionError("private"),
            "RETENTION_VERIFICATION_FAILURE",
        ),
        ("vault_manifest_upload", B2OperationError("private"), "UPLOAD_FAILURE"),
        ("vault_manifest_hash_verification", B2IntegrityError("private"), "HASH_MISMATCH"),
        (
            "vault_manifest_retention_verification",
            B2RetentionError("private"),
            "RETENTION_VERIFICATION_FAILURE",
        ),
        ("sealed_asset_upload", B2OperationError("private"), "UPLOAD_FAILURE"),
        ("sealed_asset_hash_verification", B2IntegrityError("private"), "HASH_MISMATCH"),
    ],
)
def test_each_remote_b2_stage_preserves_safe_failure(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    error: Exception,
    category: str,
) -> None:
    outcome = Harness(monkeypatch, failure_stage=stage, error=error).execute()
    assert outcome.category == category
    assert outcome.stages[-1] == {"stage": stage, "status": "FAIL"}


@pytest.mark.parametrize(
    ("kind", "expected_stage"),
    [
        ("source", "vault_source_retention_verification"),
        ("manifest", "vault_manifest_retention_verification"),
        ("sealed", "custody_receipt_construction"),
    ],
)
def test_missing_exact_version_fails_closed(
    monkeypatch: pytest.MonkeyPatch, kind: str, expected_stage: str
) -> None:
    outcome = Harness(monkeypatch, missing_kind=kind).execute()
    assert outcome.category == "VERSION_ID_MISSING"
    assert outcome.stages[-1] == {"stage": expected_stage, "status": "FAIL"}


def test_retention_rejection_and_invalid_metadata_are_distinct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = Harness(
        monkeypatch,
        failure_stage="vault_source_upload",
        error=wrapped_service_error("InvalidRequest"),
    ).execute()
    assert outcome.category == "RETENTION_REJECTED"

    class NoCalls:
        def put_object(self, **kwargs: object) -> object:
            raise AssertionError(kwargs)

    with pytest.raises(B2InvalidMetadataError):
        upload_bytes_verified(
            NoCalls(),  # type: ignore[arg-type]
            bucket="assets-test",
            key="sealed/test.png",
            data=b"body",
            expected_sha256=__import__("hashlib").sha256(b"body").hexdigest(),
            content_type="image/png",
            metadata={"unsafe_key": "value"},
        )


def test_wrong_bucket_is_rejected_during_receipt_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = Harness(monkeypatch, wrong_bucket=True).execute()
    assert outcome.category == "LOCAL_ADAPTER_ERROR"
    assert outcome.stages[-1] == {"stage": "custody_receipt_construction", "status": "FAIL"}


def test_failed_locked_readback_reports_exact_persisted_version_without_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(
        monkeypatch,
        failure_stage="vault_source_hash_verification",
        error=persisted_hash_error(),
    )
    outcome = harness.execute()
    assert outcome.category == "HASH_MISMATCH"
    assert outcome.partial_objects[0].version_id == "persisted-version-exact"
    assert outcome.partial_objects[0].retained is True
    assert "cleanup" not in [name for name, _client, _kwargs in harness.calls]


def test_broad_exception_output_excludes_raw_message_credentials_and_provenance(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "assets-app-key-private"
    raw = "private raw service message"
    outcome = Harness(
        monkeypatch,
        failure_stage="sealed_asset_upload",
        error=RuntimeError(f"{raw} {secret} private local fixture provenance"),
    ).execute()
    smoke._print_outcome(outcome)
    output = capsys.readouterr().out
    assert outcome.category == "UNKNOWN_SAFE_ERROR"
    assert raw not in output
    assert secret not in output
    assert "private local fixture provenance" not in output


def test_safe_report_has_only_safe_evidence_and_no_private_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome = Harness(monkeypatch).execute()
    assert outcome.proof is not None
    report = smoke._report(outcome.proof, outcome.stages, config())
    serialized = json.dumps(report)
    assert report["local_fixture"] is True
    assert report["ai_generated"] is False
    assert report["production_b2_generate_and_seal_evidence"] is True
    for forbidden in (
        "assets-app-key-private",
        "vault-app-key-private",
        "private local fixture provenance",
        "presigned",
        "authorization",
    ):
        assert forbidden not in serialized.lower()


def test_help_lists_live_report_and_force() -> None:
    help_text = smoke.build_parser().format_help()
    assert "--live" in help_text
    assert "--output-report" in help_text
    assert "--force" in help_text
