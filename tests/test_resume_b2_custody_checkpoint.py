"""Zero-network tests for exact-version B2 custody checkpoint recovery."""

from __future__ import annotations

import hashlib
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

import scripts.resume_b2_custody_checkpoint as recovery
from api.firemark.settings import B2AssetsConfig, B2VaultConfig

ASSETS_BUCKET = "firemark-assets-7aaf6d30"
VAULT_BUCKET = "firemark-vault-7aaf6d30"
ASSETS_KEY_ID = "dummy-assets-identifier-never-print"
ASSETS_APP_KEY = "dummy-assets-secret-never-print"
VAULT_KEY_ID = "dummy-vault-identifier-never-print"
VAULT_APP_KEY = "dummy-vault-secret-never-print"
SERVICE_MESSAGE = "private service message must never print"
SOURCE_BYTES = b"persisted-local-source"
MANIFEST_BYTES = b'{"schema":"test","prompt":"private prompt must never print"}'
SOURCE_SHA = hashlib.sha256(SOURCE_BYTES).hexdigest()
MANIFEST_SHA = hashlib.sha256(MANIFEST_BYTES).hexdigest()
CANONICAL_HASH = "b" * 64
ASSETS_SOURCE_KEY = f"assets/{SOURCE_SHA[:2]}/{SOURCE_SHA[2:4]}/{SOURCE_SHA}.png"
ASSETS_MANIFEST_KEY = f"manifests/firemark-b2-local-fixture-run-v1/{CANONICAL_HASH}.json"
VAULT_SOURCE_KEY = f"vault/sources/{SOURCE_SHA[:2]}/{SOURCE_SHA[2:4]}/{SOURCE_SHA}.png"
VAULT_MANIFEST_KEY = f"vault/manifests/firemark-b2-local-fixture-run-v1/{CANONICAL_HASH}.json"
NOW = datetime(2026, 7, 29, 12, tzinfo=UTC)
SECRET_URL = (
    "https://s3.us-east-005.backblazeb2.com/private/object"
    "?X-Amz-Credential=must-not-print&X-Amz-Signature=must-not-print"
)


def complete_values() -> dict[str, str]:
    """Return dummy secrets and the fixed public checkpoint topology."""
    return {
        "B2_ENDPOINT": "https://s3.us-east-005.backblazeb2.com",
        "B2_REGION": "us-east-005",
        "B2_ASSETS_BUCKET": ASSETS_BUCKET,
        "B2_ASSETS_KEY_ID": ASSETS_KEY_ID,
        "B2_ASSETS_APP_KEY": ASSETS_APP_KEY,
        "B2_VAULT_BUCKET": VAULT_BUCKET,
        "B2_VAULT_KEY_ID": VAULT_KEY_ID,
        "B2_VAULT_APP_KEY": VAULT_APP_KEY,
        "FIREMARK_VAULT_RETENTION_DAYS": "1",
        "FIREMARK_PRESIGNED_URL_TTL_SECONDS": "300",
    }


def service_error(code: str, operation: str) -> ClientError:
    """Build an unsafe service response whose message must stay hidden."""
    return ClientError(
        {
            "Error": {"Code": code, "Message": SERVICE_MESSAGE},
            "ResponseMetadata": {
                "HTTPStatusCode": 403,
                "RequestId": "private-request-id",
                "HostId": "private-host-id",
            },
        },
        operation,
    )


def object_value(
    body: bytes,
    *,
    kind: str,
    content_type: str,
    version_id: str,
    retention_mode: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "Body": body,
        "ContentType": content_type,
        "VersionId": version_id,
        "LastModified": NOW - timedelta(minutes=5),
        "ETag": '"0123456789abcdef0123456789abcdef"',
        "Metadata": {
            "firemark-sha256": hashlib.sha256(body).hexdigest(),
            "firemark-kind": kind,
            "firemark-schema": "1",
        },
    }
    if retention_mode is not None:
        value["Retention"] = {
            "Mode": retention_mode,
            "RetainUntilDate": NOW + timedelta(days=1),
        }
    return value


class RecoveryClient:
    """In-memory version-aware client with no successful write other than exact delete."""

    def __init__(self, *, role: str, objects: dict[str, dict[str, Any]]) -> None:
        self.role = role
        self.objects = objects
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.errors: dict[str, Exception] = {}
        self.delete_markers: dict[str, list[str]] = {}
        self.version_page_size: int | None = None
        self.vault_delete_succeeds = False
        self.vanish_on_presign_key: str | None = None

    def _raise(self, operation: str) -> None:
        if operation in self.errors:
            raise self.errors[operation]

    def _item(self, key: str, version_id: str | None) -> dict[str, Any]:
        item = self.objects.get(key)
        if item is None:
            raise service_error("NoSuchKey", "HeadObject")
        if version_id is not None and item["VersionId"] != version_id:
            raise service_error("NoSuchVersion", "HeadObject")
        return item

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_objects_v2", kwargs))
        self._raise("list_objects_v2")
        return {
            "Contents": [{"Key": key} for key in self.objects],
            "IsTruncated": False,
        }

    def list_object_versions(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_object_versions", kwargs))
        self._raise("list_object_versions")
        prefix = kwargs["Prefix"]
        versions = [
            {"Key": key, "VersionId": item["VersionId"]}
            for key, item in self.objects.items()
            if key == prefix
        ]
        markers = [
            {"Key": prefix, "VersionId": version}
            for version in self.delete_markers.get(prefix, [])
        ]
        return {"Versions": versions, "DeleteMarkers": markers, "IsTruncated": False}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("head_object", kwargs))
        self._raise("head_object")
        item = self._item(kwargs["Key"], kwargs.get("VersionId"))
        return {
            "ContentLength": len(item["Body"]),
            "ContentType": item["ContentType"],
            "VersionId": item["VersionId"],
            "LastModified": item["LastModified"],
            "ETag": item["ETag"],
            "Metadata": dict(item["Metadata"]),
        }

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object", kwargs))
        self._raise("get_object")
        item = self._item(kwargs["Key"], kwargs.get("VersionId"))
        return {"Body": io.BytesIO(item["Body"])}

    def get_object_retention(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object_retention", kwargs))
        self._raise("get_object_retention")
        item = self._item(kwargs["Key"], kwargs.get("VersionId"))
        retention = item.get("Retention")
        return {} if retention is None else {"Retention": dict(retention)}

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object_lock_configuration", kwargs))
        self._raise("get_object_lock_configuration")
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    def generate_presigned_url(self, *args: Any, **kwargs: Any) -> str:
        self.calls.append(("generate_presigned_url", {"args": args, **kwargs}))
        self._raise("generate_presigned_url")
        if self.vanish_on_presign_key is not None:
            self.objects.pop(self.vanish_on_presign_key, None)
        return SECRET_URL

    def delete_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("delete_object", kwargs))
        self._raise("delete_object")
        if "VersionId" not in kwargs:
            raise AssertionError("Key-only deletion is forbidden")
        if self.role == "vault" and not self.vault_delete_succeeds:
            raise service_error("AccessDenied", "DeleteObject")
        item = self.objects.get(kwargs["Key"])
        if item is None or item["VersionId"] != kwargs["VersionId"]:
            raise service_error("NoSuchVersion", "DeleteObject")
        del self.objects[kwargs["Key"]]
        return {}


def valid_clients() -> tuple[RecoveryClient, RecoveryClient]:
    assets = RecoveryClient(
        role="assets",
        objects={
            ASSETS_SOURCE_KEY: object_value(
                SOURCE_BYTES,
                kind="source",
                content_type="image/png",
                version_id="assets-source-v1",
            ),
            ASSETS_MANIFEST_KEY: object_value(
                MANIFEST_BYTES,
                kind="manifest",
                content_type="application/json",
                version_id="assets-manifest-v1",
            ),
        },
    )
    vault = RecoveryClient(
        role="vault",
        objects={
            VAULT_SOURCE_KEY: object_value(
                SOURCE_BYTES,
                kind="source",
                content_type="image/png",
                version_id="vault-source-v1",
                retention_mode="COMPLIANCE",
            ),
            VAULT_MANIFEST_KEY: object_value(
                MANIFEST_BYTES,
                kind="manifest",
                content_type="application/json",
                version_id="vault-manifest-v1",
                retention_mode="COMPLIANCE",
            ),
        },
    )
    return assets, vault


def factories(
    assets: RecoveryClient,
    vault: RecoveryClient,
) -> tuple[recovery.AssetsFactory, recovery.VaultFactory]:
    def assets_factory(config: B2AssetsConfig) -> RecoveryClient:
        assert config.bucket == ASSETS_BUCKET
        return assets

    def vault_factory(config: B2VaultConfig) -> RecoveryClient:
        assert config.bucket == VAULT_BUCKET
        return vault

    return assets_factory, vault_factory


class DownloadProbe:
    """Verify redaction while returning a deterministic successful byte count."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, value: Any, endpoint: str, expected_sha256: str) -> int:
        self.calls.append((repr(value), endpoint, expected_sha256))
        assert SECRET_URL not in repr(value)
        assert SECRET_URL not in str(value)
        if self.fail:
            raise recovery.RecoveryCheckpointError("PRESIGNED_HASH_MISMATCH")
        return len(SOURCE_BYTES)


def run_with(
    assets: RecoveryClient | None = None,
    vault: RecoveryClient | None = None,
    *,
    values: dict[str, str] | None = None,
    downloader: recovery.PresignedDownloader | None = None,
    output_report: Path | None = None,
    force: bool = False,
) -> recovery.RecoveryOutcome:
    default_assets, default_vault = valid_clients()
    assets_client = assets or default_assets
    vault_client = vault or default_vault
    assets_factory, vault_factory = factories(assets_client, vault_client)
    return recovery.resume_values(
        values or complete_values(),
        assets_factory=assets_factory,
        vault_factory=vault_factory,
        downloader=downloader or DownloadProbe(),
        output_report=output_report,
        force=force,
        now=NOW,
    )


def calls_named(client: RecoveryClient, name: str) -> list[dict[str, Any]]:
    return [parameters for operation, parameters in client.calls if operation == name]


def test_non_live_mode_makes_zero_network_calls(capsys: pytest.CaptureFixture[str]) -> None:
    assert recovery.main([]) == 2
    output = capsys.readouterr().out
    assert "Checkpoint recovery is disabled" in output
    assert "RECOVERY_EXIT_CODE=2" in output
    assert "PASS" not in output


def test_help_is_available_without_configuration() -> None:
    with pytest.raises(SystemExit) as captured:
        recovery.main(["--help"])
    assert captured.value.code == 0


def test_success_uses_exact_vault_version_before_and_after_delete() -> None:
    assets, vault = valid_clients()
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 0
    vault_delete = calls_named(vault, "delete_object")
    assert vault_delete == [
        {"Bucket": VAULT_BUCKET, "Key": VAULT_MANIFEST_KEY, "VersionId": "vault-manifest-v1"}
    ]
    delete_index = next(
        index
        for index, (name, values) in enumerate(vault.calls)
        if name == "delete_object" and values.get("Key") == VAULT_MANIFEST_KEY
    )
    proof_start = delete_index - 2
    proof_calls = vault.calls[proof_start : proof_start + 5]
    assert [name for name, _values in proof_calls] == [
        "head_object",
        "get_object_retention",
        "delete_object",
        "head_object",
        "get_object_retention",
    ]
    assert all(values["VersionId"] == "vault-manifest-v1" for _name, values in proof_calls)


def test_key_only_vault_delete_is_never_used() -> None:
    _assets, vault = valid_clients()
    assert run_with(vault=vault).exit_code == 0
    assert all("VersionId" in call for call in calls_named(vault, "delete_object"))
    assert all("BypassGovernanceRetention" not in call for call in calls_named(vault, "delete_object"))


def test_missing_version_fails_closed_before_any_delete() -> None:
    assets, vault = valid_clients()
    assets.objects[ASSETS_SOURCE_KEY]["VersionId"] = "unsafe/version"
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 10
    assert outcome.stages[0].stage == "discover_existing_objects"
    assert not calls_named(assets, "delete_object")
    assert not calls_named(vault, "delete_object")


def test_successful_retained_version_delete_is_critical_failure() -> None:
    assets, vault = valid_clients()
    vault.vault_delete_succeeds = True
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 40
    assert outcome.stages[3].stage == "prove_versioned_delete_denial"
    assert outcome.stages[3].status == "FAIL"
    assert not calls_named(assets, "delete_object")


def test_delete_marker_can_coexist_with_retained_version() -> None:
    assets, vault = valid_clients()
    vault.delete_markers[VAULT_MANIFEST_KEY] = ["marker-v1", "marker-v2"]
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 0
    assert outcome.report is not None
    assert outcome.report["delete_marker_counts"]["vault_manifest"] == 2
    assert VAULT_MANIFEST_KEY in vault.objects


def test_marker_inspection_is_read_only_and_precedes_all_deletes() -> None:
    assets, vault = valid_clients()
    assert run_with(assets, vault).exit_code == 0
    combined = [("assets", *call) for call in assets.calls] + [
        ("vault", *call) for call in vault.calls
    ]
    assert len(calls_named(assets, "list_object_versions")) == 2
    assert len(calls_named(vault, "list_object_versions")) == 2
    assert all("VersionId" not in call for call in calls_named(assets, "list_object_versions"))
    assert any(role == "vault" and name == "delete_object" for role, name, _values in combined)


def test_assets_cleanup_uses_exact_versions_and_never_vault_client() -> None:
    assets, vault = valid_clients()
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 0
    assert calls_named(assets, "delete_object") == [
        {"Bucket": ASSETS_BUCKET, "Key": ASSETS_SOURCE_KEY, "VersionId": "assets-source-v1"},
        {
            "Bucket": ASSETS_BUCKET,
            "Key": ASSETS_MANIFEST_KEY,
            "VersionId": "assets-manifest-v1",
        },
    ]
    assert len(calls_named(vault, "delete_object")) == 1
    assert calls_named(vault, "delete_object")[0]["Key"] == VAULT_MANIFEST_KEY
    assert not assets.objects
    assert set(vault.objects) == {VAULT_SOURCE_KEY, VAULT_MANIFEST_KEY}


def test_exact_version_not_found_during_cleanup_is_idempotent() -> None:
    assets, vault = valid_clients()
    assets.vanish_on_presign_key = ASSETS_SOURCE_KEY
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 0
    assert [call["Key"] for call in calls_named(assets, "delete_object")] == [
        ASSETS_MANIFEST_KEY
    ]


def test_cleanup_runs_only_after_presigned_and_delete_proof_pass() -> None:
    assets, vault = valid_clients()
    outcome = run_with(assets, vault, downloader=DownloadProbe(fail=True))
    assert outcome.exit_code == 30
    assert not calls_named(assets, "delete_object")
    assert not calls_named(vault, "delete_object")


def test_cleanup_does_not_run_when_delete_proof_fails() -> None:
    assets, vault = valid_clients()
    vault.errors["delete_object"] = service_error("InvalidAccessKeyId", "DeleteObject")
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 40
    assert outcome.stages[3].service_error_code == "InvalidAccessKeyId"
    assert not calls_named(assets, "delete_object")


@pytest.mark.parametrize(("role", "kind"), [("assets", "source"), ("vault", "manifest")])
def test_missing_pair_is_rejected(role: str, kind: str) -> None:
    assets, vault = valid_clients()
    target = assets if role == "assets" else vault
    key = {
        ("assets", "source"): ASSETS_SOURCE_KEY,
        ("vault", "manifest"): VAULT_MANIFEST_KEY,
    }[(role, kind)]
    del target.objects[key]
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 10
    assert not calls_named(assets, "delete_object")


def test_ambiguous_source_pair_is_rejected() -> None:
    assets, vault = valid_clients()
    extra_key = f"assets/aa/bb/{'c' * 64}.png"
    assets.objects[extra_key] = object_value(
        SOURCE_BYTES,
        kind="source",
        content_type="image/png",
        version_id="assets-source-v2",
    )
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 10
    assert not calls_named(assets, "delete_object")


def test_mismatched_pair_bytes_are_rejected() -> None:
    assets, vault = valid_clients()
    different = b"different-source"
    item = vault.objects[VAULT_SOURCE_KEY]
    item["Body"] = different
    item["Metadata"]["firemark-sha256"] = hashlib.sha256(different).hexdigest()
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 10
    assert not calls_named(assets, "delete_object")


@pytest.mark.parametrize("mode", ["GOVERNANCE", "EXPIRED"])
def test_inactive_or_governance_retention_is_rejected(mode: str) -> None:
    assets, vault = valid_clients()
    retention = vault.objects[VAULT_MANIFEST_KEY]["Retention"]
    if mode == "EXPIRED":
        retention["RetainUntilDate"] = NOW - timedelta(seconds=1)
    else:
        retention["Mode"] = mode
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 10
    assert not calls_named(assets, "delete_object")
    assert not calls_named(vault, "delete_object")


def test_presigned_url_is_absent_from_stdout_repr_report_and_errors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assets, vault = valid_clients()
    outcome = run_with(assets, vault)
    recovery._print_outcome(outcome)
    output = capsys.readouterr().out
    assert SECRET_URL not in output
    assert SECRET_URL not in repr(outcome)
    assert outcome.report is not None
    assert SECRET_URL not in json.dumps(outcome.report)

    failed_assets, failed_vault = valid_clients()
    failed = run_with(failed_assets, failed_vault, downloader=DownloadProbe(fail=True))
    assert SECRET_URL not in repr(failed)


def test_presigned_hash_mismatch_prevents_cleanup() -> None:
    assets, vault = valid_clients()
    outcome = run_with(assets, vault, downloader=DownloadProbe(fail=True))
    assert outcome.stages[2] == recovery.RecoveryStageResult(
        "verify_presigned_download", "FAIL", "PRESIGNED_HASH_MISMATCH"
    )
    assert not calls_named(assets, "delete_object")


def test_no_upload_method_or_call_exists_in_recovery_source() -> None:
    source = Path(recovery.__file__).read_text(encoding="utf-8")
    assert ".put_object(" not in source
    assert ".upload_file(" not in source
    assert ".copy_object(" not in source


def test_stage_specific_marker_failure_remains_visible() -> None:
    assets, vault = valid_clients()
    assets.errors["list_object_versions"] = service_error("AccessDenied", "ListObjectVersions")
    outcome = run_with(assets, vault)
    assert outcome.exit_code == 20
    assert outcome.stages[1].stage == "inspect_delete_markers"
    assert outcome.stages[1].status == "FAIL"
    assert outcome.stages[1].service_error_code == "AccessDenied"
    assert not calls_named(assets, "delete_object")


def test_service_messages_request_ids_and_credentials_stay_hidden(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assets, vault = valid_clients()
    vault.errors["list_object_versions"] = service_error("AccessDenied", "ListObjectVersions")
    outcome = run_with(assets, vault)
    recovery._print_outcome(outcome)
    output = capsys.readouterr().out
    for forbidden in (
        SERVICE_MESSAGE,
        "private-request-id",
        "private-host-id",
        ASSETS_KEY_ID,
        ASSETS_APP_KEY,
        VAULT_KEY_ID,
        VAULT_APP_KEY,
    ):
        assert forbidden not in output
        assert forbidden not in repr(outcome)
    assert "service_error_code=AccessDenied" in output


def test_safe_report_is_written_only_after_success(tmp_path: Path) -> None:
    report_path = tmp_path / "resume-report.json"
    assets, vault = valid_clients()
    outcome = run_with(assets, vault, output_report=report_path)
    assert outcome.exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["resumed_from_existing_objects"] is True
    assert report["new_uploads"] == 0
    assert report["production_b2_custody_evidence"] is True
    assert report["assets_cleanup_result"] == "exact_versions_absent"
    assert SECRET_URL not in report_path.read_text(encoding="utf-8")

    failed_path = tmp_path / "failed-report.json"
    failed_assets, failed_vault = valid_clients()
    failed = run_with(
        failed_assets,
        failed_vault,
        downloader=DownloadProbe(fail=True),
        output_report=failed_path,
    )
    assert failed.exit_code == 30
    assert not failed_path.exists()


def test_existing_report_without_force_fails_before_network(tmp_path: Path) -> None:
    path = tmp_path / "existing.json"
    path.write_text("existing", encoding="utf-8")
    assets, vault = valid_clients()
    outcome = run_with(assets, vault, output_report=path)
    assert outcome.exit_code == 10
    assert not assets.calls
    assert not vault.calls
    assert path.read_text(encoding="utf-8") == "existing"


def test_force_replaces_report_only_after_success(tmp_path: Path) -> None:
    path = tmp_path / "existing.json"
    path.write_text("existing", encoding="utf-8")
    outcome = run_with(output_report=path, force=True)
    assert outcome.exit_code == 0
    assert json.loads(path.read_text(encoding="utf-8"))["new_uploads"] == 0


def test_all_documented_stage_names_and_success_order() -> None:
    outcome = run_with()
    assert tuple(item.stage for item in outcome.stages) == recovery.STAGES
    assert all(item.status == "PASS" for item in outcome.stages)
