"""Zero-network tests for the persisted FIREMARK B2 smoke-state inspector."""

from __future__ import annotations

import hashlib
import io
import socket
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import (  # type: ignore[import-untyped]
    ClientError,
    ConnectTimeoutError,
    ReadTimeoutError,
    SSLError,
)

import scripts.inspect_b2_smoke_state as inspector
from api.firemark.settings import B2AssetsConfig, B2VaultConfig

ASSETS_KEY_ID = "dummy-assets-identifier-never-print"
ASSETS_APP_KEY = "dummy-assets-secret-never-print"
VAULT_KEY_ID = "dummy-vault-identifier-never-print"
VAULT_APP_KEY = "dummy-vault-secret-never-print"
SERVICE_MESSAGE = "private service message must never print"
PROMPT = "private generation prompt must never print"
SOURCE_BYTES = b"deterministic-source-bytes"
MANIFEST_BYTES = ('{"schema":"test","prompt":"' + PROMPT + '"}').encode()
SOURCE_SHA = hashlib.sha256(SOURCE_BYTES).hexdigest()
MANIFEST_SHA = hashlib.sha256(MANIFEST_BYTES).hexdigest()
ASSETS_SOURCE_KEY = f"assets/{SOURCE_SHA[:2]}/{SOURCE_SHA[2:4]}/{SOURCE_SHA}.png"
ASSETS_MANIFEST_KEY = f"manifests/test-run/{'a' * 64}.json"
VAULT_SOURCE_KEY = f"vault/sources/{SOURCE_SHA[:2]}/{SOURCE_SHA[2:4]}/{SOURCE_SHA}.png"
VAULT_MANIFEST_KEY = f"vault/manifests/test-run/{'a' * 64}.json"
NOW = datetime(2026, 7, 29, 12, tzinfo=UTC)


def complete_values() -> dict[str, str]:
    """Return dummy credentials and the fixed public checkpoint topology."""
    return {
        "B2_ENDPOINT": "https://s3.us-east-005.backblazeb2.com",
        "B2_REGION": "us-east-005",
        "B2_ASSETS_BUCKET": "firemark-assets-7aaf6d30",
        "B2_ASSETS_KEY_ID": ASSETS_KEY_ID,
        "B2_ASSETS_APP_KEY": ASSETS_APP_KEY,
        "B2_VAULT_BUCKET": "firemark-vault-7aaf6d30",
        "B2_VAULT_KEY_ID": VAULT_KEY_ID,
        "B2_VAULT_APP_KEY": VAULT_APP_KEY,
        "FIREMARK_VAULT_RETENTION_DAYS": "1",
        "FIREMARK_PRESIGNED_URL_TTL_SECONDS": "300",
    }


def client_error(code: str, status: int, operation: str) -> ClientError:
    """Create a service error containing fields that output must suppress."""
    return ClientError(
        {
            "Error": {"Code": code, "Message": SERVICE_MESSAGE},
            "ResponseMetadata": {
                "HTTPStatusCode": status,
                "RequestId": "private-request-id",
                "HostId": "private-host-id",
            },
        },
        operation,
    )


class TrackedBody(io.BytesIO):
    """Track bounded read sizes and explicit closure."""

    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.read_sizes: list[int] = []
        self.was_closed = False

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)

    def close(self) -> None:
        self.was_closed = True
        super().close()


class ReadOnlyClient:
    """Explicit in-memory client that exposes allowed reads and traps writes."""

    def __init__(self, objects: dict[str, dict[str, Any]] | None = None) -> None:
        self.objects = objects or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.errors: dict[str, Exception] = {}
        self.page_size: int | None = None
        self.lock_enabled = True
        self.last_bodies: list[TrackedBody] = []
        self.forbidden_calls: list[str] = []

    def _raise(self, operation: str) -> None:
        error = self.errors.get(operation)
        if error is not None:
            raise error

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_objects_v2", kwargs))
        self._raise("list_objects_v2")
        keys = list(self.objects)
        start = int(kwargs.get("ContinuationToken", "0"))
        size = self.page_size or max(1, len(keys))
        page = keys[start : start + size]
        next_index = start + len(page)
        response: dict[str, Any] = {
            "Contents": [{"Key": key} for key in page],
            "IsTruncated": next_index < len(keys),
        }
        if response["IsTruncated"]:
            response["NextContinuationToken"] = str(next_index)
        return response

    def list_object_versions(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_object_versions", kwargs))
        self._raise("list_object_versions")
        return {"Versions": []}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("head_object", kwargs))
        self._raise("head_object")
        item = self.objects[kwargs["Key"]]
        return {
            "ContentLength": item.get("HeadSize", len(item["Body"])),
            "ContentType": item["ContentType"],
            "VersionId": item["VersionId"],
            "LastModified": item["LastModified"],
            "ETag": item["ETag"],
            "Metadata": dict(item["Metadata"]),
        }

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object", kwargs))
        self._raise("get_object")
        body = TrackedBody(self.objects[kwargs["Key"]]["Body"])
        self.last_bodies.append(body)
        return {"Body": body}

    def get_object_retention(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object_retention", kwargs))
        self._raise("get_object_retention")
        retention = self.objects[kwargs["Key"]].get("Retention")
        return {} if retention is None else {"Retention": dict(retention)}

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object_lock_configuration", kwargs))
        self._raise("get_object_lock_configuration")
        state = "Enabled" if self.lock_enabled else "Disabled"
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": state}}

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.forbidden_calls.append("put_object")
        raise AssertionError("Inspector must not write objects")

    def upload_file(self, *args: Any, **kwargs: Any) -> None:
        self.forbidden_calls.append("upload_file")
        raise AssertionError("Inspector must not upload files")

    def copy_object(self, **kwargs: Any) -> dict[str, Any]:
        self.forbidden_calls.append("copy_object")
        raise AssertionError("Inspector must not copy objects")

    def delete_object(self, **kwargs: Any) -> dict[str, Any]:
        self.forbidden_calls.append("delete_object")
        raise AssertionError("Inspector must not delete objects")

    def generate_presigned_url(self, *args: Any, **kwargs: Any) -> str:
        self.forbidden_calls.append("generate_presigned_url")
        raise AssertionError("Inspector must not presign URLs")


def stored_object(
    body: bytes,
    *,
    kind: str,
    content_type: str,
    version: str,
    retention: str | None = None,
) -> dict[str, Any]:
    """Build one internally consistent current object."""
    value: dict[str, Any] = {
        "Body": body,
        "ContentType": content_type,
        "VersionId": version,
        "LastModified": NOW - timedelta(minutes=5),
        "ETag": '"0123456789abcdef0123456789abcdef"',
        "Metadata": {
            "firemark-sha256": hashlib.sha256(body).hexdigest(),
            "firemark-kind": kind,
            "firemark-schema": "1",
        },
    }
    if retention is not None:
        value["Retention"] = {
            "Mode": retention,
            "RetainUntilDate": NOW + timedelta(days=1),
        }
    return value


def valid_clients() -> tuple[ReadOnlyClient, ReadOnlyClient]:
    """Return the expected two-object state in each bucket."""
    assets = ReadOnlyClient(
        {
            ASSETS_SOURCE_KEY: stored_object(
                SOURCE_BYTES, kind="source", content_type="image/png", version="assets-source-v1"
            ),
            ASSETS_MANIFEST_KEY: stored_object(
                MANIFEST_BYTES,
                kind="manifest",
                content_type="application/json",
                version="assets-manifest-v1",
            ),
        }
    )
    vault = ReadOnlyClient(
        {
            VAULT_SOURCE_KEY: stored_object(
                SOURCE_BYTES,
                kind="source",
                content_type="image/png",
                version="vault-source-v1",
                retention="COMPLIANCE",
            ),
            VAULT_MANIFEST_KEY: stored_object(
                MANIFEST_BYTES,
                kind="manifest",
                content_type="application/json",
                version="vault-manifest-v1",
                retention="COMPLIANCE",
            ),
        }
    )
    return assets, vault


def factories(
    assets: ReadOnlyClient,
    vault: ReadOnlyClient,
) -> tuple[inspector.AssetsFactory, inspector.VaultFactory]:
    def assets_factory(config: B2AssetsConfig) -> ReadOnlyClient:
        assert config.bucket == "firemark-assets-7aaf6d30"
        return assets

    def vault_factory(config: B2VaultConfig) -> ReadOnlyClient:
        assert config.bucket == "firemark-vault-7aaf6d30"
        return vault

    return assets_factory, vault_factory


def run_with(
    assets: ReadOnlyClient | None = None,
    vault: ReadOnlyClient | None = None,
    values: dict[str, str] | None = None,
) -> inspector.InspectionReport:
    default_assets, default_vault = valid_clients()
    assets_client = assets if assets is not None else default_assets
    vault_client = vault if vault is not None else default_vault
    assets_factory, vault_factory = factories(assets_client, vault_client)
    return inspector.inspect_values(
        values or complete_values(),
        assets_factory=assets_factory,
        vault_factory=vault_factory,
        now=NOW,
    )


def find_record(
    report: inspector.InspectionReport, role: str, kind: str
) -> inspector.ObjectRecord:
    return next(item for item in report.objects if item.role == role and item.kind == kind)


def test_no_live_mode_makes_zero_network_calls(capsys: pytest.CaptureFixture[str]) -> None:
    assert inspector.main([]) == 2
    output = capsys.readouterr().out
    assert "Object inspection is disabled" in output
    assert "INSPECTION_EXIT_CODE=2" in output
    assert "LIKELY_FAILURE_WINDOW=INSUFFICIENT_EVIDENCE" in output
    assert "PASS" not in output


def test_help_does_not_load_configuration() -> None:
    with pytest.raises(SystemExit) as captured:
        inspector.main(["--help"])
    assert captured.value.code == 0


def test_missing_env_fails_safely(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(inspector, "DEFAULT_ENV_FILE", tmp_path / "missing.env")
    assert inspector.main(["--live"]) == 10
    output = capsys.readouterr().out
    assert "configuration_validation" in output
    assert "INSPECTION_EXIT_CODE=10" in output
    assert ASSETS_APP_KEY not in output


@pytest.mark.parametrize(
    "override",
    [
        {"B2_ASSETS_APP_KEY": ""},
        {"B2_ENDPOINT": "http://s3.us-east-005.backblazeb2.com"},
        {"B2_REGION": "wrong-region"},
        {"B2_VAULT_BUCKET": "firemark-assets-7aaf6d30"},
        {"B2_VAULT_APP_KEY": ASSETS_APP_KEY},
    ],
)
def test_incomplete_or_unsafe_configuration_fails_before_clients(
    override: dict[str, str],
) -> None:
    values = {**complete_values(), **override}
    assets, vault = valid_clients()
    report = run_with(assets, vault, values)
    assert report.exit_code == 10
    assert not assets.calls
    assert not vault.calls


def test_successful_discovery_of_two_objects_per_bucket() -> None:
    report = run_with()
    assert report.assets_object_count == 2
    assert report.vault_object_count == 2
    assert report.exit_code == 0
    assert report.likely_failure_window == "ALL_PERSISTED_OBJECTS_VALID_AND_RETAINED"
    assert report.assets_cleanup_pending == "YES"


@pytest.mark.parametrize("role", ["assets", "vault"])
def test_empty_bucket_reports_missing_expected_objects(role: str) -> None:
    assets, vault = valid_clients()
    if role == "assets":
        assets.objects.clear()
    else:
        vault.objects.clear()
    report = run_with(assets, vault)
    assert report.exit_code == 50
    assert report.likely_failure_window == "UPLOAD_OR_INTEGRITY_FAILURE"


def test_discovery_uses_pagination() -> None:
    assets, vault = valid_clients()
    assets.page_size = 1
    vault.page_size = 1
    report = run_with(assets, vault)
    assert report.exit_code == 0
    assert len([call for call in assets.calls if call[0] == "list_objects_v2"]) == 2
    assert len([call for call in vault.calls if call[0] == "list_objects_v2"]) == 2


@pytest.mark.parametrize(
    ("role", "key", "expected"),
    [
        ("assets", "assets/safe.png", "assets/safe.png"),
        ("assets", "manifests/run/safe.json", "manifests/run/safe.json"),
        ("assets", "public/cert/pointer.json", "public/cert/pointer.json"),
        ("vault", "vault/sources/safe.png", "vault/sources/safe.png"),
        ("vault", "vault/manifests/run/safe.json", "vault/manifests/run/safe.json"),
    ],
)
def test_allowed_key_prefixes(role: str, key: str, expected: str) -> None:
    assert inspector._safe_key(key, role=role) == expected


@pytest.mark.parametrize(
    "key",
    [
        "unexpected/object.png",
        "assets/control\ncharacter.png",
        "assets/file.png?credential=value",
        "assets/https://example.invalid/value",
        "assets/private-app-key-value",
        "assets/" + "a" * 1100,
    ],
)
def test_unexpected_or_unsafe_key_is_rejected(key: str) -> None:
    assert inspector._safe_key(key, role="assets") is None


def test_unsafe_key_is_never_printed(capsys: pytest.CaptureFixture[str]) -> None:
    assets, vault = valid_clients()
    unsafe = "assets/private-app-key-never-display"
    assets.objects = {unsafe: next(iter(assets.objects.values()))}
    report = run_with(assets, vault)
    inspector.print_report(report)
    output = capsys.readouterr().out
    assert unsafe not in output
    assert "[REDACTED_UNSAFE_KEY]" in output
    assert not any(call[0] == "head_object" for call in assets.calls)


def test_version_id_is_preserved_for_download_and_retention() -> None:
    assets, vault = valid_clients()
    report = run_with(assets, vault)
    source = find_record(report, "vault", "source")
    assert source.version_id == "vault-source-v1"
    source_get = next(
        call for call in vault.calls if call[0] == "get_object" and call[1]["Key"] == VAULT_SOURCE_KEY
    )
    source_retention = next(
        call
        for call in vault.calls
        if call[0] == "get_object_retention" and call[1]["Key"] == VAULT_SOURCE_KEY
    )
    assert source_get[1]["VersionId"] == "vault-source-v1"
    assert source_retention[1]["VersionId"] == "vault-source-v1"


def test_head_object_failure_is_safely_classified() -> None:
    assets, vault = valid_clients()
    assets.errors["head_object"] = client_error("AccessDenied", 403, "HeadObject")
    report = run_with(assets, vault)
    assert report.exit_code == 30
    assert any(failure.category == "PERMISSION_DENIED" for failure in report.failures)


def test_vault_retention_is_read_even_when_object_download_fails() -> None:
    assets, vault = valid_clients()
    vault.errors["get_object"] = client_error("AccessDenied", 403, "GetObject")
    report = run_with(assets, vault)
    assert report.exit_code == 40
    retention_keys = {
        call[1]["Key"] for call in vault.calls if call[0] == "get_object_retention"
    }
    assert retention_keys == {VAULT_SOURCE_KEY, VAULT_MANIFEST_KEY}
    assert report.vault_source_retention == "COMPLIANCE"
    assert report.vault_manifest_retention == "COMPLIANCE"


def test_streaming_is_bounded_and_response_body_is_closed() -> None:
    assets, vault = valid_clients()
    report = run_with(assets, vault)
    assert report.exit_code == 0
    for client in (assets, vault):
        assert client.last_bodies
        assert all(body.was_closed for body in client.last_bodies)
        assert all(
            size == inspector.STREAM_CHUNK_BYTES
            for body in client.last_bodies
            for size in body.read_sizes
        )


def test_oversized_object_is_rejected_without_download() -> None:
    assets, vault = valid_clients()
    assets.objects[ASSETS_SOURCE_KEY]["HeadSize"] = inspector.MAX_OBJECT_BYTES + 1
    report = run_with(assets, vault)
    source = find_record(report, "assets", "source")
    assert source.category == "OBJECT_TOO_LARGE"
    assert report.exit_code == 51
    assert not any(
        call[0] == "get_object" and call[1]["Key"] == ASSETS_SOURCE_KEY
        for call in assets.calls
    )


def test_sha256_metadata_match() -> None:
    report = run_with()
    assert all(item.metadata_sha_match == "PASS" for item in report.objects)
    assert all(item.byte_integrity == "PASS" for item in report.objects)


def test_sha256_metadata_mismatch() -> None:
    assets, vault = valid_clients()
    assets.objects[ASSETS_SOURCE_KEY]["Metadata"]["firemark-sha256"] = "0" * 64
    report = run_with(assets, vault)
    assert find_record(report, "assets", "source").metadata_sha_match == "FAIL"
    assert report.exit_code == 51


def test_missing_sha256_metadata() -> None:
    assets, vault = valid_clients()
    del assets.objects[ASSETS_SOURCE_KEY]["Metadata"]["firemark-sha256"]
    report = run_with(assets, vault)
    assert find_record(report, "assets", "source").metadata_sha_match == "MISSING"
    assert report.exit_code == 51


@pytest.mark.parametrize(("body", "expected"), [(b"{}", "PASS"), (b"not-json", "FAIL")])
def test_manifest_json_validation(body: bytes, expected: str) -> None:
    assets, vault = valid_clients()
    for client, key in ((assets, ASSETS_MANIFEST_KEY), (vault, VAULT_MANIFEST_KEY)):
        client.objects[key]["Body"] = body
        client.objects[key]["Metadata"]["firemark-sha256"] = hashlib.sha256(body).hexdigest()
    report = run_with(assets, vault)
    assert find_record(report, "assets", "manifest").manifest_json_valid == expected
    assert report.exit_code == (0 if expected == "PASS" else 51)


@pytest.mark.parametrize("kind", ["source", "manifest"])
def test_pair_correlation_passes(kind: str) -> None:
    report = run_with()
    result = report.source_pair_match if kind == "source" else report.manifest_pair_match
    assert result == "PASS"


def test_pair_correlation_fails_for_different_bytes_with_valid_local_hashes() -> None:
    assets, vault = valid_clients()
    different = b"different-source-bytes"
    vault.objects[VAULT_SOURCE_KEY]["Body"] = different
    vault.objects[VAULT_SOURCE_KEY]["Metadata"]["firemark-sha256"] = hashlib.sha256(
        different
    ).hexdigest()
    report = run_with(assets, vault)
    assert report.source_pair_match == "FAIL"
    assert report.exit_code == 52


def test_missing_pair_is_unknown_and_exit_50() -> None:
    assets, vault = valid_clients()
    del vault.objects[VAULT_MANIFEST_KEY]
    report = run_with(assets, vault)
    assert report.manifest_pair_match == "UNKNOWN"
    assert report.exit_code == 50


def test_active_compliance_retention() -> None:
    report = run_with()
    assert report.vault_source_retention == "COMPLIANCE"
    assert report.vault_manifest_retention == "COMPLIANCE"
    assert find_record(report, "vault", "source").retention_active == "YES"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("GOVERNANCE", "GOVERNANCE"),
        ("MISSING", "MISSING"),
        ("EXPIRED", "EXPIRED"),
    ],
)
def test_noncompliant_retention_is_reported(mutation: str, expected: str) -> None:
    assets, vault = valid_clients()
    item = vault.objects[VAULT_SOURCE_KEY]
    if mutation == "MISSING":
        item.pop("Retention")
    elif mutation == "EXPIRED":
        item["Retention"]["RetainUntilDate"] = NOW - timedelta(seconds=1)
    else:
        item["Retention"]["Mode"] = mutation
    report = run_with(assets, vault)
    assert report.vault_source_retention == expected
    assert report.exit_code == 53
    assert report.likely_failure_window == "VAULT_RETENTION_WRITE_OR_READBACK_FAILURE"


def test_retention_read_failure_uses_exit_41() -> None:
    assets, vault = valid_clients()
    vault.errors["get_object_retention"] = client_error(
        "AccessDenied", 403, "GetObjectRetention"
    )
    report = run_with(assets, vault)
    assert report.exit_code == 41
    assert report.vault_source_retention == "UNKNOWN"


@pytest.mark.parametrize(
    ("role", "error", "exit_code"),
    [
        ("assets", client_error("AccessDenied", 403, "ListObjectsV2"), 30),
        ("assets", client_error("InvalidAccessKeyId", 401, "ListObjectsV2"), 30),
        ("vault", client_error("AccessDenied", 403, "ListObjectsV2"), 40),
        ("assets", ConnectTimeoutError(endpoint_url="https://safe.invalid"), 20),
        ("assets", ReadTimeoutError(endpoint_url="https://safe.invalid"), 20),
        ("assets", socket.gaierror("private DNS message"), 20),
        ("assets", SSLError(endpoint_url="https://safe.invalid", error=ssl.SSLError()), 20),
    ],
)
def test_list_and_transport_failures_are_safely_mapped(
    role: str, error: Exception, exit_code: int
) -> None:
    assets, vault = valid_clients()
    target = assets if role == "assets" else vault
    target.errors["list_objects_v2"] = error
    report = run_with(assets, vault)
    assert report.exit_code == exit_code


def test_safe_output_excludes_bodies_secrets_prompts_and_service_messages(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assets, vault = valid_clients()
    assets.errors["head_object"] = client_error("AccessDenied", 403, "HeadObject")
    report = run_with(assets, vault)
    inspector.print_report(report)
    output = capsys.readouterr().out
    for forbidden in (
        SOURCE_BYTES.decode(),
        PROMPT,
        ASSETS_APP_KEY,
        ASSETS_KEY_ID,
        VAULT_APP_KEY,
        VAULT_KEY_ID,
        SERVICE_MESSAGE,
        "private-request-id",
        "private-host-id",
    ):
        assert forbidden not in output
    assert "service_error_code=AccessDenied" in output
    assert "http_status=403" in output


def test_no_forbidden_remote_method_is_called() -> None:
    assets, vault = valid_clients()
    report = run_with(assets, vault)
    assert report.exit_code == 0
    assert assets.forbidden_calls == []
    assert vault.forbidden_calls == []
    allowed = {
        "list_objects_v2",
        "head_object",
        "get_object",
        "get_object_retention",
        "get_object_lock_configuration",
    }
    assert {name for name, _parameters in assets.calls + vault.calls} <= allowed


def test_disabled_object_lock_uses_exit_53() -> None:
    assets, vault = valid_clients()
    vault.lock_enabled = False
    report = run_with(assets, vault)
    assert report.exit_code == 53
    assert report.likely_failure_window == "OBJECT_STATE_INCONSISTENT"


def test_documented_exit_code_mapping() -> None:
    assert {
        0,
        10,
        20,
        30,
        40,
        41,
        50,
        51,
        52,
        53,
        60,
    } == {0, 10, 20, 30, 40, 41, 50, 51, 52, 53, 60}


def test_printed_summary_contains_exact_required_fields(
    capsys: pytest.CaptureFixture[str],
) -> None:
    inspector.print_report(run_with())
    output = capsys.readouterr().out
    assert "ASSETS_OBJECT_COUNT=2" in output
    assert "VAULT_OBJECT_COUNT=2" in output
    assert "SOURCE_PAIR_MATCH=PASS" in output
    assert "MANIFEST_PAIR_MATCH=PASS" in output
    assert "VAULT_SOURCE_RETENTION=COMPLIANCE" in output
    assert "VAULT_MANIFEST_RETENTION=COMPLIANCE" in output
    assert "ASSETS_CLEANUP_PENDING=YES" in output
    assert "LIKELY_FAILURE_WINDOW=ALL_PERSISTED_OBJECTS_VALID_AND_RETAINED" in output
    assert "INSPECTION_EXIT_CODE=0" in output
