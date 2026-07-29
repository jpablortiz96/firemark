"""Zero-network tests for the read-only B2 access diagnostic."""

from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import (  # type: ignore[import-untyped]
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
    SSLError,
)

import scripts.diagnose_b2_access as diagnostic
from api.firemark.settings import B2AssetsConfig, B2VaultConfig

ASSETS_KEY_ID = "dummy-assets-key-id-never-print"
ASSETS_APP_KEY = "dummy-assets-application-key-never-print"
VAULT_KEY_ID = "dummy-vault-key-id-never-print"
VAULT_APP_KEY = "dummy-vault-application-key-never-print"
SECRET_OBJECT_NAME = "private-object-name-must-not-print"
SECRET_SERVICE_MESSAGE = "service message with private request data must not print"
SECRET_QUERY_URL = "https://s3.test.invalid/path?X-Amz-Signature=must-not-print"


def complete_values() -> dict[str, str]:
    """Return complete dummy values matching only the authorized public topology."""
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
    """Return a service error carrying unsafe fields the diagnostic must suppress."""
    return ClientError(
        {
            "Error": {"Code": code, "Message": SECRET_SERVICE_MESSAGE},
            "ResponseMetadata": {
                "HTTPStatusCode": status,
                "RequestId": "request-id-must-not-print",
                "HostId": "host-id-must-not-print",
            },
        },
        operation,
    )


class ReadOnlyClient:
    """Explicit read-only double that fails if a forbidden operation is attempted."""

    def __init__(
        self,
        *,
        head_error: Exception | None = None,
        list_error: Exception | None = None,
        lock_error: Exception | None = None,
        key_count: int = 1,
        lock_state: str | None = "Enabled",
    ) -> None:
        self.head_error = head_error
        self.list_error = list_error
        self.lock_error = lock_error
        self.key_count = key_count
        self.lock_state = lock_state
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.forbidden_calls: list[str] = []

    def head_bucket(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("head_bucket", kwargs))
        if self.head_error is not None:
            raise self.head_error
        return {}

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_objects_v2", kwargs))
        if self.list_error is not None:
            raise self.list_error
        return {
            "KeyCount": self.key_count,
            "Contents": [{"Key": SECRET_OBJECT_NAME}],
        }

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object_lock_configuration", kwargs))
        if self.lock_error is not None:
            raise self.lock_error
        configuration: dict[str, str] = {}
        if self.lock_state is not None:
            configuration["ObjectLockEnabled"] = self.lock_state
        return {"ObjectLockConfiguration": configuration}

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.forbidden_calls.append("put_object")
        raise AssertionError("Diagnostic must not call put_object")

    def delete_object(self, **kwargs: Any) -> dict[str, Any]:
        self.forbidden_calls.append("delete_object")
        raise AssertionError("Diagnostic must not call delete_object")

    def generate_presigned_url(self, *args: Any, **kwargs: Any) -> str:
        self.forbidden_calls.append("generate_presigned_url")
        raise AssertionError("Diagnostic must not generate presigned URLs")


def factories(
    assets: ReadOnlyClient,
    vault: ReadOnlyClient,
) -> tuple[diagnostic.AssetsFactory, diagnostic.VaultFactory]:
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
) -> diagnostic.DiagnosticReport:
    assets_client = assets or ReadOnlyClient()
    vault_client = vault or ReadOnlyClient()
    assets_factory, vault_factory = factories(assets_client, vault_client)
    return diagnostic.diagnose_values(
        values or complete_values(),
        assets_factory=assets_factory,
        vault_factory=vault_factory,
    )


def result(report: diagnostic.DiagnosticReport, stage: str) -> diagnostic.StageResult:
    return next(item for item in report.results if item.stage == stage)


def test_no_live_is_zero_network_and_informational(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert diagnostic.main([]) == 2
    output = capsys.readouterr().out
    assert "Diagnostic network access is disabled" in output
    assert "DIAGNOSTIC_EXIT_CODE=2" in output
    assert "OVERALL_CATEGORY=NETWORK_DISABLED" in output
    assert "PASS" not in output


def test_help_is_available_without_loading_configuration() -> None:
    with pytest.raises(SystemExit) as captured:
        diagnostic.main(["--help"])
    assert captured.value.code == 0


def test_missing_env_fails_safely(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(diagnostic, "DEFAULT_ENV_FILE", tmp_path / "missing.env")
    assert diagnostic.main(["--live"]) == 10
    output = capsys.readouterr().out
    assert "configuration_validation           FAIL" in output
    assert "CONFIGURATION_ERROR" in output
    assert ASSETS_APP_KEY not in output


def test_success_runs_every_read_only_stage_and_only_safe_methods() -> None:
    assets = ReadOnlyClient(key_count=1)
    vault = ReadOnlyClient(key_count=1)
    report = run_with(assets, vault)

    assert report.exit_code == 0
    assert report.overall_category == "OK"
    assert tuple(item.stage for item in report.results) == diagnostic.STAGES
    assert all(item.status == "PASS" for item in report.results)
    assert assets.calls == [
        ("head_bucket", {"Bucket": "firemark-assets-7aaf6d30"}),
        ("list_objects_v2", {"Bucket": "firemark-assets-7aaf6d30", "MaxKeys": 1}),
    ]
    assert vault.calls == [
        ("head_bucket", {"Bucket": "firemark-vault-7aaf6d30"}),
        ("list_objects_v2", {"Bucket": "firemark-vault-7aaf6d30", "MaxKeys": 1}),
        ("get_object_lock_configuration", {"Bucket": "firemark-vault-7aaf6d30"}),
    ]
    assert assets.forbidden_calls == []
    assert vault.forbidden_calls == []
    assert result(report, "assets_list_probe").key_count == 1
    assert result(report, "vault_object_lock_configuration").object_lock_state == "Enabled"


@pytest.mark.parametrize(
    ("mutation", "expected_stage", "expected_category", "exit_code"),
    [
        ({"B2_ASSETS_APP_KEY": ""}, "configuration_validation", "CONFIGURATION_ERROR", 10),
        ({"B2_ENDPOINT": "http://s3.us-east-005.backblazeb2.com"}, "endpoint_validation", "HTTPS_REQUIRED", 20),
        ({"B2_ENDPOINT": SECRET_QUERY_URL}, "endpoint_validation", "HTTPS_REQUIRED", 20),
        ({"B2_ASSETS_BUCKET": "firemark-vault-7aaf6d30"}, "configuration_validation", "CONFIGURATION_ERROR", 10),
        ({"B2_ASSETS_BUCKET": "unexpected-assets"}, "configuration_validation", "REGION_OR_ENDPOINT_MISMATCH", 20),
        ({"B2_ASSETS_KEY_ID": VAULT_KEY_ID}, "credential_separation_validation", "CREDENTIALS_NOT_SEPARATE", 50),
        ({"B2_ASSETS_APP_KEY": VAULT_APP_KEY}, "credential_separation_validation", "CREDENTIALS_NOT_SEPARATE", 50),
    ],
)
def test_configuration_endpoint_and_separation_failures(
    mutation: dict[str, str],
    expected_stage: str,
    expected_category: str,
    exit_code: int,
) -> None:
    values = complete_values()
    values.update(mutation)
    report = run_with(values=values)
    assert report.exit_code == exit_code
    assert result(report, expected_stage).category == expected_category
    assert result(report, "assets_client_construction").status == "SKIP"


def test_assets_head_403_with_list_success_is_compatibility_limitation() -> None:
    assets = ReadOnlyClient(
        head_error=client_error("AccessDenied", 403, "HeadBucket"),
    )
    report = run_with(assets=assets)
    stage = result(report, "assets_head_bucket")
    assert report.exit_code == 31
    assert stage.category == "HEAD_BUCKET_PERMISSION_OR_COMPATIBILITY_LIMITATION"
    assert stage.service_error_code == "AccessDenied"
    assert stage.http_status == 403


def test_assets_head_and_list_access_denied_are_not_overclassified() -> None:
    assets = ReadOnlyClient(
        head_error=client_error("AccessDenied", 403, "HeadBucket"),
        list_error=client_error("AccessDenied", 403, "ListObjectsV2"),
    )
    report = run_with(assets=assets)
    assert report.exit_code == 30
    assert result(report, "assets_head_bucket").category == "PERMISSION_DENIED"
    assert result(report, "assets_list_probe").category == "PERMISSION_DENIED"


def test_assets_bucket_not_found_is_preserved_safely() -> None:
    assets = ReadOnlyClient(
        head_error=client_error("NoSuchBucket", 404, "HeadBucket"),
    )
    report = run_with(assets=assets)
    assert report.exit_code == 30
    assert result(report, "assets_head_bucket").category == "BUCKET_NOT_FOUND"


def test_vault_head_403_with_list_success_is_compatibility_limitation() -> None:
    vault = ReadOnlyClient(head_error=client_error("AccessDenied", 403, "HeadBucket"))
    report = run_with(vault=vault)
    assert report.exit_code == 41
    assert result(report, "vault_head_bucket").category == (
        "HEAD_BUCKET_PERMISSION_OR_COMPATIBILITY_LIMITATION"
    )


def test_vault_list_permission_is_correlated_with_successful_head() -> None:
    vault = ReadOnlyClient(list_error=client_error("AccessDenied", 403, "ListObjectsV2"))
    report = run_with(vault=vault)
    assert report.exit_code == 40
    assert result(report, "vault_list_probe").category == "MISSING_LIST_PERMISSION"


def test_object_lock_enabled_disabled_and_missing_permission() -> None:
    assert run_with().exit_code == 0

    disabled = run_with(vault=ReadOnlyClient(lock_state="Disabled"))
    assert disabled.exit_code == 43
    assert result(disabled, "vault_object_lock_configuration").category == "OBJECT_LOCK_DISABLED"

    missing = run_with(
        vault=ReadOnlyClient(
            lock_error=client_error("AccessDenied", 403, "GetObjectLockConfiguration")
        )
    )
    assert missing.exit_code == 42
    assert result(missing, "vault_object_lock_configuration").category == (
        "MISSING_READ_BUCKET_RETENTIONS"
    )


def chained_endpoint_error(cause: Exception) -> EndpointConnectionError:
    try:
        raise cause
    except Exception as exc:
        try:
            raise EndpointConnectionError(endpoint_url=SECRET_QUERY_URL) from exc
        except EndpointConnectionError as wrapped:
            return wrapped


@pytest.mark.parametrize(
    ("failure", "category"),
    [
        (chained_endpoint_error(socket.gaierror("dummy DNS failure")), "DNS_FAILURE"),
        (SSLError(endpoint_url=SECRET_QUERY_URL, error=ssl.SSLError("dummy TLS failure")), "TLS_FAILURE"),
        (ConnectTimeoutError(endpoint_url=SECRET_QUERY_URL), "CONNECTION_TIMEOUT"),
        (ReadTimeoutError(endpoint_url=SECRET_QUERY_URL, error=TimeoutError()), "READ_TIMEOUT"),
    ],
)
def test_transport_failures_are_normalized_without_endpoint_output(
    failure: Exception,
    category: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = run_with(assets=ReadOnlyClient(head_error=failure))
    assert report.exit_code == 20
    assert result(report, "assets_head_bucket").category == category
    diagnostic.print_report(report)
    assert SECRET_QUERY_URL not in capsys.readouterr().out


def test_authentication_error_and_safe_client_error_extraction() -> None:
    assets = ReadOnlyClient(
        head_error=client_error("InvalidAccessKeyId", 403, "HeadBucket"),
    )
    report = run_with(assets=assets)
    stage = result(report, "assets_head_bucket")
    assert report.exit_code == 30
    assert stage.category == "AUTHENTICATION_FAILURE"
    assert stage.exception_type == "ClientError"
    assert stage.service_error_code == "InvalidAccessKeyId"
    assert stage.http_status == 403


def test_output_never_contains_service_messages_credentials_urls_or_object_names(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assets = ReadOnlyClient(
        head_error=client_error("AccessDenied", 403, "HeadBucket"),
        key_count=1,
    )
    report = run_with(assets=assets)
    diagnostic.print_report(report)
    output = capsys.readouterr().out
    for forbidden in (
        SECRET_SERVICE_MESSAGE,
        ASSETS_KEY_ID,
        ASSETS_APP_KEY,
        VAULT_KEY_ID,
        VAULT_APP_KEY,
        SECRET_QUERY_URL,
        SECRET_OBJECT_NAME,
        "request-id-must-not-print",
        "host-id-must-not-print",
    ):
        assert forbidden not in output
    assert "service_error_code=AccessDenied" in output
    assert "http_status=403" in output


def test_client_construction_failures_skip_only_dependent_stages() -> None:
    def broken_assets(config: B2AssetsConfig) -> ReadOnlyClient:
        raise RuntimeError(SECRET_SERVICE_MESSAGE)

    _, vault_factory = factories(ReadOnlyClient(), ReadOnlyClient())
    report = diagnostic.diagnose_values(
        complete_values(),
        assets_factory=broken_assets,
        vault_factory=vault_factory,
    )
    assert report.exit_code == 30
    assert result(report, "assets_client_construction").category == "CLIENT_CONSTRUCTION_ERROR"
    assert result(report, "assets_head_bucket").status == "SKIP"
    assert result(report, "vault_head_bucket").status == "PASS"


def test_multiple_access_failures_use_exit_60() -> None:
    denied = client_error("AccessDenied", 403, "HeadBucket")
    report = run_with(
        assets=ReadOnlyClient(head_error=denied, list_error=denied),
        vault=ReadOnlyClient(head_error=denied, list_error=denied),
    )
    assert report.exit_code == 60
    assert report.overall_category == "UNKNOWN_SAFE_ERROR"


def test_invalid_list_shape_and_missing_lock_state_are_safe_unknowns() -> None:
    assets = ReadOnlyClient(key_count=-1)
    report = run_with(assets=assets)
    assert report.exit_code == 30
    assert result(report, "assets_list_probe").category == "UNKNOWN_SAFE_ERROR"

    missing_lock = run_with(vault=ReadOnlyClient(lock_state=None))
    assert missing_lock.exit_code == 43
    stage = result(missing_lock, "vault_object_lock_configuration")
    assert stage.object_lock_state == "Missing"


def test_documented_exit_code_constants_and_mapping() -> None:
    assert diagnostic.INFORMATIONAL_EXIT_CODE == 2
    expected = {0, 10, 20, 30, 31, 40, 41, 42, 43, 50, 60}
    observed = {
        run_with().exit_code,
        run_with(values={**complete_values(), "B2_REGION": ""}).exit_code,
        run_with(values={**complete_values(), "B2_ENDPOINT": "http://unsafe"}).exit_code,
        run_with(
            assets=ReadOnlyClient(
                head_error=client_error("AccessDenied", 403, "HeadBucket"),
                list_error=client_error("AccessDenied", 403, "ListObjectsV2"),
            )
        ).exit_code,
        run_with(
            assets=ReadOnlyClient(head_error=client_error("AccessDenied", 403, "HeadBucket"))
        ).exit_code,
        run_with(
            vault=ReadOnlyClient(
                head_error=client_error("AccessDenied", 403, "HeadBucket"),
                list_error=client_error("AccessDenied", 403, "ListObjectsV2"),
            )
        ).exit_code,
        run_with(
            vault=ReadOnlyClient(head_error=client_error("AccessDenied", 403, "HeadBucket"))
        ).exit_code,
        run_with(
            vault=ReadOnlyClient(
                lock_error=client_error("AccessDenied", 403, "GetObjectLockConfiguration")
            )
        ).exit_code,
        run_with(vault=ReadOnlyClient(lock_state="Disabled")).exit_code,
        run_with(
            values={**complete_values(), "B2_ASSETS_KEY_ID": VAULT_KEY_ID}
        ).exit_code,
        run_with(
            assets=ReadOnlyClient(
                head_error=client_error("AccessDenied", 403, "HeadBucket"),
                list_error=client_error("AccessDenied", 403, "ListObjectsV2"),
            ),
            vault=ReadOnlyClient(
                head_error=client_error("AccessDenied", 403, "HeadBucket"),
                list_error=client_error("AccessDenied", 403, "ListObjectsV2"),
            ),
        ).exit_code,
    }
    assert observed == expected
