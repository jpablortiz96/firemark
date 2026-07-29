"""Diagnose FIREMARK Backblaze B2 access through read-only calls only."""

from __future__ import annotations

import argparse
import hmac
import socket
import ssl
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit

from botocore.exceptions import (  # type: ignore[import-untyped]
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
    SSLError,
)
from dotenv import dotenv_values
from pydantic import ValidationError

from api.firemark.b2_storage import create_assets_client, create_vault_client
from api.firemark.settings import B2AssetsConfig, B2VaultConfig, Settings

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = REPOSITORY_ROOT / ".env"
EXPECTED_ENDPOINT_HOSTNAME = "s3.us-east-005.backblazeb2.com"
EXPECTED_REGION = "us-east-005"
EXPECTED_ASSETS_BUCKET = "firemark-assets-7aaf6d30"
EXPECTED_VAULT_BUCKET = "firemark-vault-7aaf6d30"
INFORMATIONAL_EXIT_CODE = 2

STAGES = (
    "configuration_validation",
    "endpoint_validation",
    "assets_client_construction",
    "assets_head_bucket",
    "assets_list_probe",
    "vault_client_construction",
    "vault_head_bucket",
    "vault_list_probe",
    "vault_object_lock_configuration",
    "credential_separation_validation",
)

Status = Literal["PASS", "FAIL", "SKIP"]


class ReadOnlyS3Client(Protocol):
    """The complete and intentionally tiny diagnostic client surface."""

    def head_bucket(self, **kwargs: Any) -> dict[str, Any]: ...

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]: ...


AssetsFactory = Callable[[B2AssetsConfig], ReadOnlyS3Client]
VaultFactory = Callable[[B2VaultConfig], ReadOnlyS3Client]


def _default_assets_factory(config: B2AssetsConfig) -> ReadOnlyS3Client:
    return cast(ReadOnlyS3Client, create_assets_client(config))


def _default_vault_factory(config: B2VaultConfig) -> ReadOnlyS3Client:
    return cast(ReadOnlyS3Client, create_vault_client(config))


@dataclass(frozen=True)
class StageResult:
    """A safe normalized stage result containing no request or credential data."""

    stage: str
    status: Status
    category: str
    exception_type: str | None = None
    service_error_code: str | None = None
    http_status: int | None = None
    key_count: int | None = None
    object_lock_state: str | None = None


@dataclass(frozen=True)
class DiagnosticReport:
    """Read-only stage results and deterministic process outcome."""

    results: tuple[StageResult, ...]
    exit_code: int
    overall_category: str
    safe_next_action: str


def _result(
    stage: str,
    status: Status,
    category: str,
    **kwargs: Any,
) -> StageResult:
    return StageResult(stage=stage, status=status, category=category, **kwargs)


def _skipped(stage: str, category: str) -> StageResult:
    return _result(stage, "SKIP", category)


def _exception_chain_contains(exc: BaseException, expected: type[BaseException]) -> bool:
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        if isinstance(current, expected):
            return True
        visited.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def _safe_failure(stage: str, exc: Exception) -> StageResult:
    category = "UNKNOWN_SAFE_ERROR"
    service_code: str | None = None
    http_status: int | None = None
    if isinstance(exc, ClientError):
        error = exc.response.get("Error")
        metadata = exc.response.get("ResponseMetadata")
        if isinstance(error, dict) and error.get("Code") is not None:
            service_code = str(error["Code"])
        if isinstance(metadata, dict) and isinstance(metadata.get("HTTPStatusCode"), int):
            http_status = metadata["HTTPStatusCode"]
        if service_code in {"InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken"}:
            category = "AUTHENTICATION_FAILURE"
        elif service_code in {"NoSuchBucket", "NotFound", "404"} or http_status == 404:
            category = "BUCKET_NOT_FOUND"
        elif service_code in {"AuthorizationHeaderMalformed", "PermanentRedirect"}:
            category = "REGION_OR_ENDPOINT_MISMATCH"
        elif service_code in {"AccessDenied", "Forbidden", "403"} or http_status == 403:
            category = "PERMISSION_DENIED"
    elif isinstance(exc, (socket.gaierror,)) or _exception_chain_contains(exc, socket.gaierror):
        category = "DNS_FAILURE"
    elif isinstance(exc, (SSLError, ssl.SSLError)) or _exception_chain_contains(exc, ssl.SSLError):
        category = "TLS_FAILURE"
    elif isinstance(exc, ReadTimeoutError):
        category = "READ_TIMEOUT"
    elif isinstance(exc, (ConnectTimeoutError, TimeoutError)):
        category = "CONNECTION_TIMEOUT"
    elif isinstance(exc, EndpointConnectionError):
        category = "REGION_OR_ENDPOINT_MISMATCH"
    return _result(
        stage,
        "FAIL",
        category,
        exception_type=type(exc).__name__,
        service_error_code=service_code,
        http_status=http_status,
    )


def _required_values(values: Mapping[str, str | None]) -> tuple[str, ...]:
    required = (
        "B2_ENDPOINT",
        "B2_REGION",
        "B2_ASSETS_BUCKET",
        "B2_ASSETS_KEY_ID",
        "B2_ASSETS_APP_KEY",
        "B2_VAULT_BUCKET",
        "B2_VAULT_KEY_ID",
        "B2_VAULT_APP_KEY",
        "FIREMARK_VAULT_RETENTION_DAYS",
        "FIREMARK_PRESIGNED_URL_TTL_SECONDS",
    )
    return tuple(name for name in required if not values.get(name))


def _configuration_result(values: Mapping[str, str | None]) -> StageResult:
    if _required_values(values):
        return _result("configuration_validation", "FAIL", "CONFIGURATION_ERROR")
    region = str(values["B2_REGION"]).strip()
    assets_bucket = str(values["B2_ASSETS_BUCKET"])
    vault_bucket = str(values["B2_VAULT_BUCKET"])
    if not region or assets_bucket == vault_bucket:
        return _result("configuration_validation", "FAIL", "CONFIGURATION_ERROR")
    if (
        region != EXPECTED_REGION
        or assets_bucket != EXPECTED_ASSETS_BUCKET
        or vault_bucket != EXPECTED_VAULT_BUCKET
    ):
        return _result("configuration_validation", "FAIL", "REGION_OR_ENDPOINT_MISMATCH")
    return _result("configuration_validation", "PASS", "OK")


def _endpoint_result(values: Mapping[str, str | None]) -> StageResult:
    raw_endpoint = values.get("B2_ENDPOINT")
    if not raw_endpoint:
        return _result("endpoint_validation", "FAIL", "CONFIGURATION_ERROR")
    parsed = urlsplit(raw_endpoint)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return _result("endpoint_validation", "FAIL", "HTTPS_REQUIRED")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        return _result("endpoint_validation", "FAIL", "HTTPS_REQUIRED")
    if parsed.hostname != EXPECTED_ENDPOINT_HOSTNAME:
        return _result("endpoint_validation", "FAIL", "REGION_OR_ENDPOINT_MISMATCH")
    return _result("endpoint_validation", "PASS", "OK")


def _credential_result(values: Mapping[str, str | None]) -> StageResult:
    names = (
        "B2_ASSETS_KEY_ID",
        "B2_ASSETS_APP_KEY",
        "B2_VAULT_KEY_ID",
        "B2_VAULT_APP_KEY",
    )
    if any(not values.get(name) for name in names):
        return _result("credential_separation_validation", "FAIL", "CONFIGURATION_ERROR")
    assets_key_id = str(values["B2_ASSETS_KEY_ID"])
    assets_app_key = str(values["B2_ASSETS_APP_KEY"])
    vault_key_id = str(values["B2_VAULT_KEY_ID"])
    vault_app_key = str(values["B2_VAULT_APP_KEY"])
    if hmac.compare_digest(assets_key_id, vault_key_id) or hmac.compare_digest(
        assets_app_key, vault_app_key
    ):
        return _result(
            "credential_separation_validation",
            "FAIL",
            "CREDENTIALS_NOT_SEPARATE",
        )
    return _result("credential_separation_validation", "PASS", "OK")


def _settings_from_values(values: Mapping[str, str | None]) -> Settings:
    return Settings.model_validate(
        {
            "b2_endpoint": values["B2_ENDPOINT"],
            "b2_region": values["B2_REGION"],
            "b2_assets_bucket": values["B2_ASSETS_BUCKET"],
            "b2_assets_key_id": values["B2_ASSETS_KEY_ID"],
            "b2_assets_app_key": values["B2_ASSETS_APP_KEY"],
            "b2_vault_bucket": values["B2_VAULT_BUCKET"],
            "b2_vault_key_id": values["B2_VAULT_KEY_ID"],
            "b2_vault_app_key": values["B2_VAULT_APP_KEY"],
            "vault_retention_days": values["FIREMARK_VAULT_RETENTION_DAYS"],
            "presigned_url_ttl_seconds": values["FIREMARK_PRESIGNED_URL_TTL_SECONDS"],
        }
    )


def _head_stage(client: ReadOnlyS3Client, *, stage: str, bucket: str) -> StageResult:
    try:
        client.head_bucket(Bucket=bucket)
    except Exception as exc:
        return _safe_failure(stage, exc)
    return _result(stage, "PASS", "OK")


def _list_stage(client: ReadOnlyS3Client, *, stage: str, bucket: str) -> StageResult:
    try:
        response = client.list_objects_v2(Bucket=bucket, MaxKeys=1)
    except Exception as exc:
        return _safe_failure(stage, exc)
    key_count = response.get("KeyCount")
    if not isinstance(key_count, int) or isinstance(key_count, bool) or key_count < 0:
        return _result(stage, "FAIL", "UNKNOWN_SAFE_ERROR")
    return _result(stage, "PASS", "OK", key_count=key_count)


def _lock_stage(client: ReadOnlyS3Client, *, bucket: str) -> StageResult:
    stage = "vault_object_lock_configuration"
    try:
        response = client.get_object_lock_configuration(Bucket=bucket)
    except Exception as exc:
        return _safe_failure(stage, exc)
    configuration = response.get("ObjectLockConfiguration")
    state = configuration.get("ObjectLockEnabled") if isinstance(configuration, dict) else None
    normalized = str(state) if state is not None else "Missing"
    if state != "Enabled":
        return _result(
            stage,
            "FAIL",
            "OBJECT_LOCK_DISABLED",
            object_lock_state=normalized,
        )
    return _result(
        stage,
        "PASS",
        "OBJECT_LOCK_CONFIRMED",
        object_lock_state="Enabled",
    )


def _correlate(results: dict[str, StageResult]) -> None:
    assets_head = results["assets_head_bucket"]
    assets_list = results["assets_list_probe"]
    if assets_head.status == "FAIL" and assets_head.category == "PERMISSION_DENIED":
        if assets_list.status == "PASS":
            results[assets_head.stage] = replace(
                assets_head,
                category="HEAD_BUCKET_PERMISSION_OR_COMPATIBILITY_LIMITATION",
            )
        elif assets_list.category == "PERMISSION_DENIED":
            results[assets_list.stage] = replace(assets_list, category="PERMISSION_DENIED")
    if assets_head.status == "PASS" and assets_list.category == "PERMISSION_DENIED":
        results[assets_list.stage] = replace(assets_list, category="MISSING_LIST_PERMISSION")

    vault_head = results["vault_head_bucket"]
    vault_list = results["vault_list_probe"]
    if vault_head.status == "FAIL" and vault_head.category == "PERMISSION_DENIED":
        if vault_list.status == "PASS":
            results[vault_head.stage] = replace(
                vault_head,
                category="HEAD_BUCKET_PERMISSION_OR_COMPATIBILITY_LIMITATION",
            )
    if vault_head.status == "PASS" and vault_list.category == "PERMISSION_DENIED":
        results[vault_list.stage] = replace(vault_list, category="MISSING_LIST_PERMISSION")

    lock = results["vault_object_lock_configuration"]
    if (
        lock.category == "PERMISSION_DENIED"
        and results["vault_head_bucket"].status == "PASS"
        and results["vault_list_probe"].status == "PASS"
    ):
        results[lock.stage] = replace(lock, category="MISSING_READ_BUCKET_RETENTIONS")


def _outcome(results: dict[str, StageResult]) -> tuple[int, str, str]:
    configuration = results["configuration_validation"]
    endpoint = results["endpoint_validation"]
    credentials = results["credential_separation_validation"]
    if configuration.status == "FAIL":
        code = 20 if configuration.category == "REGION_OR_ENDPOINT_MISMATCH" else 10
        return code, configuration.category, "Review required configuration names without sharing secrets."
    if endpoint.status == "FAIL":
        return 20, endpoint.category, "Review the configured HTTPS B2 endpoint and local connectivity."
    if credentials.status == "FAIL":
        return 50, credentials.category, "Provision distinct assets and vault credentials."

    transport_categories = {"DNS_FAILURE", "TLS_FAILURE", "CONNECTION_TIMEOUT", "READ_TIMEOUT"}
    if any(result.category in transport_categories for result in results.values()):
        category = next(
            result.category for result in results.values() if result.category in transport_categories
        )
        return 20, category, "Review DNS, TLS, and connectivity to the configured B2 endpoint."

    assets_failed = any(
        results[name].status == "FAIL"
        for name in ("assets_client_construction", "assets_head_bucket", "assets_list_probe")
    )
    vault_access_failed = any(
        results[name].status == "FAIL"
        for name in ("vault_client_construction", "vault_head_bucket", "vault_list_probe")
    )
    if assets_failed and vault_access_failed:
        return 60, "UNKNOWN_SAFE_ERROR", "Review both scoped credential capabilities separately."
    if results["assets_head_bucket"].category == (
        "HEAD_BUCKET_PERMISSION_OR_COMPATIBILITY_LIMITATION"
    ):
        return 31, results["assets_head_bucket"].category, "Treat assets head_bucket as optional when list access works."
    if assets_failed:
        category = next(
            results[name].category
            for name in ("assets_client_construction", "assets_head_bucket", "assets_list_probe")
            if results[name].status == "FAIL"
        )
        return 30, category, "Review assets credential mapping and read/list capabilities."
    if results["vault_head_bucket"].category == (
        "HEAD_BUCKET_PERMISSION_OR_COMPATIBILITY_LIMITATION"
    ):
        return 41, results["vault_head_bucket"].category, "Treat vault head_bucket as optional when list access works."
    if vault_access_failed:
        category = next(
            results[name].category
            for name in ("vault_client_construction", "vault_head_bucket", "vault_list_probe")
            if results[name].status == "FAIL"
        )
        return 40, category, "Review vault credential mapping and read/list capabilities."
    lock = results["vault_object_lock_configuration"]
    if lock.status == "FAIL":
        if lock.category == "OBJECT_LOCK_DISABLED":
            return 43, lock.category, "Stop: the configured vault does not report Object Lock enabled."
        return 42, lock.category, "Grant readBucketRetentions or review B2 Object Lock API compatibility."
    if any(result.status != "PASS" for result in results.values()):
        return 60, "UNKNOWN_SAFE_ERROR", "Review the normalized failed stages before another checkpoint."
    return 0, "OK", "Read-only access is ready for owner review before any custody retry."


def diagnose_values(
    values: Mapping[str, str | None],
    *,
    assets_factory: AssetsFactory = _default_assets_factory,
    vault_factory: VaultFactory = _default_vault_factory,
) -> DiagnosticReport:
    """Run all safe stages against injected clients without ever writing an object."""
    results: dict[str, StageResult] = {}
    results["configuration_validation"] = _configuration_result(values)
    results["endpoint_validation"] = _endpoint_result(values)
    results["credential_separation_validation"] = _credential_result(values)

    prerequisites_pass = all(
        results[name].status == "PASS"
        for name in (
            "configuration_validation",
            "endpoint_validation",
            "credential_separation_validation",
        )
    )
    if not prerequisites_pass:
        for name in STAGES[2:9]:
            results[name] = _skipped(name, "CONFIGURATION_ERROR")
    else:
        try:
            settings = _settings_from_values(values)
            complete = settings.require_complete_b2_config()
        except (ValidationError, ValueError) as exc:
            results["configuration_validation"] = _safe_failure(
                "configuration_validation", exc
            )
            for name in STAGES[2:9]:
                results[name] = _skipped(name, "CONFIGURATION_ERROR")
        else:
            try:
                assets_client = assets_factory(complete.assets)
            except Exception as exc:
                results["assets_client_construction"] = _safe_failure(
                    "assets_client_construction", exc
                )
                results["assets_client_construction"] = replace(
                    results["assets_client_construction"],
                    category="CLIENT_CONSTRUCTION_ERROR",
                )
                results["assets_head_bucket"] = _skipped(
                    "assets_head_bucket", "CLIENT_CONSTRUCTION_ERROR"
                )
                results["assets_list_probe"] = _skipped(
                    "assets_list_probe", "CLIENT_CONSTRUCTION_ERROR"
                )
            else:
                results["assets_client_construction"] = _result(
                    "assets_client_construction", "PASS", "OK"
                )
                results["assets_head_bucket"] = _head_stage(
                    assets_client,
                    stage="assets_head_bucket",
                    bucket=EXPECTED_ASSETS_BUCKET,
                )
                results["assets_list_probe"] = _list_stage(
                    assets_client,
                    stage="assets_list_probe",
                    bucket=EXPECTED_ASSETS_BUCKET,
                )

            try:
                vault_client = vault_factory(complete.vault)
            except Exception as exc:
                results["vault_client_construction"] = _safe_failure(
                    "vault_client_construction", exc
                )
                results["vault_client_construction"] = replace(
                    results["vault_client_construction"],
                    category="CLIENT_CONSTRUCTION_ERROR",
                )
                for name in (
                    "vault_head_bucket",
                    "vault_list_probe",
                    "vault_object_lock_configuration",
                ):
                    results[name] = _skipped(name, "CLIENT_CONSTRUCTION_ERROR")
            else:
                results["vault_client_construction"] = _result(
                    "vault_client_construction", "PASS", "OK"
                )
                results["vault_head_bucket"] = _head_stage(
                    vault_client,
                    stage="vault_head_bucket",
                    bucket=EXPECTED_VAULT_BUCKET,
                )
                results["vault_list_probe"] = _list_stage(
                    vault_client,
                    stage="vault_list_probe",
                    bucket=EXPECTED_VAULT_BUCKET,
                )
                results["vault_object_lock_configuration"] = _lock_stage(
                    vault_client,
                    bucket=EXPECTED_VAULT_BUCKET,
                )

    _correlate(results)
    exit_code, category, action = _outcome(results)
    return DiagnosticReport(
        results=tuple(results[name] for name in STAGES),
        exit_code=exit_code,
        overall_category=category,
        safe_next_action=action,
    )


def load_values(path: Path) -> Mapping[str, str | None]:
    """Load the ignored dotenv file without printing or exporting any value."""
    if not path.is_file():
        return {}
    loaded = dotenv_values(path)
    return {str(key): value for key, value in loaded.items()}


def _print_headers() -> None:
    print("FIREMARK B2 read-only access diagnostic")
    print("Network writes: DISABLED")
    print("Object uploads: DISABLED")
    print("Object deletion: DISABLED")
    print("Presigned URLs: DISABLED")


def print_report(report: DiagnosticReport) -> None:
    """Print only normalized safe fields and aggregate outcomes."""
    print("Stage                              Result  Category")
    print("---------------------------------- ------- --------------------------------")
    for result in report.results:
        print(f"{result.stage:34} {result.status:7} {result.category}")
        if result.key_count is not None:
            print(f"{result.stage} KeyCount={result.key_count}")
        if result.object_lock_state is not None:
            print(f"{result.stage} ObjectLockEnabled={result.object_lock_state}")
        if result.status == "FAIL":
            safe_fields = []
            if result.exception_type is not None:
                safe_fields.append(f"exception_type={result.exception_type}")
            if result.service_error_code is not None:
                safe_fields.append(f"service_error_code={result.service_error_code}")
            if result.http_status is not None:
                safe_fields.append(f"http_status={result.http_status}")
            if safe_fields:
                print(f"{result.stage} {' '.join(safe_fields)}")
    print(f"DIAGNOSTIC_EXIT_CODE={report.exit_code}")
    print(f"OVERALL_CATEGORY={report.overall_category}")
    print(f"SAFE_NEXT_ACTION={report.safe_next_action}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run read-only FIREMARK Backblaze B2 access diagnostics.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Opt in to read-only calls against the configured Backblaze B2 endpoint.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Refuse network access unless the owner supplies the explicit live option."""
    args = _build_parser().parse_args(argv)
    _print_headers()
    if not args.live:
        print("Diagnostic network access is disabled (no --live).")
        print(f"DIAGNOSTIC_EXIT_CODE={INFORMATIONAL_EXIT_CODE}")
        print("OVERALL_CATEGORY=NETWORK_DISABLED")
        print("SAFE_NEXT_ACTION=Configure and review .env, then explicitly rerun with --live.")
        return INFORMATIONAL_EXIT_CODE
    report = diagnose_values(load_values(DEFAULT_ENV_FILE))
    print(f"Endpoint hostname: {EXPECTED_ENDPOINT_HOSTNAME}")
    print(f"Region: {EXPECTED_REGION}")
    print_report(report)
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
