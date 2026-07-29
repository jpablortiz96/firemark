"""Resume the post-persistence FIREMARK B2 custody checkpoint without uploads."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit

import urllib3
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from api.firemark.b2_storage import (
    B2CleanupError,
    B2ConfigurationError,
    B2DeleteProofError,
    B2IntegrityError,
    B2OperationError,
    B2RetentionError,
    RedactedPresignedURL,
    create_assets_client,
    create_vault_client,
    delete_unlocked_version_verified,
    generate_presigned_get,
    head_object_receipt,
    prove_locked_delete_denial,
)
from api.firemark.custody import LockedDeleteProof, LockedObjectReceipt
from api.firemark.settings import B2AssetsConfig, B2VaultConfig

try:
    from scripts.inspect_b2_smoke_state import (
        DEFAULT_ENV_FILE,
        InspectionReport,
        ObjectRecord,
        inspect_values,
        load_values,
    )
except ModuleNotFoundError as exc:
    if exc.name != "scripts":
        raise
    from inspect_b2_smoke_state import (  # type: ignore[import-not-found, no-redef]
        DEFAULT_ENV_FILE,
        InspectionReport,
        ObjectRecord,
        inspect_values,
        load_values,
    )

INFORMATIONAL_EXIT_CODE = 2
MAX_PRESIGNED_DOWNLOAD_BYTES = 10 * 1024 * 1024
STAGES = (
    "discover_existing_objects",
    "inspect_delete_markers",
    "verify_presigned_download",
    "prove_versioned_delete_denial",
    "cleanup_assets_versions",
    "verify_assets_cleanup",
    "write_safe_report",
)

Status = Literal["PASS", "FAIL", "SKIP"]


class RecoveryS3Client(Protocol):
    """The complete client surface allowed during checkpoint recovery."""

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]: ...

    def list_object_versions(self, **kwargs: Any) -> dict[str, Any]: ...

    def head_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_object_retention(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]: ...

    def generate_presigned_url(self, *args: Any, **kwargs: Any) -> str: ...

    def delete_object(self, **kwargs: Any) -> dict[str, Any]: ...


AssetsFactory = Callable[[B2AssetsConfig], RecoveryS3Client]
VaultFactory = Callable[[B2VaultConfig], RecoveryS3Client]
PresignedDownloader = Callable[[RedactedPresignedURL, str, str], int]


def _default_assets_factory(config: B2AssetsConfig) -> RecoveryS3Client:
    return cast(RecoveryS3Client, create_assets_client(config))


def _default_vault_factory(config: B2VaultConfig) -> RecoveryS3Client:
    return cast(RecoveryS3Client, create_vault_client(config))


@dataclass(frozen=True)
class RecoveryStageResult:
    """One stage result containing normalized non-secret fields only."""

    stage: str
    status: Status
    category: str
    service_error_code: str | None = None


@dataclass(frozen=True)
class CheckpointObjects:
    """Exactly one safe source pair and one safe manifest pair."""

    assets_source: ObjectRecord
    assets_manifest: ObjectRecord
    vault_source: ObjectRecord
    vault_manifest: ObjectRecord


@dataclass(frozen=True)
class VersionState:
    """Safe counts for current versions and delete markers of one key."""

    role: str
    kind: str
    key: str
    version_count: int
    delete_marker_count: int
    target_version_found: bool


@dataclass(frozen=True)
class RecoveryOutcome:
    """Complete safe recovery outcome without any raw URL or service response."""

    stages: tuple[RecoveryStageResult, ...]
    exit_code: int
    report: Mapping[str, Any] | None = None


class RecoveryCheckpointError(RuntimeError):
    """Safe stage failure whose representation cannot expose remote values."""

    def __init__(self, category: str, *, service_error_code: str | None = None) -> None:
        super().__init__(category)
        self.category = category
        self.service_error_code = service_error_code


def _service_error_code(exc: BaseException) -> str | None:
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, ClientError):
            error = current.response.get("Error")
            code = error.get("Code") if isinstance(error, Mapping) else None
            return str(code) if code is not None else None
        current = current.__cause__ or current.__context__
    return None


def _safe_error(exc: Exception) -> tuple[str, str | None]:
    if isinstance(exc, RecoveryCheckpointError):
        return exc.category, exc.service_error_code
    code = _service_error_code(exc)
    if isinstance(exc, B2ConfigurationError):
        return "CONFIGURATION_ERROR", code
    if isinstance(exc, B2IntegrityError):
        return "INTEGRITY_FAILURE", code
    if isinstance(exc, B2RetentionError):
        return "RETENTION_FAILURE", code
    if isinstance(exc, B2DeleteProofError):
        return "DELETE_PROOF_FAILURE", exc.service_error_code or code
    if isinstance(exc, B2CleanupError):
        return "ASSETS_CLEANUP_FAILURE", code
    if isinstance(exc, B2OperationError):
        return "B2_OPERATION_FAILURE", code
    if isinstance(exc, (OSError, UnicodeError, TypeError, ValueError)):
        return "LOCAL_SAFE_FAILURE", code
    return "UNKNOWN_SAFE_FAILURE", code


def _failed_outcome(
    completed: Sequence[RecoveryStageResult],
    *,
    stage: str,
    exc: Exception,
) -> RecoveryOutcome:
    category, service_code = _safe_error(exc)
    results = list(completed)
    results.append(RecoveryStageResult(stage, "FAIL", category, service_code))
    stage_index = STAGES.index(stage)
    for remaining in STAGES[stage_index + 1 :]:
        results.append(RecoveryStageResult(remaining, "SKIP", "PREREQUISITE_FAILED"))
    exit_codes = {
        "discover_existing_objects": 10,
        "inspect_delete_markers": 20,
        "verify_presigned_download": 30,
        "prove_versioned_delete_denial": 40,
        "cleanup_assets_versions": 50,
        "verify_assets_cleanup": 51,
        "write_safe_report": 60,
    }
    return RecoveryOutcome(tuple(results), exit_codes[stage])


def _pass(stage: str, category: str = "OK") -> RecoveryStageResult:
    return RecoveryStageResult(stage, "PASS", category)


def _single_record(
    inspection: InspectionReport,
    *,
    role: Literal["assets", "vault"],
    kind: Literal["source", "manifest"],
) -> ObjectRecord:
    matches = [item for item in inspection.objects if item.role == role and item.kind == kind]
    if len(matches) != 1:
        raise RecoveryCheckpointError("MISSING_OR_AMBIGUOUS_OBJECT_PAIR")
    item = matches[0]
    if (
        item.key is None
        or item.version_id is None
        or not item.version_id.strip()
        or item.calculated_sha256 is None
        or item.size is None
        or item.content_type is None
        or item.last_modified is None
    ):
        raise RecoveryCheckpointError("INCOMPLETE_EXACT_VERSION_EVIDENCE")
    if item.byte_integrity != "PASS" or item.metadata_sha_match != "PASS":
        raise RecoveryCheckpointError("INTEGRITY_FAILURE")
    return item


def _checkpoint_objects(inspection: InspectionReport) -> CheckpointObjects:
    if inspection.failures:
        first = inspection.failures[0]
        raise RecoveryCheckpointError(
            first.category,
            service_error_code=first.service_error_code,
        )
    if inspection.source_pair_match != "PASS" or inspection.manifest_pair_match != "PASS":
        raise RecoveryCheckpointError("PAIR_CORRELATION_FAILURE")
    result = CheckpointObjects(
        assets_source=_single_record(inspection, role="assets", kind="source"),
        assets_manifest=_single_record(inspection, role="assets", kind="manifest"),
        vault_source=_single_record(inspection, role="vault", kind="source"),
        vault_manifest=_single_record(inspection, role="vault", kind="manifest"),
    )
    for locked in (result.vault_source, result.vault_manifest):
        if locked.retention != "COMPLIANCE" or locked.retention_active != "YES":
            raise RecoveryCheckpointError("ACTIVE_COMPLIANCE_RETENTION_REQUIRED")
        if locked.retain_until is None:
            raise RecoveryCheckpointError("RETENTION_TIMESTAMP_REQUIRED")
    return result


def _version_state(
    client: RecoveryS3Client,
    *,
    role: str,
    kind: str,
    bucket: str,
    key: str,
    target_version_id: str,
) -> VersionState:
    version_count = 0
    marker_count = 0
    target_found = False
    key_marker: str | None = None
    version_marker: str | None = None
    seen_markers: set[tuple[str | None, str | None]] = set()
    for _page in range(1000):
        parameters: dict[str, Any] = {"Bucket": bucket, "Prefix": key}
        if key_marker is not None:
            parameters["KeyMarker"] = key_marker
        if version_marker is not None:
            parameters["VersionIdMarker"] = version_marker
        response = client.list_object_versions(**parameters)
        versions = response.get("Versions", [])
        delete_markers = response.get("DeleteMarkers", [])
        if not isinstance(versions, list) or not isinstance(delete_markers, list):
            raise RecoveryCheckpointError("INVALID_VERSION_LIST_RESPONSE")
        for item in versions:
            if isinstance(item, Mapping) and item.get("Key") == key:
                version_count += 1
                if item.get("VersionId") == target_version_id:
                    target_found = True
        marker_count += sum(
            isinstance(item, Mapping) and item.get("Key") == key for item in delete_markers
        )
        if response.get("IsTruncated") is not True:
            break
        next_key = response.get("NextKeyMarker")
        next_version = response.get("NextVersionIdMarker")
        if not isinstance(next_key, str) or not next_key:
            raise RecoveryCheckpointError("INVALID_VERSION_PAGINATION_STATE")
        if next_version is not None and not isinstance(next_version, str):
            raise RecoveryCheckpointError("INVALID_VERSION_PAGINATION_STATE")
        next_pair = (next_key, next_version)
        if next_pair in seen_markers:
            raise RecoveryCheckpointError("INVALID_VERSION_PAGINATION_STATE")
        seen_markers.add(next_pair)
        key_marker, version_marker = next_pair
    else:
        raise RecoveryCheckpointError("VERSION_PAGINATION_LIMIT_EXCEEDED")
    if not target_found:
        raise RecoveryCheckpointError("TARGET_VERSION_NOT_FOUND")
    return VersionState(
        role=role,
        kind=kind,
        key=key,
        version_count=version_count,
        delete_marker_count=marker_count,
        target_version_found=True,
    )


def _inspect_all_version_states(
    assets_client: RecoveryS3Client,
    vault_client: RecoveryS3Client,
    objects: CheckpointObjects,
    *,
    assets_bucket: str,
    vault_bucket: str,
) -> tuple[VersionState, ...]:
    states: list[VersionState] = []
    for role, kind, client, item in (
        ("assets", "source", assets_client, objects.assets_source),
        ("assets", "manifest", assets_client, objects.assets_manifest),
        ("vault", "source", vault_client, objects.vault_source),
        ("vault", "manifest", vault_client, objects.vault_manifest),
    ):
        assert item.key is not None
        assert item.version_id is not None
        states.append(
            _version_state(
                client,
                role=role,
                kind=kind,
                bucket=assets_bucket if role == "assets" else vault_bucket,
                key=item.key,
                target_version_id=item.version_id,
            )
        )
    return tuple(states)


def _download_presigned_https(
    value: RedactedPresignedURL,
    endpoint: str,
    expected_sha256: str,
) -> int:
    """Consume one redacted URL over bounded verified HTTPS without persisting it."""
    url = value.reveal_url()
    parsed = urlsplit(url)
    endpoint_host = urlsplit(endpoint).hostname
    if parsed.scheme != "https" or not parsed.hostname or parsed.hostname != endpoint_host:
        raise RecoveryCheckpointError("PRESIGNED_ENDPOINT_MISMATCH")
    manager = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=5, read=30),
        retries=False,
        cert_reqs="CERT_REQUIRED",
    )
    try:
        response = manager.request(
            "GET",
            url,
            preload_content=False,
            redirect=False,
        )
    except urllib3.exceptions.HTTPError as exc:
        raise RecoveryCheckpointError("PRESIGNED_HTTPS_FAILURE") from exc
    try:
        if response.status != 200:
            raise RecoveryCheckpointError("PRESIGNED_HTTP_STATUS_FAILURE")
        hasher = hashlib.sha256()
        total = 0
        while chunk := response.read(64 * 1024, decode_content=False):
            total += len(chunk)
            if total > MAX_PRESIGNED_DOWNLOAD_BYTES:
                raise RecoveryCheckpointError("PRESIGNED_DOWNLOAD_TOO_LARGE")
            hasher.update(chunk)
        if hasher.hexdigest() != expected_sha256:
            raise RecoveryCheckpointError("PRESIGNED_HASH_MISMATCH")
        return total
    finally:
        response.release_conn()
        manager.clear()


def _locked_receipt(item: ObjectRecord, bucket: str) -> LockedObjectReceipt:
    if (
        item.key is None
        or item.calculated_sha256 is None
        or item.content_type is None
        or item.size is None
        or item.version_id is None
        or item.last_modified is None
        or item.retain_until is None
    ):
        raise RecoveryCheckpointError("INCOMPLETE_LOCKED_VERSION_EVIDENCE")
    return LockedObjectReceipt(
        bucket=bucket,
        key=item.key,
        sha256=item.calculated_sha256,
        content_type=item.content_type,
        size_bytes=item.size,
        version_id=item.version_id,
        etag=item.etag,
        created_at=item.last_modified,
        retention_until=item.retain_until,
        retention_verified=True,
    )


def _safe_object(item: ObjectRecord, bucket: str) -> dict[str, Any]:
    return {
        "bucket": bucket,
        "content_type": item.content_type,
        "key": item.key,
        "kind": item.kind,
        "retention_mode": item.retention if item.role == "vault" else None,
        "retention_until": (
            item.retain_until.isoformat().replace("+00:00", "Z")
            if item.retain_until is not None
            else None
        ),
        "sha256": item.calculated_sha256,
        "size_bytes": item.size,
        "version_id": item.version_id,
    }


def _safe_report(
    *,
    objects: CheckpointObjects,
    version_states: Sequence[VersionState],
    proof: LockedDeleteProof,
    stages: Sequence[RecoveryStageResult],
    assets_bucket: str,
    vault_bucket: str,
    downloaded_size: int,
    now: datetime,
) -> dict[str, Any]:
    return {
        "ai_generated": False,
        "assets_cleanup_result": "exact_versions_absent",
        "created_at": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "delete_marker_counts": {
            f"{state.role}_{state.kind}": state.delete_marker_count for state in version_states
        },
        "delete_proof": proof.model_dump(mode="json"),
        "local_fixture": True,
        "new_uploads": 0,
        "objects": [
            _safe_object(objects.assets_source, assets_bucket),
            _safe_object(objects.assets_manifest, assets_bucket),
            _safe_object(objects.vault_source, vault_bucket),
            _safe_object(objects.vault_manifest, vault_bucket),
        ],
        "package_versions": {
            name: importlib.metadata.version(name)
            for name in ("boto3", "botocore", "genblaze-core", "genblaze-s3")
        },
        "presigned_download_size_bytes": downloaded_size,
        "production_b2_custody_evidence": True,
        "resumed_from_existing_objects": True,
        "stage_results": [
            {
                "category": stage.category,
                "service_error_code": stage.service_error_code,
                "stage": stage.stage,
                "status": stage.status,
            }
            for stage in stages
        ],
        "version_counts": {
            f"{state.role}_{state.kind}": state.version_count for state in version_states
        },
    }


def _validate_report_target(path: Path | None, *, force: bool) -> None:
    if force and path is None:
        raise RecoveryCheckpointError("FORCE_REQUIRES_OUTPUT_REPORT")
    if path is not None and path.exists() and not force:
        raise RecoveryCheckpointError("OUTPUT_REPORT_EXISTS")


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
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
    finally:
        temporary.unlink(missing_ok=True)


def resume_values(
    values: Mapping[str, str | None],
    *,
    assets_factory: AssetsFactory = _default_assets_factory,
    vault_factory: VaultFactory = _default_vault_factory,
    downloader: PresignedDownloader = _download_presigned_https,
    output_report: Path | None = None,
    force: bool = False,
    now: datetime | None = None,
) -> RecoveryOutcome:
    """Resume only the verified post-persistence steps against exact versions."""
    timestamp = (now or datetime.now(UTC)).astimezone(UTC)
    completed: list[RecoveryStageResult] = []
    assets_clients: list[RecoveryS3Client] = []
    vault_clients: list[RecoveryS3Client] = []
    assets_configs: list[B2AssetsConfig] = []
    vault_configs: list[B2VaultConfig] = []

    def capture_assets(config: B2AssetsConfig) -> RecoveryS3Client:
        client = assets_factory(config)
        assets_configs.append(config)
        assets_clients.append(client)
        return client

    def capture_vault(config: B2VaultConfig) -> RecoveryS3Client:
        client = vault_factory(config)
        vault_configs.append(config)
        vault_clients.append(client)
        return client

    try:
        _validate_report_target(output_report, force=force)
        inspection = inspect_values(
            values,
            assets_factory=capture_assets,
            vault_factory=capture_vault,
            now=timestamp,
        )
        objects = _checkpoint_objects(inspection)
        if len(assets_clients) != 1 or len(vault_clients) != 1:
            raise RecoveryCheckpointError("SEPARATE_CLIENT_CONSTRUCTION_REQUIRED")
    except Exception as exc:
        return _failed_outcome(completed, stage="discover_existing_objects", exc=exc)
    completed.append(_pass("discover_existing_objects"))
    assets_client, vault_client = assets_clients[0], vault_clients[0]
    assets_config, vault_config = assets_configs[0], vault_configs[0]

    try:
        version_states = _inspect_all_version_states(
            assets_client,
            vault_client,
            objects,
            assets_bucket=assets_config.bucket,
            vault_bucket=vault_config.bucket,
        )
    except Exception as exc:
        return _failed_outcome(completed, stage="inspect_delete_markers", exc=exc)
    completed.append(_pass("inspect_delete_markers"))

    try:
        assert objects.assets_source.key is not None
        assert objects.assets_source.version_id is not None
        assert objects.assets_source.calculated_sha256 is not None
        presigned = generate_presigned_get(
            assets_client,
            bucket=assets_config.bucket,
            key=objects.assets_source.key,
            version_id=objects.assets_source.version_id,
            ttl_seconds=assets_config.presigned_url_ttl_seconds,
        )
        downloaded_size = downloader(
            presigned,
            assets_config.endpoint,
            objects.assets_source.calculated_sha256,
        )
    except Exception as exc:
        return _failed_outcome(completed, stage="verify_presigned_download", exc=exc)
    completed.append(_pass("verify_presigned_download"))

    try:
        proof = prove_locked_delete_denial(
            vault_client,
            _locked_receipt(objects.vault_manifest, vault_config.bucket),
            now=timestamp,
        )
    except Exception as exc:
        return _failed_outcome(completed, stage="prove_versioned_delete_denial", exc=exc)
    completed.append(_pass("prove_versioned_delete_denial", proof.safe_error_category))

    try:
        for item in (objects.assets_source, objects.assets_manifest):
            assert item.key is not None
            assert item.version_id is not None
            assert item.calculated_sha256 is not None
            delete_unlocked_version_verified(
                assets_client,
                bucket=assets_config.bucket,
                key=item.key,
                version_id=item.version_id,
                expected_sha256=item.calculated_sha256,
                known_unlocked=True,
            )
    except Exception as exc:
        return _failed_outcome(completed, stage="cleanup_assets_versions", exc=exc)
    completed.append(_pass("cleanup_assets_versions"))

    try:
        for item in (objects.assets_source, objects.assets_manifest):
            assert item.key is not None
            assert item.version_id is not None
            assert item.calculated_sha256 is not None
            remaining = head_object_receipt(
                assets_client,
                bucket=assets_config.bucket,
                key=item.key,
                version_id=item.version_id,
                expected_sha256=item.calculated_sha256,
            )
            if remaining is not None:
                raise RecoveryCheckpointError("EXACT_ASSETS_VERSION_STILL_EXISTS")
    except Exception as exc:
        return _failed_outcome(completed, stage="verify_assets_cleanup", exc=exc)
    completed.append(_pass("verify_assets_cleanup"))

    try:
        report_stages = (*completed, _pass("write_safe_report"))
        report = _safe_report(
            objects=objects,
            version_states=version_states,
            proof=proof,
            stages=report_stages,
            assets_bucket=assets_config.bucket,
            vault_bucket=vault_config.bucket,
            downloaded_size=downloaded_size,
            now=timestamp,
        )
        if output_report is not None:
            _write_report(output_report.resolve(), report)
    except Exception as exc:
        return _failed_outcome(completed, stage="write_safe_report", exc=exc)
    completed.append(_pass("write_safe_report"))
    return RecoveryOutcome(tuple(completed), 0, report)


def _print_header() -> None:
    print("FIREMARK B2 custody checkpoint recovery")
    print("New uploads: DISABLED")
    print("Object copies: DISABLED")
    print("Retention mutation: DISABLED")
    print("Bucket mutation: DISABLED")
    print("Vault cleanup: DISABLED")


def _print_outcome(outcome: RecoveryOutcome) -> None:
    print("Stage                              Result  Category")
    print("---------------------------------- ------- --------------------------------")
    for result in outcome.stages:
        print(f"{result.stage:34} {result.status:7} {result.category}")
        if result.service_error_code is not None:
            print(f"{result.stage} service_error_code={result.service_error_code}")
    if outcome.report is not None:
        marker_counts = outcome.report.get("delete_marker_counts")
        if isinstance(marker_counts, Mapping):
            for name in sorted(marker_counts):
                count = marker_counts[name]
                if isinstance(name, str) and isinstance(count, int):
                    print(f"DELETE_MARKER_COUNT_{name.upper()}={count}")
    print(f"RECOVERY_EXIT_CODE={outcome.exit_code}")
    print(f"RECOVERY_COMPLETE={'YES' if outcome.exit_code == 0 else 'NO'}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resume FIREMARK B2 custody from verified existing object versions.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Opt in to bounded exact-version deletes after all read-only prerequisites pass.",
    )
    parser.add_argument(
        "--output-report",
        type=Path,
        help="Optional safe JSON evidence report written only after successful recovery.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing output report after all recovery stages pass.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Default to zero network and zero mutation until explicit live opt-in."""
    args = _build_parser().parse_args(argv)
    _print_header()
    if not args.live:
        print("Checkpoint recovery is disabled (no --live).")
        print(f"RECOVERY_EXIT_CODE={INFORMATIONAL_EXIT_CODE}")
        print("RECOVERY_COMPLETE=NO")
        print("SAFE_NEXT_ACTION=Review the recovery plan, then explicitly rerun with --live.")
        return INFORMATIONAL_EXIT_CODE
    outcome = resume_values(
        load_values(DEFAULT_ENV_FILE),
        output_report=args.output_report,
        force=args.force,
    )
    _print_outcome(outcome)
    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
