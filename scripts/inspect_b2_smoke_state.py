"""Inspect persisted FIREMARK B2 smoke objects through read-only calls only."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import socket
import ssl
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
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
MAX_OBJECT_BYTES = 10 * 1024 * 1024
STREAM_CHUNK_BYTES = 64 * 1024
MAX_KEY_LENGTH = 1024
INFORMATIONAL_EXIT_CODE = 2

ALLOWED_METADATA = ("firemark-sha256", "firemark-kind", "firemark-schema")
ASSETS_PREFIXES = ("assets/", "manifests/", "public/")
VAULT_PREFIXES = ("vault/sources/", "vault/manifests/")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
ETAG_PATTERN = re.compile(r'"?[0-9A-Fa-f]{1,128}(?:-[0-9]+)?"?')
SAFE_VERSION_PATTERN = re.compile(r"[A-Za-z0-9._=-]{1,256}")
SAFE_CONTENT_TYPE_PATTERN = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+;-]+")
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:authorization|credential|secret|token|app[-_]?key|key[-_]?id|x-amz)",
    re.IGNORECASE,
)

Result = Literal["PASS", "FAIL", "UNKNOWN"]
MetadataMatch = Literal["PASS", "FAIL", "MISSING"]
RetentionSummary = Literal["COMPLIANCE", "GOVERNANCE", "MISSING", "EXPIRED", "UNKNOWN"]


class StreamingBody(Protocol):
    """Minimal readable and closable response-body surface."""

    def read(self, amount: int = -1) -> bytes: ...

    def close(self) -> None: ...


class ReadOnlyS3Client(Protocol):
    """The complete remote operation surface permitted to this inspector."""

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]: ...

    def list_object_versions(self, **kwargs: Any) -> dict[str, Any]: ...

    def head_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_object_retention(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]: ...


AssetsFactory = Callable[[B2AssetsConfig], ReadOnlyS3Client]
VaultFactory = Callable[[B2VaultConfig], ReadOnlyS3Client]


def _default_assets_factory(config: B2AssetsConfig) -> ReadOnlyS3Client:
    return cast(ReadOnlyS3Client, create_assets_client(config))


def _default_vault_factory(config: B2VaultConfig) -> ReadOnlyS3Client:
    return cast(ReadOnlyS3Client, create_vault_client(config))


@dataclass(frozen=True)
class SafeFailure:
    """A normalized failure that excludes messages and request data."""

    stage: str
    category: str
    exception_type: str
    service_error_code: str | None = None
    http_status: int | None = None
    role: str | None = None


@dataclass(frozen=True)
class ObjectRecord:
    """Safe evidence derived from one current object without retaining its body."""

    role: Literal["assets", "vault"]
    key: str | None
    kind: str
    size: int | None
    content_type: str | None
    version_id: str | None
    last_modified: datetime | None
    etag: str | None
    metadata: tuple[tuple[str, str], ...]
    calculated_sha256: str | None
    metadata_sha_match: MetadataMatch
    byte_integrity: Result
    retention: RetentionSummary = "UNKNOWN"
    retain_until: datetime | None = None
    retention_active: Literal["YES", "NO", "UNKNOWN"] = "UNKNOWN"
    manifest_json_valid: Result = "UNKNOWN"
    category: str = "OK"


@dataclass(frozen=True)
class PairCorrelation:
    """Independent safe correlation checks for one logical cross-bucket pair."""

    found: Literal["PASS", "FAIL"]
    hashes_equal: Result
    content_types_compatible: Result
    metadata_compatible: Result
    overall: Result


@dataclass(frozen=True)
class InspectionReport:
    """Safe persisted-state observations and conservative outcome."""

    objects: tuple[ObjectRecord, ...]
    failures: tuple[SafeFailure, ...]
    assets_object_count: int
    vault_object_count: int
    source_correlation: PairCorrelation
    manifest_correlation: PairCorrelation
    source_pair_match: Result
    manifest_pair_match: Result
    vault_source_retention: RetentionSummary
    vault_manifest_retention: RetentionSummary
    assets_cleanup_pending: Literal["YES", "NO", "UNKNOWN"]
    likely_failure_window: str
    exit_code: int
    safe_next_action: str


def _exception_chain_contains(exc: BaseException, expected: type[BaseException]) -> bool:
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        if isinstance(current, expected):
            return True
        visited.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def _safe_failure(stage: str, exc: Exception, *, role: str | None = None) -> SafeFailure:
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
        elif service_code in {"NoSuchBucket", "NoSuchKey", "NotFound", "404"} or http_status == 404:
            category = "NOT_FOUND"
        elif service_code in {"AuthorizationHeaderMalformed", "PermanentRedirect"}:
            category = "REGION_OR_ENDPOINT_MISMATCH"
        elif service_code in {"AccessDenied", "Forbidden", "403"} or http_status == 403:
            category = "PERMISSION_DENIED"
    elif isinstance(exc, socket.gaierror) or _exception_chain_contains(exc, socket.gaierror):
        category = "DNS_FAILURE"
    elif isinstance(exc, (SSLError, ssl.SSLError)) or _exception_chain_contains(exc, ssl.SSLError):
        category = "TLS_FAILURE"
    elif isinstance(exc, ReadTimeoutError):
        category = "READ_TIMEOUT"
    elif isinstance(exc, (ConnectTimeoutError, TimeoutError)):
        category = "CONNECTION_TIMEOUT"
    elif isinstance(exc, EndpointConnectionError):
        category = "ENDPOINT_CONNECTION_FAILURE"
    return SafeFailure(
        stage=stage,
        category=category,
        exception_type=type(exc).__name__,
        service_error_code=service_code,
        http_status=http_status,
        role=role,
    )


def _settings_from_values(values: Mapping[str, str | None]) -> Settings:
    return Settings.model_validate(
        {
            "b2_endpoint": values.get("B2_ENDPOINT"),
            "b2_region": values.get("B2_REGION"),
            "b2_assets_bucket": values.get("B2_ASSETS_BUCKET"),
            "b2_assets_key_id": values.get("B2_ASSETS_KEY_ID"),
            "b2_assets_app_key": values.get("B2_ASSETS_APP_KEY"),
            "b2_vault_bucket": values.get("B2_VAULT_BUCKET"),
            "b2_vault_key_id": values.get("B2_VAULT_KEY_ID"),
            "b2_vault_app_key": values.get("B2_VAULT_APP_KEY"),
            "vault_retention_days": values.get("FIREMARK_VAULT_RETENTION_DAYS"),
            "presigned_url_ttl_seconds": values.get("FIREMARK_PRESIGNED_URL_TTL_SECONDS"),
        }
    )


def _validated_config(
    values: Mapping[str, str | None],
) -> tuple[B2AssetsConfig, B2VaultConfig] | SafeFailure:
    required_names = (
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
    if any(not values.get(name) for name in required_names):
        return SafeFailure(
            stage="configuration_validation",
            category="CONFIGURATION_ERROR",
            exception_type="ConfigurationError",
        )
    try:
        settings = _settings_from_values(values)
        complete = settings.require_complete_b2_config()
    except (ValidationError, ValueError, KeyError) as exc:
        return _safe_failure("configuration_validation", exc)
    endpoint = urlsplit(str(complete.assets.endpoint))
    if (
        endpoint.scheme != "https"
        or endpoint.hostname != EXPECTED_ENDPOINT_HOSTNAME
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query
        or endpoint.fragment
        or endpoint.path not in ("", "/")
        or complete.assets.region != EXPECTED_REGION
        or complete.vault.region != EXPECTED_REGION
        or complete.assets.bucket != EXPECTED_ASSETS_BUCKET
        or complete.vault.bucket != EXPECTED_VAULT_BUCKET
    ):
        return SafeFailure(
            stage="configuration_validation",
            category="REGION_OR_ENDPOINT_MISMATCH",
            exception_type="ConfigurationError",
        )
    if complete.assets.bucket == complete.vault.bucket:
        return SafeFailure(
            stage="configuration_validation",
            category="CONFIGURATION_ERROR",
            exception_type="ConfigurationError",
        )
    if hmac.compare_digest(
        complete.assets.key_id.get_secret_value(), complete.vault.key_id.get_secret_value()
    ) or hmac.compare_digest(
        complete.assets.app_key.get_secret_value(), complete.vault.app_key.get_secret_value()
    ):
        return SafeFailure(
            stage="configuration_validation",
            category="CREDENTIALS_NOT_SEPARATE",
            exception_type="ConfigurationError",
        )
    return complete.assets, complete.vault


def _safe_key(key: object, *, role: str) -> str | None:
    if not isinstance(key, str) or not key or len(key) > MAX_KEY_LENGTH:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in key):
        return None
    if "?" in key or "://" in key or SENSITIVE_KEY_PATTERN.search(key):
        return None
    prefixes = ASSETS_PREFIXES if role == "assets" else VAULT_PREFIXES
    if not key.startswith(prefixes):
        return None
    return key


def _kind_for_key(key: str, role: str) -> str:
    if role == "assets":
        if key.startswith("assets/"):
            return "source"
        if key.startswith("manifests/"):
            return "manifest"
        return "public"
    if key.startswith("vault/sources/"):
        return "source"
    if key.startswith("vault/manifests/"):
        return "manifest"
    return "unknown"


def _safe_version(value: object) -> str | None:
    return value if isinstance(value, str) and SAFE_VERSION_PATTERN.fullmatch(value) else None


def _safe_etag(value: object) -> str | None:
    return value if isinstance(value, str) and ETAG_PATTERN.fullmatch(value) else None


def _safe_content_type(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 200:
        return None
    return value if SAFE_CONTENT_TYPE_PATTERN.fullmatch(value) else None


def _safe_datetime(value: object) -> datetime | None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        return None
    return value.astimezone(UTC)


def _safe_metadata(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping):
        return ()
    result: list[tuple[str, str]] = []
    for name in ALLOWED_METADATA:
        raw = value.get(name)
        if not isinstance(raw, str) or len(raw) > 256:
            continue
        if any(ord(character) < 32 or ord(character) == 127 for character in raw):
            continue
        if name == "firemark-sha256" and not SHA256_PATTERN.fullmatch(raw):
            continue
        if name == "firemark-kind" and raw not in {"source", "manifest", "public"}:
            continue
        if name == "firemark-schema" and not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", raw):
            continue
        result.append((name, raw))
    return tuple(result)


def _list_current_keys(
    client: ReadOnlyS3Client,
    *,
    bucket: str,
    role: str,
) -> tuple[list[str], list[SafeFailure]]:
    keys: list[str] = []
    failures: list[SafeFailure] = []
    continuation_token: str | None = None
    seen_tokens: set[str] = set()
    for _page in range(1000):
        parameters: dict[str, Any] = {"Bucket": bucket}
        if continuation_token is not None:
            parameters["ContinuationToken"] = continuation_token
        try:
            response = client.list_objects_v2(**parameters)
        except Exception as exc:
            failures.append(_safe_failure(f"{role}_list_objects", exc, role=role))
            break
        contents = response.get("Contents", [])
        if not isinstance(contents, list):
            failures.append(
                SafeFailure(
                    stage=f"{role}_list_objects",
                    category="INVALID_SERVICE_RESPONSE",
                    exception_type="ResponseValidationError",
                    role=role,
                )
            )
            break
        for item in contents:
            raw_key = item.get("Key") if isinstance(item, Mapping) else None
            if isinstance(raw_key, str):
                keys.append(raw_key)
            else:
                failures.append(
                    SafeFailure(
                        stage=f"{role}_object_key_validation",
                        category="UNSAFE_OBJECT_KEY",
                        exception_type="ObjectKeyValidationError",
                        role=role,
                    )
                )
        if response.get("IsTruncated") is not True:
            break
        next_token = response.get("NextContinuationToken")
        if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
            failures.append(
                SafeFailure(
                    stage=f"{role}_list_objects",
                    category="INVALID_PAGINATION_STATE",
                    exception_type="ResponseValidationError",
                    role=role,
                )
            )
            break
        seen_tokens.add(next_token)
        continuation_token = next_token
    else:
        failures.append(
            SafeFailure(
                stage=f"{role}_list_objects",
                category="PAGINATION_LIMIT_EXCEEDED",
                exception_type="ResponseValidationError",
                role=role,
            )
        )
    return keys, failures


def _stream_sha256(body: object, *, capture: bool) -> tuple[str, int, bytes | None]:
    if not hasattr(body, "read") or not hasattr(body, "close"):
        raise TypeError("Unreadable response body")
    stream = cast(StreamingBody, body)
    digest = hashlib.sha256()
    total = 0
    chunks: list[bytes] | None = [] if capture else None
    try:
        while True:
            chunk = stream.read(STREAM_CHUNK_BYTES)
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise TypeError("Non-bytes response body")
            total += len(chunk)
            if total > MAX_OBJECT_BYTES:
                raise OverflowError("Object exceeds inspection limit")
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
    finally:
        stream.close()
    captured = b"".join(chunks) if chunks is not None else None
    return digest.hexdigest(), total, captured


def _retention_state(
    client: ReadOnlyS3Client,
    *,
    bucket: str,
    key: str,
    version_id: str | None,
    now: datetime,
) -> tuple[RetentionSummary, datetime | None, Literal["YES", "NO", "UNKNOWN"]]:
    parameters: dict[str, Any] = {"Bucket": bucket, "Key": key}
    if version_id is not None:
        parameters["VersionId"] = version_id
    response = client.get_object_retention(**parameters)
    retention = response.get("Retention")
    if not isinstance(retention, Mapping):
        return "MISSING", None, "UNKNOWN"
    mode = retention.get("Mode")
    retain_until = _safe_datetime(retention.get("RetainUntilDate"))
    if mode not in {"COMPLIANCE", "GOVERNANCE"} or retain_until is None:
        return "MISSING", retain_until, "UNKNOWN"
    if retain_until <= now:
        return "EXPIRED", retain_until, "NO"
    return cast(RetentionSummary, mode), retain_until, "YES"


def _inspect_object(
    client: ReadOnlyS3Client,
    *,
    bucket: str,
    role: Literal["assets", "vault"],
    raw_key: str,
    now: datetime,
) -> tuple[ObjectRecord, list[SafeFailure]]:
    safe_key = _safe_key(raw_key, role=role)
    if safe_key is None:
        return (
            ObjectRecord(
                role=role,
                key=None,
                kind="unknown",
                size=None,
                content_type=None,
                version_id=None,
                last_modified=None,
                etag=None,
                metadata=(),
                calculated_sha256=None,
                metadata_sha_match="MISSING",
                byte_integrity="FAIL",
                category="UNSAFE_OR_UNEXPECTED_OBJECT_KEY",
            ),
            [
                SafeFailure(
                    stage=f"{role}_object_key_validation",
                    category="UNSAFE_OR_UNEXPECTED_OBJECT_KEY",
                    exception_type="ObjectKeyValidationError",
                    role=role,
                )
            ],
        )
    kind = _kind_for_key(safe_key, role)
    failures: list[SafeFailure] = []
    try:
        head = client.head_object(Bucket=bucket, Key=safe_key)
    except Exception as exc:
        return (
            ObjectRecord(
                role=role,
                key=safe_key,
                kind=kind,
                size=None,
                content_type=None,
                version_id=None,
                last_modified=None,
                etag=None,
                metadata=(),
                calculated_sha256=None,
                metadata_sha_match="MISSING",
                byte_integrity="FAIL",
                category="HEAD_OBJECT_FAILURE",
            ),
            [_safe_failure(f"{role}_head_object", exc, role=role)],
        )
    raw_size = head.get("ContentLength")
    size = raw_size if isinstance(raw_size, int) and not isinstance(raw_size, bool) else None
    content_type = _safe_content_type(head.get("ContentType"))
    version_id = _safe_version(head.get("VersionId"))
    last_modified = _safe_datetime(head.get("LastModified"))
    etag = _safe_etag(head.get("ETag"))
    metadata = _safe_metadata(head.get("Metadata"))
    metadata_dict = dict(metadata)
    if size is None or size < 0:
        failures.append(
            SafeFailure(
                stage=f"{role}_head_object",
                category="INVALID_SERVICE_RESPONSE",
                exception_type="ResponseValidationError",
                role=role,
            )
        )
    if size is not None and size > MAX_OBJECT_BYTES:
        failures.append(
            SafeFailure(
                stage=f"{role}_bounded_download",
                category="OBJECT_TOO_LARGE",
                exception_type="ObjectSizeLimitError",
                role=role,
            )
        )
        oversized_retention: RetentionSummary = "UNKNOWN"
        oversized_retain_until: datetime | None = None
        oversized_retention_active: Literal["YES", "NO", "UNKNOWN"] = "UNKNOWN"
        if role == "vault":
            try:
                (
                    oversized_retention,
                    oversized_retain_until,
                    oversized_retention_active,
                ) = _retention_state(
                    client,
                    bucket=bucket,
                    key=safe_key,
                    version_id=version_id,
                    now=now,
                )
            except Exception as exc:
                failures.append(_safe_failure("vault_get_object_retention", exc, role=role))
        return (
            ObjectRecord(
                role=role,
                key=safe_key,
                kind=kind,
                size=size,
                content_type=content_type,
                version_id=version_id,
                last_modified=last_modified,
                etag=etag,
                metadata=metadata,
                calculated_sha256=None,
                metadata_sha_match=(
                    "MISSING" if "firemark-sha256" not in metadata_dict else "FAIL"
                ),
                byte_integrity="FAIL",
                retention=oversized_retention,
                retain_until=oversized_retain_until,
                retention_active=oversized_retention_active,
                category="OBJECT_TOO_LARGE",
            ),
            failures,
        )
    get_parameters: dict[str, Any] = {"Bucket": bucket, "Key": safe_key}
    if version_id is not None:
        get_parameters["VersionId"] = version_id
    calculated: str | None = None
    downloaded_size: int | None = None
    manifest_bytes: bytes | None = None
    download_category: str | None = None
    try:
        response = client.get_object(**get_parameters)
        calculated, downloaded_size, manifest_bytes = _stream_sha256(
            response.get("Body"), capture=kind == "manifest"
        )
    except Exception as exc:
        if isinstance(exc, OverflowError):
            download_category = "OBJECT_TOO_LARGE"
            failures.append(
                SafeFailure(
                    stage=f"{role}_bounded_download",
                    category=download_category,
                    exception_type=type(exc).__name__,
                    role=role,
                )
            )
        else:
            failures.append(_safe_failure(f"{role}_get_object", exc, role=role))
    metadata_sha = metadata_dict.get("firemark-sha256")
    metadata_match: MetadataMatch = "MISSING"
    if metadata_sha is not None and calculated is not None:
        metadata_match = "PASS" if hmac.compare_digest(metadata_sha, calculated) else "FAIL"
    size_match = size is not None and downloaded_size is not None and size == downloaded_size
    byte_integrity: Result = (
        "PASS" if calculated is not None and size_match and metadata_match == "PASS" else "FAIL"
    )
    manifest_json_valid: Result = "UNKNOWN"
    if kind == "manifest" and manifest_bytes is not None:
        try:
            json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError):
            manifest_json_valid = "FAIL"
        else:
            manifest_json_valid = "PASS"
        if manifest_json_valid == "FAIL":
            byte_integrity = "FAIL"
    retention: RetentionSummary = "UNKNOWN"
    retain_until: datetime | None = None
    retention_active: Literal["YES", "NO", "UNKNOWN"] = "UNKNOWN"
    if role == "vault":
        try:
            retention, retain_until, retention_active = _retention_state(
                client,
                bucket=bucket,
                key=safe_key,
                version_id=version_id,
                now=now,
            )
        except Exception as exc:
            failures.append(_safe_failure("vault_get_object_retention", exc, role=role))
    category = "OK"
    if download_category is not None:
        category = download_category
    elif calculated is None:
        category = "OBJECT_READ_FAILURE"
    elif not size_match:
        category = "CONTENT_LENGTH_MISMATCH"
    elif metadata_match == "MISSING":
        category = "SHA256_METADATA_MISSING"
    elif metadata_match == "FAIL":
        category = "SHA256_MISMATCH"
    elif manifest_json_valid == "FAIL":
        category = "INVALID_MANIFEST_JSON"
    elif role == "vault" and retention != "COMPLIANCE":
        category = f"RETENTION_{retention}"
    return (
        ObjectRecord(
            role=role,
            key=safe_key,
            kind=kind,
            size=size,
            content_type=content_type,
            version_id=version_id,
            last_modified=last_modified,
            etag=etag,
            metadata=metadata,
            calculated_sha256=calculated,
            metadata_sha_match=metadata_match,
            byte_integrity=byte_integrity,
            retention=retention,
            retain_until=retain_until,
            retention_active=retention_active,
            manifest_json_valid=manifest_json_valid,
            category=category,
        ),
        failures,
    )


def _pair_correlation(objects: Sequence[ObjectRecord], kind: str) -> PairCorrelation:
    assets = [item for item in objects if item.role == "assets" and item.kind == kind]
    vault = [item for item in objects if item.role == "vault" and item.kind == kind]
    if not assets or not vault:
        return PairCorrelation("FAIL", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN")
    if len(assets) != 1 or len(vault) != 1:
        return PairCorrelation("FAIL", "UNKNOWN", "UNKNOWN", "UNKNOWN", "FAIL")
    left, right = assets[0], vault[0]
    hashes_equal: Result = "UNKNOWN"
    if left.calculated_sha256 is not None and right.calculated_sha256 is not None:
        hashes_equal = (
            "PASS"
            if hmac.compare_digest(left.calculated_sha256, right.calculated_sha256)
            else "FAIL"
        )
    content_types_equal: Result = "UNKNOWN"
    if left.content_type is not None and right.content_type is not None:
        content_types_equal = "PASS" if left.content_type == right.content_type else "FAIL"
    left_metadata = dict(left.metadata)
    right_metadata = dict(right.metadata)
    metadata_equal: Result = (
        "PASS"
        if all(
            left_metadata.get(name) is not None
            and left_metadata.get(name) == right_metadata.get(name)
            for name in ALLOWED_METADATA
        )
        else "FAIL"
    )
    overall: Result = (
        "PASS"
        if hashes_equal == content_types_equal == metadata_equal == "PASS"
        else "FAIL"
    )
    return PairCorrelation(
        found="PASS",
        hashes_equal=hashes_equal,
        content_types_compatible=content_types_equal,
        metadata_compatible=metadata_equal,
        overall=overall,
    )


def _kind_retention(objects: Sequence[ObjectRecord], kind: str) -> RetentionSummary:
    matching = [item.retention for item in objects if item.role == "vault" and item.kind == kind]
    return matching[0] if len(matching) == 1 else "UNKNOWN"


def _has_transport_failure(failures: Sequence[SafeFailure]) -> bool:
    return any(
        failure.category
        in {
            "DNS_FAILURE",
            "TLS_FAILURE",
            "CONNECTION_TIMEOUT",
            "READ_TIMEOUT",
            "ENDPOINT_CONNECTION_FAILURE",
            "REGION_OR_ENDPOINT_MISMATCH",
        }
        for failure in failures
    )


def _outcome(
    objects: Sequence[ObjectRecord],
    failures: Sequence[SafeFailure],
    *,
    source_pair: Result,
    manifest_pair: Result,
    lock_enabled: bool | None,
) -> tuple[int, str, Literal["YES", "NO", "UNKNOWN"], str]:
    assets = [item for item in objects if item.role == "assets"]
    vault = [item for item in objects if item.role == "vault"]
    expected_missing = any(
        not any(item.role == role and item.kind == kind for item in objects)
        for role in ("assets", "vault")
        for kind in ("source", "manifest")
    )
    integrity_failed = any(item.byte_integrity == "FAIL" for item in objects)
    retention_bad = any(
        item.role == "vault"
        and item.kind in {"source", "manifest"}
        and (item.retention != "COMPLIANCE" or item.retention_active != "YES")
        for item in objects
    )
    unexpected = any(item.kind in {"unknown", "public"} for item in objects)
    multiple = any(
        len([item for item in objects if item.role == role and item.kind == kind]) > 1
        for role in ("assets", "vault")
        for kind in ("source", "manifest")
    )
    if any(failure.stage == "configuration_validation" for failure in failures):
        return 10, "INSUFFICIENT_EVIDENCE", "UNKNOWN", "Review the ignored local B2 configuration."
    if _has_transport_failure(failures):
        return 20, "INSUFFICIENT_EVIDENCE", "UNKNOWN", "Review endpoint, DNS, TLS, and connectivity."
    assets_operation_stages = {
        "assets_client_construction",
        "assets_list_objects",
        "assets_head_object",
        "assets_get_object",
    }
    vault_operation_stages = {
        "vault_client_construction",
        "vault_list_objects",
        "vault_head_object",
        "vault_get_object",
        "vault_object_lock_configuration",
    }
    if any(failure.stage in assets_operation_stages for failure in failures):
        return 30, "INSUFFICIENT_EVIDENCE", "UNKNOWN", "Review assets read and list capabilities."
    if any(failure.stage in vault_operation_stages for failure in failures):
        return 40, "INSUFFICIENT_EVIDENCE", "UNKNOWN", "Review vault read and list capabilities."
    if any(failure.stage == "vault_get_object_retention" for failure in failures):
        return (
            41,
            "VAULT_RETENTION_WRITE_OR_READBACK_FAILURE",
            "UNKNOWN",
            "Review vault readBucketRetentions capability without changing retention.",
        )
    if expected_missing:
        return 50, "UPLOAD_OR_INTEGRITY_FAILURE", "UNKNOWN", "Review which expected smoke upload is absent."
    if integrity_failed:
        return 51, "UPLOAD_OR_INTEGRITY_FAILURE", "UNKNOWN", "Do not retry; review the failed integrity evidence."
    if source_pair != "PASS" or manifest_pair != "PASS":
        return 52, "OBJECT_STATE_INCONSISTENT", "UNKNOWN", "Review cross-bucket hash and metadata correlation."
    if lock_enabled is not True:
        return 53, "OBJECT_STATE_INCONSISTENT", "UNKNOWN", "Review vault Object Lock state without changing it."
    if retention_bad:
        return (
            53,
            "VAULT_RETENTION_WRITE_OR_READBACK_FAILURE",
            "UNKNOWN",
            "Do not retry; review the observed vault retention state.",
        )
    if unexpected or multiple:
        return 60, "OBJECT_STATE_INCONSISTENT", "UNKNOWN", "Review unexpected or duplicate object state."
    if len(assets) >= 2 and len(vault) >= 2:
        return (
            0,
            "ALL_PERSISTED_OBJECTS_VALID_AND_RETAINED",
            "YES",
            "Investigate presigned download verification, delete-denial proof, or assets cleanup.",
        )
    return 60, "INSUFFICIENT_EVIDENCE", "UNKNOWN", "Collect more read-only persisted-state evidence."


def inspect_values(
    values: Mapping[str, str | None],
    *,
    assets_factory: AssetsFactory = _default_assets_factory,
    vault_factory: VaultFactory = _default_vault_factory,
    now: datetime | None = None,
) -> InspectionReport:
    """Inspect all current safe FIREMARK keys through injected read-only clients."""
    timestamp = (now or datetime.now(UTC)).astimezone(UTC)
    configured = _validated_config(values)
    if isinstance(configured, SafeFailure):
        failures = (configured,)
        exit_code, inference, cleanup, action = _outcome(
            (), failures, source_pair="UNKNOWN", manifest_pair="UNKNOWN", lock_enabled=None
        )
        return InspectionReport(
            objects=(),
            failures=failures,
            assets_object_count=0,
            vault_object_count=0,
            source_correlation=PairCorrelation(
                "FAIL", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"
            ),
            manifest_correlation=PairCorrelation(
                "FAIL", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"
            ),
            source_pair_match="UNKNOWN",
            manifest_pair_match="UNKNOWN",
            vault_source_retention="UNKNOWN",
            vault_manifest_retention="UNKNOWN",
            assets_cleanup_pending=cleanup,
            likely_failure_window=inference,
            exit_code=exit_code,
            safe_next_action=action,
        )
    assets_config, vault_config = configured
    failures_list: list[SafeFailure] = []
    objects: list[ObjectRecord] = []
    try:
        assets_client = assets_factory(assets_config)
    except Exception as exc:
        failures_list.append(_safe_failure("assets_client_construction", exc, role="assets"))
        assets_client = None
    try:
        vault_client = vault_factory(vault_config)
    except Exception as exc:
        failures_list.append(_safe_failure("vault_client_construction", exc, role="vault"))
        vault_client = None
    for role, client, bucket in (
        ("assets", assets_client, EXPECTED_ASSETS_BUCKET),
        ("vault", vault_client, EXPECTED_VAULT_BUCKET),
    ):
        if client is None:
            continue
        keys, list_failures = _list_current_keys(client, bucket=bucket, role=role)
        failures_list.extend(list_failures)
        for raw_key in keys:
            record, object_failures = _inspect_object(
                client,
                bucket=bucket,
                role=cast(Literal["assets", "vault"], role),
                raw_key=raw_key,
                now=timestamp,
            )
            objects.append(record)
            failures_list.extend(object_failures)
    lock_enabled: bool | None = None
    if vault_client is not None:
        try:
            lock_response = vault_client.get_object_lock_configuration(
                Bucket=EXPECTED_VAULT_BUCKET
            )
            configuration = lock_response.get("ObjectLockConfiguration")
            lock_enabled = bool(
                isinstance(configuration, Mapping)
                and configuration.get("ObjectLockEnabled") == "Enabled"
            )
        except Exception as exc:
            failures_list.append(_safe_failure("vault_object_lock_configuration", exc, role="vault"))
    source_correlation = _pair_correlation(objects, "source")
    manifest_correlation = _pair_correlation(objects, "manifest")
    source_pair = source_correlation.overall
    manifest_pair = manifest_correlation.overall
    exit_code, inference, cleanup, action = _outcome(
        objects,
        failures_list,
        source_pair=source_pair,
        manifest_pair=manifest_pair,
        lock_enabled=lock_enabled,
    )
    return InspectionReport(
        objects=tuple(objects),
        failures=tuple(failures_list),
        assets_object_count=sum(item.role == "assets" for item in objects),
        vault_object_count=sum(item.role == "vault" for item in objects),
        source_correlation=source_correlation,
        manifest_correlation=manifest_correlation,
        source_pair_match=source_pair,
        manifest_pair_match=manifest_pair,
        vault_source_retention=_kind_retention(objects, "source"),
        vault_manifest_retention=_kind_retention(objects, "manifest"),
        assets_cleanup_pending=cleanup,
        likely_failure_window=inference,
        exit_code=exit_code,
        safe_next_action=action,
    )


def load_values(path: Path) -> Mapping[str, str | None]:
    """Load the ignored dotenv file without printing or exporting any value."""
    if not path.is_file():
        return {}
    loaded = dotenv_values(path)
    return {str(key): value for key, value in loaded.items()}


def _utc_text(value: datetime | None) -> str:
    return value.isoformat().replace("+00:00", "Z") if value is not None else "UNKNOWN"


def _print_headers() -> None:
    print("FIREMARK B2 persisted smoke-state inspector")
    print("Network writes: DISABLED")
    print("Object uploads: DISABLED")
    print("Object deletion: DISABLED")
    print("Presigned URLs: DISABLED")
    print("Bucket mutation: DISABLED")


def print_report(report: InspectionReport) -> None:
    """Print only normalized object evidence and safe failures."""
    print("Role    Kind      Size       Hash metadata  Byte integrity  Retention")
    print("------- --------- ---------- -------------- --------------- -----------")
    for item in report.objects:
        size = str(item.size) if item.size is not None else "UNKNOWN"
        print(
            f"{item.role:7} {item.kind:9} {size:10} {item.metadata_sha_match:14} "
            f"{item.byte_integrity:15} {item.retention}"
        )
        print(f"OBJECT_KEY={item.key if item.key is not None else '[REDACTED_UNSAFE_KEY]'}")
        print(f"CONTENT_TYPE={item.content_type or 'UNKNOWN'}")
        print(f"VERSION_ID={item.version_id or 'UNKNOWN'}")
        print(f"LAST_MODIFIED_UTC={_utc_text(item.last_modified)}")
        print(f"ETAG={item.etag or 'UNKNOWN'}")
        for name, value in item.metadata:
            print(f"METADATA_{name.upper().replace('-', '_')}={value}")
        print(f"CALCULATED_SHA256={item.calculated_sha256 or 'UNKNOWN'}")
        print(f"RETENTION_MODE={item.retention}")
        print(f"RETAIN_UNTIL_UTC={_utc_text(item.retain_until)}")
        print(f"RETENTION_ACTIVE={item.retention_active}")
        if item.kind == "manifest":
            print(f"MANIFEST_JSON_VALID={item.manifest_json_valid}")
    for failure in report.failures:
        fields = [
            f"stage={failure.stage}",
            f"category={failure.category}",
            f"exception_type={failure.exception_type}",
        ]
        if failure.service_error_code is not None:
            fields.append(f"service_error_code={failure.service_error_code}")
        if failure.http_status is not None:
            fields.append(f"http_status={failure.http_status}")
        print("SAFE_FAILURE " + " ".join(fields))
    print(f"SOURCE_PAIR_FOUND={report.source_correlation.found}")
    print(f"SOURCE_PAIR_HASHES_EQUAL={report.source_correlation.hashes_equal}")
    print(
        "SOURCE_PAIR_CONTENT_TYPES_COMPATIBLE="
        f"{report.source_correlation.content_types_compatible}"
    )
    print(f"SOURCE_PAIR_METADATA_COMPATIBLE={report.source_correlation.metadata_compatible}")
    print(f"MANIFEST_PAIR_FOUND={report.manifest_correlation.found}")
    print(f"MANIFEST_PAIR_HASHES_EQUAL={report.manifest_correlation.hashes_equal}")
    print(
        "MANIFEST_PAIR_CONTENT_TYPES_COMPATIBLE="
        f"{report.manifest_correlation.content_types_compatible}"
    )
    print(
        "MANIFEST_PAIR_METADATA_COMPATIBLE="
        f"{report.manifest_correlation.metadata_compatible}"
    )
    print(f"ASSETS_OBJECT_COUNT={report.assets_object_count}")
    print(f"VAULT_OBJECT_COUNT={report.vault_object_count}")
    print(f"SOURCE_PAIR_MATCH={report.source_pair_match}")
    print(f"MANIFEST_PAIR_MATCH={report.manifest_pair_match}")
    print(f"VAULT_SOURCE_RETENTION={report.vault_source_retention}")
    print(f"VAULT_MANIFEST_RETENTION={report.vault_manifest_retention}")
    print(f"ASSETS_CLEANUP_PENDING={report.assets_cleanup_pending}")
    print(f"LIKELY_FAILURE_WINDOW={report.likely_failure_window}")
    print(f"INSPECTION_EXIT_CODE={report.exit_code}")
    print(f"SAFE_NEXT_ACTION={report.safe_next_action}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect persisted FIREMARK B2 smoke state through read-only calls.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Opt in to read-only inspection against the configured Backblaze B2 endpoint.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Refuse all network access unless the owner explicitly supplies --live."""
    args = _build_parser().parse_args(argv)
    _print_headers()
    if not args.live:
        print("Object inspection is disabled (no --live).")
        print("ASSETS_OBJECT_COUNT=0")
        print("VAULT_OBJECT_COUNT=0")
        print("SOURCE_PAIR_MATCH=UNKNOWN")
        print("MANIFEST_PAIR_MATCH=UNKNOWN")
        print("VAULT_SOURCE_RETENTION=UNKNOWN")
        print("VAULT_MANIFEST_RETENTION=UNKNOWN")
        print("ASSETS_CLEANUP_PENDING=UNKNOWN")
        print("LIKELY_FAILURE_WINDOW=INSUFFICIENT_EVIDENCE")
        print(f"INSPECTION_EXIT_CODE={INFORMATIONAL_EXIT_CODE}")
        print("SAFE_NEXT_ACTION=Review .env, then explicitly rerun this inspector with --live.")
        return INFORMATIONAL_EXIT_CODE
    report = inspect_values(load_values(DEFAULT_ENV_FILE))
    print_report(report)
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
