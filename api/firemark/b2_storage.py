"""Production-safe Backblaze B2 storage and Object Lock controls."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

import boto3  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from genblaze_core import KeyStrategy, ObjectStorageSink, StorageBackend
from genblaze_s3 import S3StorageBackend

from api.firemark.custody import LockedDeleteProof, LockedObjectReceipt, StoredObjectReceipt
from api.firemark.hashing import sha256_bytes, sha256_file
from api.firemark.settings import B2AssetsConfig, B2VaultConfig

DEFAULT_MEMORY_LIMIT = 16 * 1024 * 1024
DEFAULT_STREAM_CHUNK_SIZE = 1024 * 1024
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_METADATA_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9._:/+ -]{1,256}$")
_METADATA_KEYS = frozenset({"firemark-sha256", "firemark-kind", "firemark-schema"})
_EXTENSIONS = frozenset(
    {
        "aac",
        "avif",
        "bin",
        "flac",
        "gif",
        "jpeg",
        "jpg",
        "m4a",
        "mov",
        "mp3",
        "mp4",
        "parquet",
        "pdf",
        "png",
        "wav",
        "webm",
        "webp",
        "zip",
    }
)


class B2Error(RuntimeError):
    """Base class for safe FIREMARK B2 failures."""


class B2ConfigurationError(B2Error):
    """Raised before an unsafe or incomplete B2 operation."""


class B2OperationError(B2Error):
    """Raised for a safely classified B2 service or transport failure."""


class B2IntegrityError(B2Error):
    """Raised when stored or downloaded bytes fail independent SHA-256 verification."""


class B2RetentionError(B2Error):
    """Raised when Object Lock cannot be proven as active COMPLIANCE retention."""


class B2DeleteProofError(B2Error):
    """Raised when a failed delete cannot be attributed safely to active retention."""


class S3Client(Protocol):
    """Small structural surface used from the dynamic boto3 S3 client."""

    def head_bucket(self, **kwargs: Any) -> dict[str, Any]: ...

    def put_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def head_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def delete_object(self, **kwargs: Any) -> dict[str, Any]: ...

    def generate_presigned_url(self, *args: Any, **kwargs: Any) -> str: ...

    def get_object_retention(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]: ...


ClientFactory = Callable[..., S3Client]
_DEFAULT_CLIENT_FACTORY = cast(ClientFactory, boto3.client)


@dataclass(frozen=True, repr=False)
class RedactedPresignedURL:
    """A short-lived GET URL whose normal representations never expose credentials."""

    _url: str
    expires_in: int

    def __post_init__(self) -> None:
        parsed = urlsplit(self._url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise B2ConfigurationError("Presigned GET must be an HTTPS URL")
        _validate_ttl(self.expires_in)

    def __repr__(self) -> str:
        return f"RedactedPresignedURL(url='<redacted>', expires_in={self.expires_in})"

    def __str__(self) -> str:
        return "<redacted presigned GET>"

    def reveal_url(self) -> str:
        """Explicitly return the secret-bearing URL for immediate transport use only."""
        return self._url


@dataclass(frozen=True)
class RetentionState:
    """Normalized service readback for one retained object version."""

    mode: str
    retain_until: datetime


def _safe_operation_error(operation: str, bucket: str, key: str | None = None) -> str:
    target = f"{bucket}/{key}" if key is not None else bucket
    return f"B2 {operation} failed for {target}"


def _validate_digest(value: str) -> str:
    if not _SHA256_PATTERN.fullmatch(value):
        raise ValueError("SHA-256 must be 64 lowercase hexadecimal characters")
    return value


def _validate_identifier(value: str, label: str) -> str:
    if not value or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must use 1-128 safe identifier characters")
    if ".." in value or "/" in value or "\\" in value:
        raise ValueError(f"{label} must not contain path traversal")
    return value


def normalize_extension(extension: str) -> str:
    """Normalize one allowlisted media extension without accepting client filenames."""
    normalized = extension.strip().lower().removeprefix(".")
    if normalized not in _EXTENSIONS:
        raise ValueError("Unsupported or unsafe storage extension")
    return normalized


def assets_source_key(sha256: str, extension: str) -> str:
    """Build a content-addressed private assets key."""
    digest = _validate_digest(sha256)
    suffix = normalize_extension(extension)
    return f"assets/{digest[:2]}/{digest[2:4]}/{digest}.{suffix}"


def assets_manifest_key(run_id: str, canonical_hash: str) -> str:
    """Build the private full-manifest key for one Genblaze run."""
    return f"manifests/{_validate_identifier(run_id, 'run_id')}/{_validate_digest(canonical_hash)}.json"


def public_pointer_key(cert_id: str) -> str:
    """Build the future safe public pointer location."""
    return f"public/{_validate_identifier(cert_id, 'cert_id')}/pointer.json"


def public_signed_envelope_key(cert_id: str) -> str:
    """Build the future signed-envelope location."""
    return f"public/{_validate_identifier(cert_id, 'cert_id')}/signed-envelope.json"


def public_custody_receipt_key(cert_id: str) -> str:
    """Build the future public custody-receipt location."""
    return f"public/{_validate_identifier(cert_id, 'cert_id')}/custody-receipt.json"


def vault_source_key(sha256: str, extension: str) -> str:
    """Build a timestamp-free content-addressed vault source key."""
    digest = _validate_digest(sha256)
    suffix = normalize_extension(extension)
    return f"vault/sources/{digest[:2]}/{digest[2:4]}/{digest}.{suffix}"


def vault_manifest_key(run_id: str, canonical_hash: str) -> str:
    """Build the immutable full-manifest vault key."""
    return f"vault/manifests/{_validate_identifier(run_id, 'run_id')}/{_validate_digest(canonical_hash)}.json"


def _client_config() -> Config:
    return Config(
        signature_version="s3v4",
        connect_timeout=5,
        read_timeout=30,
        retries={"mode": "standard", "max_attempts": 3},
        s3={"addressing_style": "path"},
    )


def _create_client(
    config: B2AssetsConfig | B2VaultConfig,
    *,
    client_factory: ClientFactory = _DEFAULT_CLIENT_FACTORY,
) -> S3Client:
    """Create a TLS-verifying client with explicit credentials and no profile fallback."""
    return client_factory(
        "s3",
        endpoint_url=config.endpoint,
        region_name=config.region,
        aws_access_key_id=config.key_id.get_secret_value(),
        aws_secret_access_key=config.app_key.get_secret_value(),
        config=_client_config(),
        verify=True,
    )


def create_assets_client(
    config: B2AssetsConfig,
    *,
    client_factory: ClientFactory = _DEFAULT_CLIENT_FACTORY,
) -> S3Client:
    """Create the separately credentialed private assets client."""
    return _create_client(config, client_factory=client_factory)


def create_vault_client(
    config: B2VaultConfig,
    *,
    client_factory: ClientFactory = _DEFAULT_CLIENT_FACTORY,
) -> S3Client:
    """Create the separately credentialed private vault client."""
    return _create_client(config, client_factory=client_factory)


def create_genblaze_assets_backend(config: B2AssetsConfig) -> S3StorageBackend:
    """Construct the authorized public Genblaze adapter for assets only."""
    return S3StorageBackend.for_backblaze(
        bucket=config.bucket,
        region=config.region,
        key_id=config.key_id.get_secret_value(),
        app_key=config.app_key.get_secret_value(),
        public_url_base=None,
        auto_lifecycle=False,
        preflight=False,
    )


def create_genblaze_assets_sink(backend: S3StorageBackend) -> ObjectStorageSink:
    """Prove the public storage protocol with content-addressable Genblaze keys."""
    if not isinstance(backend, StorageBackend):
        raise B2ConfigurationError("Genblaze S3 backend does not implement StorageBackend")
    return ObjectStorageSink(backend, key_strategy=KeyStrategy.CONTENT_ADDRESSABLE)


def _safe_metadata(metadata: Mapping[str, str] | None, digest: str) -> dict[str, str]:
    result = dict(metadata or {})
    result["firemark-sha256"] = digest
    if not set(result) <= _METADATA_KEYS:
        raise B2ConfigurationError("Object metadata contains a non-allowlisted key")
    for key, value in result.items():
        if not isinstance(value, str) or not _METADATA_VALUE_PATTERN.fullmatch(value):
            raise B2ConfigurationError(f"Object metadata value is unsafe for {key}")
    return result


def _version_parameters(version_id: str | None) -> dict[str, str]:
    return {"VersionId": version_id} if version_id else {}


def _response_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise B2OperationError(f"B2 returned an invalid {label} timestamp")
    return value.astimezone(UTC)


def _service_code(exc: ClientError) -> str:
    error = exc.response.get("Error", {})
    code = error.get("Code") if isinstance(error, dict) else None
    return str(code or "Unknown")


def check_bucket_access(client: S3Client, *, bucket: str) -> None:
    """Require authenticated access to the configured private bucket."""
    try:
        client.head_bucket(Bucket=bucket)
    except (BotoCoreError, ClientError) as exc:
        raise B2OperationError(_safe_operation_error("head_bucket", bucket)) from exc


def head_object_receipt(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    expected_sha256: str,
    version_id: str | None = None,
) -> StoredObjectReceipt | None:
    """Read safe object metadata, returning None only for a real missing object."""
    digest = _validate_digest(expected_sha256)
    try:
        response = client.head_object(
            Bucket=bucket,
            Key=key,
            **_version_parameters(version_id),
        )
    except ClientError as exc:
        if _service_code(exc) in {"404", "NoSuchKey", "NoSuchVersion", "NotFound"}:
            return None
        raise B2OperationError(_safe_operation_error("head_object", bucket, key)) from exc
    except BotoCoreError as exc:
        raise B2OperationError(_safe_operation_error("head_object", bucket, key)) from exc

    metadata = response.get("Metadata") or {}
    if not isinstance(metadata, dict) or metadata.get("firemark-sha256") != digest:
        raise B2IntegrityError("B2 object metadata does not match the expected SHA-256")
    size = response.get("ContentLength")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise B2OperationError("B2 head_object returned an invalid content length")
    content_type = response.get("ContentType")
    if not isinstance(content_type, str) or not content_type:
        raise B2OperationError("B2 head_object returned no content type")
    last_modified = _response_datetime(response.get("LastModified"), "LastModified")
    returned_version = response.get("VersionId")
    returned_etag = response.get("ETag")
    return StoredObjectReceipt(
        bucket=bucket,
        key=key,
        sha256=digest,
        content_type=content_type,
        size_bytes=size,
        version_id=str(returned_version) if returned_version else version_id,
        etag=str(returned_etag) if returned_etag else None,
        created_at=last_modified,
    )


def _read_body(response: Mapping[str, Any], max_bytes: int) -> bytes:
    if isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    content_length = response.get("ContentLength")
    if isinstance(content_length, int) and content_length > max_bytes:
        raise B2IntegrityError("B2 download exceeds the configured memory limit")
    body = response.get("Body")
    if body is None or not hasattr(body, "read"):
        raise B2OperationError("B2 get_object returned no readable body")
    try:
        payload = body.read(max_bytes + 1)
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
    if not isinstance(payload, bytes):
        raise B2OperationError("B2 get_object returned a non-bytes body")
    if len(payload) > max_bytes:
        raise B2IntegrityError("B2 download exceeds the configured memory limit")
    return payload


def download_bytes_verified(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    expected_sha256: str,
    version_id: str | None = None,
    max_bytes: int = DEFAULT_MEMORY_LIMIT,
) -> bytes:
    """Download bounded bytes and verify SHA-256 independently of ETag."""
    digest = _validate_digest(expected_sha256)
    try:
        response = client.get_object(
            Bucket=bucket,
            Key=key,
            **_version_parameters(version_id),
        )
    except (BotoCoreError, ClientError) as exc:
        raise B2OperationError(_safe_operation_error("get_object", bucket, key)) from exc
    payload = _read_body(response, max_bytes)
    if sha256_bytes(payload) != digest:
        raise B2IntegrityError("Downloaded B2 bytes do not match the expected SHA-256")
    return payload


def _put_verified(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    body: bytes | Any,
    size_bytes: int,
    expected_sha256: str,
    content_type: str,
    metadata: Mapping[str, str] | None,
    known_unlocked: bool,
) -> StoredObjectReceipt:
    digest = _validate_digest(expected_sha256)
    if not content_type.strip():
        raise B2ConfigurationError("content_type must not be blank")
    safe_metadata = _safe_metadata(metadata, digest)
    try:
        response = client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType=content_type,
            Metadata=safe_metadata,
        )
    except (BotoCoreError, ClientError) as exc:
        raise B2OperationError(_safe_operation_error("put_object", bucket, key)) from exc
    version_id = str(response["VersionId"]) if response.get("VersionId") else None
    try:
        receipt = head_object_receipt(
            client,
            bucket=bucket,
            key=key,
            expected_sha256=digest,
            version_id=version_id,
        )
        if receipt is None or receipt.size_bytes != size_bytes:
            raise B2IntegrityError("Uploaded B2 object size did not verify")
        download_bytes_verified(
            client,
            bucket=bucket,
            key=key,
            expected_sha256=digest,
            version_id=version_id,
            max_bytes=max(DEFAULT_MEMORY_LIMIT, size_bytes),
        )
        return receipt
    except (B2IntegrityError, B2OperationError):
        if known_unlocked:
            try:
                delete_unlocked_object(
                    client,
                    bucket=bucket,
                    key=key,
                    version_id=version_id,
                    known_unlocked=True,
                )
            except B2Error:
                pass
        raise


def upload_bytes_verified(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    data: bytes,
    expected_sha256: str,
    content_type: str,
    metadata: Mapping[str, str] | None = None,
    known_unlocked: bool = False,
) -> StoredObjectReceipt:
    """Upload bytes, head them, download them, and verify their SHA-256."""
    if sha256_bytes(data) != _validate_digest(expected_sha256):
        raise B2IntegrityError("Upload bytes do not match the expected SHA-256")
    return _put_verified(
        client,
        bucket=bucket,
        key=key,
        body=data,
        size_bytes=len(data),
        expected_sha256=expected_sha256,
        content_type=content_type,
        metadata=metadata,
        known_unlocked=known_unlocked,
    )


def upload_file_verified(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    path: Path,
    expected_sha256: str,
    content_type: str,
    metadata: Mapping[str, str] | None = None,
    known_unlocked: bool = False,
) -> StoredObjectReceipt:
    """Stream a local file into B2 and independently verify the stored bytes."""
    digest = _validate_digest(expected_sha256)
    if sha256_file(path) != digest:
        raise B2IntegrityError("Upload file does not match the expected SHA-256")
    with path.open("rb") as source:
        return _put_verified(
            client,
            bucket=bucket,
            key=key,
            body=source,
            size_bytes=path.stat().st_size,
            expected_sha256=digest,
            content_type=content_type,
            metadata=metadata,
            known_unlocked=known_unlocked,
        )


def stream_download_verified(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    destination: Path,
    expected_sha256: str,
    version_id: str | None = None,
    overwrite: bool = False,
    max_bytes: int | None = None,
    chunk_size: int = DEFAULT_STREAM_CHUNK_SIZE,
) -> StoredObjectReceipt:
    """Stream into an atomic local destination while hashing and bounding bytes."""
    digest = _validate_digest(expected_sha256)
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Destination already exists: {destination}")
    if isinstance(chunk_size, bool) or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")
    if max_bytes is not None and (isinstance(max_bytes, bool) or max_bytes <= 0):
        raise ValueError("max_bytes must be a positive integer")
    try:
        response = client.get_object(
            Bucket=bucket,
            Key=key,
            **_version_parameters(version_id),
        )
    except (BotoCoreError, ClientError) as exc:
        raise B2OperationError(_safe_operation_error("get_object", bucket, key)) from exc
    body = response.get("Body")
    if body is None or not hasattr(body, "read"):
        raise B2OperationError("B2 get_object returned no readable body")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    temporary = Path(name)
    hasher = hashlib.sha256()
    total = 0
    try:
        with temporary.open("wb") as target:
            while chunk := body.read(chunk_size):
                if not isinstance(chunk, bytes):
                    raise B2OperationError("B2 stream returned non-bytes data")
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    raise B2IntegrityError("B2 stream exceeds the configured size limit")
                hasher.update(chunk)
                target.write(chunk)
        if hasher.hexdigest() != digest:
            raise B2IntegrityError("Streamed B2 bytes do not match the expected SHA-256")
        if destination.exists() and not overwrite:
            raise FileExistsError(f"Destination already exists: {destination}")
        os.replace(temporary, destination)
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()
        temporary.unlink(missing_ok=True)
    return StoredObjectReceipt(
        bucket=bucket,
        key=key,
        sha256=digest,
        content_type=str(response.get("ContentType") or "application/octet-stream"),
        size_bytes=total,
        version_id=str(response["VersionId"]) if response.get("VersionId") else version_id,
        etag=str(response["ETag"]) if response.get("ETag") else None,
        created_at=datetime.now(UTC),
    )


def _validate_ttl(ttl_seconds: int) -> int:
    if isinstance(ttl_seconds, bool) or not 60 <= ttl_seconds <= 900:
        raise B2ConfigurationError("Presigned URL TTL must be between 60 and 900 seconds")
    return ttl_seconds


def generate_presigned_get(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    ttl_seconds: int,
    version_id: str | None = None,
) -> RedactedPresignedURL:
    """Generate a private GET URL locally through boto3 and redact normal output."""
    ttl = _validate_ttl(ttl_seconds)
    params = {"Bucket": bucket, "Key": key, **_version_parameters(version_id)}
    try:
        url = client.generate_presigned_url(
            "get_object",
            Params=params,
            ExpiresIn=ttl,
            HttpMethod="GET",
        )
    except (BotoCoreError, ClientError) as exc:
        raise B2OperationError(_safe_operation_error("generate_presigned_url", bucket, key)) from exc
    return RedactedPresignedURL(url, ttl)


def delete_unlocked_object(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    version_id: str | None = None,
    known_unlocked: bool = False,
) -> None:
    """Delete only an object explicitly known to be outside immutable custody."""
    if not known_unlocked:
        raise B2ConfigurationError("Refusing cleanup when object retention state is unknown")
    try:
        client.delete_object(
            Bucket=bucket,
            Key=key,
            **_version_parameters(version_id),
        )
    except (BotoCoreError, ClientError) as exc:
        raise B2OperationError(_safe_operation_error("delete_object", bucket, key)) from exc


def verify_bucket_object_lock_enabled(client: S3Client, *, bucket: str) -> None:
    """Fail closed unless the real bucket reports Object Lock enabled."""
    try:
        response = client.get_object_lock_configuration(Bucket=bucket)
    except (BotoCoreError, ClientError) as exc:
        raise B2RetentionError(_safe_operation_error("get_object_lock_configuration", bucket)) from exc
    configuration = response.get("ObjectLockConfiguration")
    if not isinstance(configuration, dict) or configuration.get("ObjectLockEnabled") != "Enabled":
        raise B2RetentionError("Vault bucket does not report Object Lock enabled")


def _future_retention(retention_until: datetime, *, now: datetime | None = None) -> datetime:
    if retention_until.tzinfo is None or retention_until.utcoffset() is None:
        raise B2RetentionError("Retention timestamp must be timezone-aware")
    normalized = retention_until.astimezone(UTC)
    if normalized <= (now or datetime.now(UTC)).astimezone(UTC):
        raise B2RetentionError("Retention timestamp must be in the future")
    return normalized


def read_object_retention(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    version_id: str | None = None,
) -> RetentionState:
    """Read and normalize retention for an exact object version."""
    try:
        response = client.get_object_retention(
            Bucket=bucket,
            Key=key,
            **_version_parameters(version_id),
        )
    except (BotoCoreError, ClientError) as exc:
        raise B2RetentionError(_safe_operation_error("get_object_retention", bucket, key)) from exc
    retention = response.get("Retention")
    if not isinstance(retention, dict):
        raise B2RetentionError("B2 returned no object retention")
    mode = retention.get("Mode")
    if mode != "COMPLIANCE":
        raise B2RetentionError("B2 object retention is not COMPLIANCE")
    retain_until = _response_datetime(retention.get("RetainUntilDate"), "RetainUntilDate")
    return RetentionState(mode=mode, retain_until=retain_until)


def _retention_covers(returned: datetime, requested: datetime) -> bool:
    return returned >= requested or requested - returned < timedelta(seconds=1)


def _locked_receipt(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    digest: str,
    content_type: str,
    size_bytes: int,
    version_id: str | None,
    etag: str | None,
    requested_retention: datetime,
) -> LockedObjectReceipt:
    head = head_object_receipt(
        client,
        bucket=bucket,
        key=key,
        expected_sha256=digest,
        version_id=version_id,
    )
    if head is None or head.size_bytes != size_bytes:
        raise B2IntegrityError("Locked B2 object metadata did not verify")
    state = read_object_retention(
        client,
        bucket=bucket,
        key=key,
        version_id=version_id,
    )
    if not _retention_covers(state.retain_until, requested_retention):
        raise B2RetentionError("Confirmed retention is earlier than requested")
    download_bytes_verified(
        client,
        bucket=bucket,
        key=key,
        expected_sha256=digest,
        version_id=version_id,
        max_bytes=max(DEFAULT_MEMORY_LIMIT, size_bytes),
    )
    return LockedObjectReceipt(
        **head.model_dump(exclude={"version_id", "etag"}),
        version_id=version_id or head.version_id,
        etag=etag or head.etag,
        retention_until=state.retain_until,
        retention_verified=True,
    )


def upload_locked_bytes(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    data: bytes,
    expected_sha256: str,
    content_type: str,
    retention_until: datetime,
    metadata: Mapping[str, str] | None = None,
) -> LockedObjectReceipt:
    """Write bytes with COMPLIANCE retention and verify both bytes and retention."""
    digest = _validate_digest(expected_sha256)
    if sha256_bytes(data) != digest:
        raise B2IntegrityError("Locked upload bytes do not match the expected SHA-256")
    requested = _future_retention(retention_until)
    verify_bucket_object_lock_enabled(client, bucket=bucket)
    try:
        response = client.put_object(
            Bucket=bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
            Metadata=_safe_metadata(metadata, digest),
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=requested,
        )
    except (BotoCoreError, ClientError) as exc:
        raise B2OperationError(_safe_operation_error("locked put_object", bucket, key)) from exc
    version_id = str(response["VersionId"]) if response.get("VersionId") else None
    etag = str(response["ETag"]) if response.get("ETag") else None
    return _locked_receipt(
        client,
        bucket=bucket,
        key=key,
        digest=digest,
        content_type=content_type,
        size_bytes=len(data),
        version_id=version_id,
        etag=etag,
        requested_retention=requested,
    )


def upload_locked_file(
    client: S3Client,
    *,
    bucket: str,
    key: str,
    path: Path,
    expected_sha256: str,
    content_type: str,
    retention_until: datetime,
    metadata: Mapping[str, str] | None = None,
) -> LockedObjectReceipt:
    """Stream a file into COMPLIANCE custody and verify the exact version."""
    digest = _validate_digest(expected_sha256)
    if sha256_file(path) != digest:
        raise B2IntegrityError("Locked upload file does not match the expected SHA-256")
    requested = _future_retention(retention_until)
    verify_bucket_object_lock_enabled(client, bucket=bucket)
    try:
        with path.open("rb") as source:
            response = client.put_object(
                Bucket=bucket,
                Key=key,
                Body=source,
                ContentType=content_type,
                Metadata=_safe_metadata(metadata, digest),
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=requested,
            )
    except (BotoCoreError, ClientError) as exc:
        raise B2OperationError(_safe_operation_error("locked put_object", bucket, key)) from exc
    version_id = str(response["VersionId"]) if response.get("VersionId") else None
    etag = str(response["ETag"]) if response.get("ETag") else None
    return _locked_receipt(
        client,
        bucket=bucket,
        key=key,
        digest=digest,
        content_type=content_type,
        size_bytes=path.stat().st_size,
        version_id=version_id,
        etag=etag,
        requested_retention=requested,
    )


def prove_locked_delete_denial(
    client: S3Client,
    receipt: LockedObjectReceipt,
    *,
    now: datetime | None = None,
) -> LockedDeleteProof:
    """Prove a delete denial only through active retention and post-error corroboration."""
    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    before = read_object_retention(
        client,
        bucket=receipt.bucket,
        key=receipt.key,
        version_id=receipt.version_id,
    )
    if before.retain_until <= current_time:
        raise B2DeleteProofError("Object retention is not currently active")
    if head_object_receipt(
        client,
        bucket=receipt.bucket,
        key=receipt.key,
        expected_sha256=receipt.sha256,
        version_id=receipt.version_id,
    ) is None:
        raise B2DeleteProofError("Locked object does not exist before delete proof")

    try:
        client.delete_object(
            Bucket=receipt.bucket,
            Key=receipt.key,
            **_version_parameters(receipt.version_id),
        )
    except ClientError as exc:
        error_code = _service_code(exc)
    except BotoCoreError as exc:
        raise B2DeleteProofError("Delete proof failed because of a transport error") from exc
    else:
        raise B2DeleteProofError("Delete unexpectedly succeeded; Object Lock was not proven")

    rejected_codes = {
        "ExpiredToken",
        "InvalidAccessKeyId",
        "InvalidToken",
        "NoSuchBucket",
        "NoSuchKey",
        "NoSuchVersion",
        "RequestTimeout",
        "SignatureDoesNotMatch",
    }
    accepted_codes = {"AccessDenied", "InvalidRequest", "MethodNotAllowed", "ObjectLocked"}
    if error_code in rejected_codes or error_code not in accepted_codes:
        raise B2DeleteProofError(f"Delete denial category is not retention-compatible: {error_code}")

    after_head = head_object_receipt(
        client,
        bucket=receipt.bucket,
        key=receipt.key,
        expected_sha256=receipt.sha256,
        version_id=receipt.version_id,
    )
    if after_head is None:
        raise B2DeleteProofError("Object is missing after the denied delete attempt")
    after = read_object_retention(
        client,
        bucket=receipt.bucket,
        key=receipt.key,
        version_id=receipt.version_id,
    )
    if after.retain_until <= current_time:
        raise B2DeleteProofError("Active retention is absent after the delete attempt")
    return LockedDeleteProof(
        bucket=receipt.bucket,
        key=receipt.key,
        version_id=receipt.version_id,
        error_code=error_code,
        safe_error_category="active_compliance_retention",
        retention_mode="COMPLIANCE",
        retention_until=after.retain_until,
        object_exists_after_attempt=True,
        retention_exists_after_attempt=True,
        verified=True,
    )
