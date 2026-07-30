"""Immutable receipts and orchestration for FIREMARK B2 custody."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from api.firemark.hashing import sha256_bytes, sha256_file


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Custody timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _retention_covers(returned: datetime, requested: datetime) -> bool:
    normalized_returned = _utc(returned)
    normalized_requested = _utc(requested)
    return normalized_returned >= normalized_requested or (
        normalized_requested - normalized_returned < timedelta(seconds=1)
    )


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    raise TypeError(f"Unsupported canonical value: {type(value).__name__}")


class StoredObjectReceipt(BaseModel):
    """Safe immutable evidence for a byte-verified object."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket: str
    key: str
    sha256: str
    content_type: str
    size_bytes: int
    version_id: str | None = None
    etag: str | None = None
    created_at: datetime

    @field_validator("bucket", "key", "content_type")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        """Reject blank storage identifiers and content types."""
        if not value.strip():
            raise ValueError("Storage receipt fields must not be blank")
        return value

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        """Require a canonical lowercase SHA-256 digest."""
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("Receipt SHA-256 must be 64 lowercase hexadecimal characters")
        return value

    @field_validator("size_bytes")
    @classmethod
    def validate_size(cls, value: int) -> int:
        """Reject negative or boolean object sizes."""
        if isinstance(value, bool) or value < 0:
            raise ValueError("size_bytes must be a non-negative integer")
        return value

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        """Normalize the service timestamp to UTC."""
        return _utc(value)


class LockedObjectReceipt(StoredObjectReceipt):
    """Byte and retention evidence for a COMPLIANCE-locked object."""

    retention_mode: Literal["COMPLIANCE"] = "COMPLIANCE"
    retention_until: datetime
    retention_verified: Literal[True] = True

    @field_validator("retention_until")
    @classmethod
    def normalize_retention(cls, value: datetime) -> datetime:
        """Normalize confirmed retention to UTC."""
        return _utc(value)

    @model_validator(mode="after")
    def require_exact_version(self) -> LockedObjectReceipt:
        """Require immutable custody evidence to identify one exact version."""
        if self.version_id is None or not self.version_id.strip():
            raise ValueError("Locked object receipt requires a nonblank VersionId")
        return self


class LockedDeleteProof(BaseModel):
    """Corroborated safe evidence that active retention denied deletion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket: str
    key: str
    version_id: str
    error_code: str
    safe_error_category: Literal["active_compliance_retention"]
    retention_mode: Literal["COMPLIANCE"]
    retention_until: datetime
    object_exists_after_attempt: Literal[True]
    retention_exists_after_attempt: Literal[True]
    verified: Literal[True]

    @field_validator("retention_until")
    @classmethod
    def normalize_retention(cls, value: datetime) -> datetime:
        """Normalize post-delete retention evidence to UTC."""
        return _utc(value)


class B2CustodyReceipt(BaseModel):
    """Complete safe receipt for assets storage and immutable vault custody."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_sha256: str
    canonical_hash: str
    assets_source: StoredObjectReceipt
    assets_manifest: StoredObjectReceipt
    vault_source: LockedObjectReceipt
    vault_manifest: LockedObjectReceipt
    requested_retention_until: datetime
    created_at: datetime
    custody_verified: bool

    @field_validator("source_sha256", "canonical_hash")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        """Require canonical lowercase SHA-256 identifiers."""
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("Custody hashes must be 64 lowercase hexadecimal characters")
        return value

    @field_validator("requested_retention_until", "created_at")
    @classmethod
    def normalize_timestamps(cls, value: datetime) -> datetime:
        """Normalize all receipt-level timestamps to UTC."""
        return _utc(value)

    @model_validator(mode="after")
    def validate_relationships(self) -> B2CustodyReceipt:
        """Prevent forged verification and inconsistent object relationships."""
        if self.assets_source.sha256 != self.source_sha256:
            raise ValueError("Assets source receipt does not match source_sha256")
        if self.vault_source.sha256 != self.source_sha256:
            raise ValueError("Vault source receipt does not match source_sha256")
        if self.assets_manifest.sha256 != self.vault_manifest.sha256:
            raise ValueError("Assets and vault manifest bytes must have the same SHA-256")
        locations = {
            (self.assets_source.bucket, self.assets_source.key),
            (self.assets_manifest.bucket, self.assets_manifest.key),
            (self.vault_source.bucket, self.vault_source.key),
            (self.vault_manifest.bucket, self.vault_manifest.key),
        }
        if len(locations) != 4:
            raise ValueError("Custody object bucket/key locations must be unique")
        if self.assets_source.bucket != self.assets_manifest.bucket:
            raise ValueError("Assets receipts must use one assets bucket")
        if self.vault_source.bucket != self.vault_manifest.bucket:
            raise ValueError("Vault receipts must use one vault bucket")
        if self.assets_source.bucket == self.vault_source.bucket:
            raise ValueError("Assets and vault receipts must use different buckets")
        if not _retention_covers(self.vault_source.retention_until, self.requested_retention_until):
            raise ValueError("Vault source retention is earlier than requested")
        if not _retention_covers(
            self.vault_manifest.retention_until, self.requested_retention_until
        ):
            raise ValueError("Vault manifest retention is earlier than requested")
        if self.custody_verified and not (
            self.vault_source.retention_verified and self.vault_manifest.retention_verified
        ):
            raise ValueError("custody_verified requires two verified COMPLIANCE objects")
        return self

    def canonical_bytes(self) -> bytes:
        """Serialize the custody receipt as deterministic canonical UTF-8 JSON."""
        return json.dumps(
            self.model_dump(mode="python"),
            default=_json_default,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


class B2CustodyWorkflowError(RuntimeError):
    """Fail closed while retaining only safe partial-state locations."""

    def __init__(
        self,
        message: str,
        *,
        partial_keys: tuple[str, ...] = (),
        stage: str | None = None,
        category: str = "UNKNOWN_SAFE_ERROR",
        service_error_code: str | None = None,
        bucket_role: str | None = None,
        object_kind: str | None = None,
        partial_objects: tuple[PartialB2Object, ...] = (),
    ) -> None:
        super().__init__(message)
        self.partial_keys = partial_keys
        self.stage = stage
        self.category = category
        self.service_error_code = service_error_code
        self.bucket_role = bucket_role
        self.object_kind = object_kind
        self.partial_objects = partial_objects


@dataclass(frozen=True)
class PartialB2Object:
    """Safe exact-version state retained after an interrupted custody workflow."""

    bucket_role: Literal["assets", "vault"]
    object_kind: Literal["source", "manifest", "sealed"]
    key: str
    version_id: str | None
    retained: bool


def execute_b2_custody(
    *,
    assets_client: Any,
    vault_client: Any,
    assets_bucket: str,
    vault_bucket: str,
    source_path: Path,
    manifest_bytes: bytes,
    source_sha256: str,
    canonical_hash: str,
    run_id: str,
    cert_id: str,
    extension: str,
    retention_until: datetime,
    source_content_type: str,
    manifest_content_type: str = "application/json",
    now: datetime | None = None,
    stage_callback: Callable[[str], None] | None = None,
    persistence_callback: Callable[[tuple[PartialB2Object, ...]], None] | None = None,
) -> B2CustodyReceipt:
    """Store and verify four objects without claiming cross-object atomicity."""
    from api.firemark.b2_storage import (
        B2PersistedObjectError,
        assets_manifest_key,
        assets_source_key,
        classify_b2_failure,
        delete_unlocked_version_verified,
        download_bytes_verified,
        head_object_receipt,
        public_custody_receipt_key,
        read_object_retention,
        upload_bytes_verified,
        upload_file_verified,
        upload_locked_bytes,
        upload_locked_file,
        vault_manifest_key,
        vault_source_key,
    )

    public_custody_receipt_key(cert_id)  # Validate the reserved future publication identifier.
    if sha256_file(source_path) != source_sha256:
        raise B2CustodyWorkflowError("Source file does not match source_sha256")
    from api.firemark.genblaze_provenance import parse_complete_manifest_payload

    manifest = parse_complete_manifest_payload(manifest_bytes)
    if manifest.canonical_hash != canonical_hash:
        raise B2CustodyWorkflowError("Manifest does not match canonical_hash")
    manifest_sha256 = sha256_bytes(manifest_bytes)

    source_key = assets_source_key(source_sha256, extension)
    manifest_key = assets_manifest_key(run_id, canonical_hash)
    locked_source_key = vault_source_key(source_sha256, extension)
    locked_manifest_key = vault_manifest_key(run_id, canonical_hash)
    created_assets: list[StoredObjectReceipt] = []
    partial_keys: list[str] = []
    partial_objects: list[PartialB2Object] = []
    current_stage = "vault_source_upload"
    bucket_role = "assets"
    object_kind = "source"
    timestamp = _utc(now or datetime.now(UTC))

    def begin(stage: str, *, role: str, kind: str) -> None:
        nonlocal current_stage, bucket_role, object_kind
        current_stage = stage
        bucket_role = role
        object_kind = kind
        if stage_callback is not None:
            stage_callback(stage)

    try:
        begin("vault_source_upload", role="assets", kind="source")
        assets_source = head_object_receipt(
            assets_client,
            bucket=assets_bucket,
            key=source_key,
            expected_sha256=source_sha256,
        )
        if assets_source is None:
            assets_source = upload_file_verified(
                assets_client,
                bucket=assets_bucket,
                key=source_key,
                path=source_path,
                expected_sha256=source_sha256,
                content_type=source_content_type,
                metadata={"firemark-kind": "source", "firemark-schema": "1"},
                known_unlocked=True,
            )
            created_assets.append(assets_source)
        else:
            if assets_source.content_type != source_content_type:
                raise B2CustodyWorkflowError("Existing assets source content type conflicts")
            download_bytes_verified(
                assets_client,
                bucket=assets_bucket,
                key=source_key,
                expected_sha256=source_sha256,
                version_id=assets_source.version_id,
            )
        partial_keys.append(source_key)
        partial_objects.append(
            PartialB2Object("assets", "source", source_key, assets_source.version_id, False)
        )
        if persistence_callback is not None:
            persistence_callback(tuple(partial_objects))
        begin("vault_source_upload", role="assets", kind="manifest")
        assets_manifest = head_object_receipt(
            assets_client,
            bucket=assets_bucket,
            key=manifest_key,
            expected_sha256=manifest_sha256,
        )
        if assets_manifest is None:
            assets_manifest = upload_bytes_verified(
                assets_client,
                bucket=assets_bucket,
                key=manifest_key,
                data=manifest_bytes,
                expected_sha256=manifest_sha256,
                content_type=manifest_content_type,
                metadata={"firemark-kind": "manifest", "firemark-schema": "1"},
                known_unlocked=True,
            )
            created_assets.append(assets_manifest)
        else:
            if assets_manifest.content_type != manifest_content_type:
                raise B2CustodyWorkflowError("Existing assets manifest content type conflicts")
            download_bytes_verified(
                assets_client,
                bucket=assets_bucket,
                key=manifest_key,
                expected_sha256=manifest_sha256,
                version_id=assets_manifest.version_id,
            )
        partial_keys.append(manifest_key)
        partial_objects.append(
            PartialB2Object("assets", "manifest", manifest_key, assets_manifest.version_id, False)
        )
        if persistence_callback is not None:
            persistence_callback(tuple(partial_objects))
        begin("vault_source_upload", role="vault", kind="source")
        existing_vault_source = head_object_receipt(
            vault_client,
            bucket=vault_bucket,
            key=locked_source_key,
            expected_sha256=source_sha256,
        )
        if existing_vault_source is None:
            vault_source = upload_locked_file(
                vault_client,
                bucket=vault_bucket,
                key=locked_source_key,
                path=source_path,
                expected_sha256=source_sha256,
                content_type=source_content_type,
                retention_until=retention_until,
                metadata={"firemark-kind": "source", "firemark-schema": "1"},
                stage_callback=lambda stage: begin(stage, role="vault", kind="source"),
                upload_stage="vault_source_upload",
                hash_verification_stage="vault_source_hash_verification",
                retention_verification_stage="vault_source_retention_verification",
            )
        else:
            begin("vault_source_hash_verification", role="vault", kind="source")
            download_bytes_verified(
                vault_client,
                bucket=vault_bucket,
                key=locked_source_key,
                expected_sha256=source_sha256,
                version_id=existing_vault_source.version_id,
            )
            begin("vault_source_retention_verification", role="vault", kind="source")
            state = read_object_retention(
                vault_client,
                bucket=vault_bucket,
                key=locked_source_key,
                version_id=existing_vault_source.version_id,
            )
            if not _retention_covers(state.retain_until, retention_until):
                raise B2CustodyWorkflowError("Existing vault source retention conflicts")
            vault_source = LockedObjectReceipt(
                **existing_vault_source.model_dump(),
                retention_until=state.retain_until,
                retention_verified=True,
            )
        partial_keys.append(locked_source_key)
        partial_objects.append(
            PartialB2Object("vault", "source", locked_source_key, vault_source.version_id, True)
        )
        if persistence_callback is not None:
            persistence_callback(tuple(partial_objects))
        begin("vault_manifest_upload", role="vault", kind="manifest")
        existing_vault_manifest = head_object_receipt(
            vault_client,
            bucket=vault_bucket,
            key=locked_manifest_key,
            expected_sha256=manifest_sha256,
        )
        if existing_vault_manifest is None:
            vault_manifest = upload_locked_bytes(
                vault_client,
                bucket=vault_bucket,
                key=locked_manifest_key,
                data=manifest_bytes,
                expected_sha256=manifest_sha256,
                content_type=manifest_content_type,
                retention_until=retention_until,
                metadata={"firemark-kind": "manifest", "firemark-schema": "1"},
                stage_callback=lambda stage: begin(stage, role="vault", kind="manifest"),
                upload_stage="vault_manifest_upload",
                hash_verification_stage="vault_manifest_hash_verification",
                retention_verification_stage="vault_manifest_retention_readback",
                retention_validation_stage="vault_manifest_retention_validation",
            )
        else:
            begin("vault_manifest_hash_verification", role="vault", kind="manifest")
            download_bytes_verified(
                vault_client,
                bucket=vault_bucket,
                key=locked_manifest_key,
                expected_sha256=manifest_sha256,
                version_id=existing_vault_manifest.version_id,
            )
            begin("vault_manifest_retention_readback", role="vault", kind="manifest")
            state = read_object_retention(
                vault_client,
                bucket=vault_bucket,
                key=locked_manifest_key,
                version_id=existing_vault_manifest.version_id,
            )
            begin("vault_manifest_retention_validation", role="vault", kind="manifest")
            if not _retention_covers(state.retain_until, retention_until):
                raise B2CustodyWorkflowError("Existing vault manifest retention conflicts")
            vault_manifest = LockedObjectReceipt(
                **existing_vault_manifest.model_dump(),
                retention_until=state.retain_until,
                retention_verified=True,
            )
        partial_keys.append(locked_manifest_key)
        partial_objects.append(
            PartialB2Object(
                "vault", "manifest", locked_manifest_key, vault_manifest.version_id, True
            )
        )
        custody_receipt = B2CustodyReceipt(
            source_sha256=source_sha256,
            canonical_hash=canonical_hash,
            assets_source=assets_source,
            assets_manifest=assets_manifest,
            vault_source=vault_source,
            vault_manifest=vault_manifest,
            requested_retention_until=retention_until,
            created_at=timestamp,
            custody_verified=True,
        )
        begin("checkpoint_after_vault_manifest", role="vault", kind="manifest")
        if persistence_callback is not None:
            persistence_callback(tuple(partial_objects))
    except Exception as exc:
        if (
            isinstance(exc, B2PersistedObjectError)
            and bucket_role == "vault"
            and object_kind in {"source", "manifest"}
        ):
            partial_kind: Literal["source", "manifest"] = (
                "source" if object_kind == "source" else "manifest"
            )
            partial_objects.append(
                PartialB2Object(
                    "vault",
                    partial_kind,
                    exc.key,
                    exc.version_id,
                    exc.retained,
                )
            )
        for stored in created_assets:
            try:
                delete_unlocked_version_verified(
                    assets_client,
                    bucket=assets_bucket,
                    key=stored.key,
                    version_id=stored.version_id,
                    expected_sha256=stored.sha256,
                    known_unlocked=True,
                )
            except Exception:
                pass
        failure = classify_b2_failure(exc, stage=current_stage)
        raise B2CustodyWorkflowError(
            "B2 custody failed; inspect safe partial_keys before retrying",
            partial_keys=tuple(partial_keys),
            stage=current_stage,
            category=failure.category,
            service_error_code=failure.service_error_code,
            bucket_role=bucket_role,
            object_kind=object_kind,
            partial_objects=tuple(partial_objects),
        ) from exc

    return custody_receipt
