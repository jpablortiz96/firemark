"""Safe durable local checkpoint for resumable Generate & Seal operations."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

CHECKPOINT_SCHEMA_VERSION: Literal["firemark.generate-and-seal-checkpoint.v1"] = (
    "firemark.generate-and-seal-checkpoint.v1"
)
DEFAULT_CHECKPOINT_PATH = Path(".artifacts/generate-and-seal-checkpoint.json")
DEFAULT_PRIVATE_ROOT = Path(".artifacts/generate-and-seal-private")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class CheckpointObject(BaseModel):
    """Safe exact-version storage reference without credentials or object bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_role: Literal["assets", "vault"]
    object_kind: Literal["source", "manifest", "sealed"]
    bucket: str
    key: str
    sha256: str
    version_id: str
    retention_mode: Literal["COMPLIANCE"] | None = None
    retention_until: datetime | None = None
    size_bytes: int


class CheckpointPartialObject(BaseModel):
    """Minimum safe evidence retained when an upload failed during verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_role: Literal["assets", "vault"]
    object_kind: Literal["source", "manifest", "sealed"]
    key: str
    version_id: str | None
    retained: bool


class GenerateAndSealCheckpoint(BaseModel):
    """Allowlisted recovery state; private evidence remains in separate ignored files."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["firemark.generate-and-seal-checkpoint.v1"] = CHECKPOINT_SCHEMA_VERSION
    operation_state: Literal[
        "prepared", "custody_persisted", "sealed_persisted", "registered", "complete"
    ]
    run_id: str
    asset_id: str
    cert_id: str
    source_sha256: str
    sealed_sha256: str
    canonical_hash: str
    issued_at: datetime
    requested_retention_until: datetime
    signer_key_id: str
    provider: str
    model: str
    size: str
    generated_byte_count: int
    source_path: str
    manifest_path: str
    ai_generated: Literal[True] = True
    local_fixture: Literal[False] = False
    new_provider_calls: Literal[0] = 0
    stage_results: tuple[dict[str, str], ...] = ()
    assets_source: CheckpointObject | None = None
    assets_manifest: CheckpointObject | None = None
    vault_source: CheckpointObject | None = None
    vault_manifest: CheckpointObject | None = None
    sealed_asset: CheckpointObject | None = None
    partial_objects: tuple[CheckpointPartialObject, ...] = ()

    @field_validator("run_id", "asset_id", "cert_id", "signer_key_id")
    @classmethod
    def safe_identifier(cls, value: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("Checkpoint identifiers must use safe characters")
        return value

    @field_validator("issued_at", "requested_retention_until")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Checkpoint timestamps must be timezone-aware")
        return value.astimezone(UTC)


def checkpoint_object(
    receipt: Any,
    *,
    bucket_role: Literal["assets", "vault"],
    object_kind: Literal["source", "manifest", "sealed"],
) -> CheckpointObject:
    """Project a storage receipt onto the safe checkpoint allowlist."""
    if receipt.version_id is None:
        raise ValueError("Checkpoint storage references require exact VersionIds")
    return CheckpointObject(
        bucket_role=bucket_role,
        object_kind=object_kind,
        bucket=receipt.bucket,
        key=receipt.key,
        sha256=receipt.sha256,
        version_id=receipt.version_id,
        retention_mode=getattr(receipt, "retention_mode", None),
        retention_until=getattr(receipt, "retention_until", None),
        size_bytes=receipt.size_bytes,
    )


def write_checkpoint_atomic(path: Path, checkpoint: GenerateAndSealCheckpoint) -> None:
    """Atomically replace one ignored checkpoint without rendering its contents."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            checkpoint.model_dump(mode="json"),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_checkpoint(path: Path) -> GenerateAndSealCheckpoint:
    """Read and validate a safe checkpoint without loading its private evidence files."""
    return GenerateAndSealCheckpoint.model_validate_json(path.read_bytes())


def write_private_evidence_atomic(
    root: Path,
    *,
    run_id: str,
    source_bytes: bytes,
    manifest_bytes: bytes,
) -> tuple[Path, Path]:
    """Persist ignored private working bytes atomically for provider-free recovery."""
    if not _SAFE_ID.fullmatch(run_id):
        raise ValueError("Unsafe checkpoint run identifier")
    directory = root / run_id
    directory.mkdir(parents=True, exist_ok=True)

    def write(name: str, payload: bytes) -> Path:
        destination = directory / name
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{name}.", dir=directory)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            temporary.write_bytes(payload)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return destination.resolve()

    return write("source.png", source_bytes), write("private-manifest.json", manifest_bytes)
