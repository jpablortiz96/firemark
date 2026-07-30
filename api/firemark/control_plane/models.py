"""Frozen domain and API models for the FIREMARK Control Plane."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator, model_validator

from api.firemark.custody import B2CustodyReceipt
from api.firemark.seal_envelope import SignedSealEnvelopeV1

CertificateStatus = Literal["active", "revoked", "invalid"]
AssetType = Literal["image", "audio"]
VerificationStatus = Literal[
    "verified",
    "hash_mismatch",
    "signature_invalid",
    "certificate_revoked",
    "certificate_not_found",
    "malformed_evidence",
]
DeliveryStatus = Literal["issued", "blocked", "storage_failure"]
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class FrozenModel(BaseModel):
    """Shared immutable and closed validation policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Control-plane timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _nonblank(value: str) -> str:
    if not value.strip():
        raise ValueError("Control-plane identifiers must not be blank")
    return value


def _identifier(value: str) -> str:
    if not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError("FIREMARK identifiers must use 1-128 safe characters")
    return value


def _digest(value: str) -> str:
    if not _SHA256_PATTERN.fullmatch(value):
        raise ValueError("SHA-256 must be 64 lowercase hexadecimal characters")
    return value


class GenerationRunRecord(FrozenModel):
    """Private canonical generation provenance persisted by the backend."""

    run_id: str
    provider: str
    model: str
    ai_generated: bool
    prompt_private: str
    parameters_private: dict[str, Any]
    seed_private: int | str | None = None
    canonical_hash: str
    manifest_storage_key: str
    manifest_version_id: str | None = None
    created_at: datetime

    _ids = field_validator("run_id")(_identifier)
    _text = field_validator("provider", "model", "prompt_private", "manifest_storage_key")(
        _nonblank
    )
    _hash = field_validator("canonical_hash")(_digest)
    _time = field_validator("created_at")(_utc)


class AssetRecord(FrozenModel):
    """Private source/sealed asset relationship and exact delivery location."""

    asset_id: str
    run_id: str
    asset_type: AssetType
    media_type: str
    file_extension: str
    byte_size: int = Field(gt=0)
    width: int | None = Field(default=None, gt=0)
    height: int | None = Field(default=None, gt=0)
    duration_ms: int | None = Field(default=None, gt=0)
    source_sha256: str
    sealed_sha256: str
    assets_bucket: str
    assets_key: str
    assets_version_id: str
    vault_bucket: str
    vault_key: str
    vault_version_id: str
    created_at: datetime

    _ids = field_validator("asset_id", "run_id")(_identifier)
    _text = field_validator(
        "media_type", "file_extension", "assets_bucket", "assets_key", "assets_version_id",
        "vault_bucket", "vault_key", "vault_version_id",
    )(_nonblank)
    _hashes = field_validator("source_sha256", "sealed_sha256")(_digest)
    _time = field_validator("created_at")(_utc)

    @model_validator(mode="after")
    def validate_media_relationships(self) -> AssetRecord:
        if self.asset_type == "image" and self.source_sha256 == self.sealed_sha256:
            raise ValueError("Image source_sha256 and sealed_sha256 must be different")
        if self.asset_type == "image" and self.duration_ms is not None:
            raise ValueError("Image assets cannot declare audio duration")
        if self.asset_type == "audio" and (self.width is not None or self.height is not None):
            raise ValueError("Audio assets cannot declare image dimensions")
        if (self.width is None) != (self.height is None):
            raise ValueError("Image width and height must be supplied together")
        return self


class CustodyRecord(FrozenModel):
    """Private immutable custody evidence associated with one asset."""

    asset_id: str
    custody_receipt: B2CustodyReceipt
    retention_mode: Literal["COMPLIANCE"]
    retention_until: datetime
    custody_verified: bool
    created_at: datetime

    _id = field_validator("asset_id")(_identifier)
    _times = field_validator("retention_until", "created_at")(_utc)

    @model_validator(mode="after")
    def require_verified_receipt(self) -> CustodyRecord:
        if self.custody_verified and not self.custody_receipt.custody_verified:
            raise ValueError("Verified custody requires a verified receipt")
        return self


class CertificateRecord(FrozenModel):
    """Stored certificate plus private relationships needed by the Verify Gate."""

    cert_id: str
    asset_id: str
    run_id: str
    provider: str
    model: str
    media_type: AssetType
    mime_type: str
    byte_size: int = Field(gt=0)
    ai_generated: bool
    width: int | None = Field(default=None, gt=0)
    height: int | None = Field(default=None, gt=0)
    duration_ms: int | None = Field(default=None, gt=0)
    source_sha256: str
    sealed_sha256: str
    canonical_hash: str
    signer_key_id: str
    signer_public_key_b64: str
    signature_b64: str
    signed_envelope: SignedSealEnvelopeV1
    public_manifest: dict[str, Any]
    certificate_status: CertificateStatus = "active"
    issued_at: datetime
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    asset: AssetRecord | None = Field(default=None, repr=False)
    custody: CustodyRecord | None = Field(default=None, repr=False)

    _ids = field_validator("cert_id", "asset_id", "run_id")(_identifier)
    _texts = field_validator("signer_key_id", "signer_public_key_b64", "signature_b64")(
        _nonblank
    )
    _media_text = field_validator("provider", "model", "mime_type")(_nonblank)
    _hashes = field_validator("source_sha256", "sealed_sha256", "canonical_hash")(_digest)
    _issued = field_validator("issued_at")(_utc)

    @field_validator("revoked_at")
    @classmethod
    def normalize_optional_time(cls, value: datetime | None) -> datetime | None:
        return _utc(value) if value is not None else None

    @model_validator(mode="after")
    def validate_status(self) -> CertificateRecord:
        revoked_fields = self.revoked_at is not None and bool(self.revocation_reason)
        if (self.certificate_status == "revoked") != revoked_fields:
            raise ValueError("Revoked certificates require timestamp and reason only when revoked")
        return self


class PublicCertificate(FrozenModel):
    """Safe public Birth Certificate projection."""

    schema_version: Literal["1.0"] = "1.0"
    cert_id: str
    asset_id: str
    run_id: str
    provider: str
    model: str
    media_type: AssetType
    mime_type: str
    byte_size: int = Field(gt=0)
    ai_generated: bool
    width: int | None = Field(default=None, gt=0)
    height: int | None = Field(default=None, gt=0)
    duration_ms: int | None = Field(default=None, gt=0)
    source_sha256: str
    sealed_sha256: str
    canonical_hash: str
    signer_key_id: str
    signer_public_key_b64: str
    signature_b64: str
    public_manifest: dict[str, Any]
    certificate_status: CertificateStatus
    issued_at: datetime
    verify_url: AnyHttpUrl

    _ids = field_validator("cert_id", "asset_id", "run_id")(_identifier)
    _hashes = field_validator("source_sha256", "sealed_sha256", "canonical_hash")(_digest)
    _media_text = field_validator("provider", "model", "mime_type")(_nonblank)
    _time = field_validator("issued_at")(_utc)


class VerificationRequest(FrozenModel):
    """Supported hash-based certificate verification request."""

    cert_id: str
    presented_sha256: str | None = None

    _id = field_validator("cert_id")(_identifier)
    _hash = field_validator("presented_sha256")(
        lambda value: _digest(value) if value is not None else None
    )


class VerificationResult(FrozenModel):
    """Deterministic result of certificate verification."""

    verification_event_id: UUID
    cert_id: str
    media_type: AssetType | None = None
    mime_type: str | None = None
    provider: str | None = None
    model: str | None = None
    status: VerificationStatus
    verified: bool
    signature_valid: bool
    envelope_valid: bool
    hash_match: bool | None
    custody_reference_valid: bool
    safe_reason_code: str
    verified_at: datetime

    _time = field_validator("verified_at")(_utc)


class DeliveryAuthorization(FrozenModel):
    """Verify Gate request requiring the final distributed-byte hash."""

    presented_sha256: str

    _hash = field_validator("presented_sha256")(_digest)


class DeliveryResult(FrozenModel):
    """Persistence-safe delivery decision; it deliberately contains no URL."""

    delivery_event_id: UUID | None
    verification_event_id: UUID
    cert_id: str
    status: DeliveryStatus
    safe_reason_code: str
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def normalize_expiry(cls, value: datetime | None) -> datetime | None:
        return _utc(value) if value is not None else None


class DeliveryHTTPResponse(FrozenModel):
    """Transport-only serializer for an authorized short-lived URL."""

    cert_id: str
    status: Literal["issued"]
    download_url: AnyHttpUrl = Field(repr=False)
    expires_at: datetime
    expires_in: int

    _time = field_validator("expires_at")(_utc)
