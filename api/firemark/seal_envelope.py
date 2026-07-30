"""Canonical FIREMARK Seal Envelope models and signature operations."""

from __future__ import annotations

import hmac
import json
import re
from datetime import UTC, datetime
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from api.firemark.signer import (
    Ed25519KeyPair,
    Ed25519Signer,
    KeyMaterialError,
    decode_signature_base64,
    public_key_fingerprint,
    public_key_signer_id,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT_PATTERN = re.compile(r"^SHA256:[A-Za-z0-9_-]{43}$")
_NON_BLANK_FIELDS = (
    "cert_id",
    "run_id",
    "sealed_asset_bucket",
    "sealed_asset_key",
    "public_manifest_bucket",
    "public_manifest_key",
    "vault_bucket",
    "vault_source_key",
    "vault_source_version_id",
    "vault_manifest_key",
    "vault_manifest_version_id",
    "signer_key_id",
)


def _canonical_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class SealEnvelopeV1(BaseModel):
    """Immutable, canonical metadata covered by the FIREMARK signature."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    cert_id: str
    run_id: str
    canonical_hash: str
    source_sha256: str
    sealed_sha256: str
    sealed_asset_bucket: str
    sealed_asset_key: str
    public_manifest_bucket: str
    public_manifest_key: str
    vault_bucket: str
    vault_source_key: str
    vault_source_version_id: str
    vault_manifest_key: str
    vault_manifest_version_id: str
    retention_until: datetime
    signer_key_id: str
    created_at: datetime

    @field_validator("canonical_hash", "source_sha256", "sealed_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        """Require a lowercase 64-character hexadecimal SHA-256 digest."""
        if not _SHA256_PATTERN.fullmatch(value):
            raise ValueError("SHA-256 digests must be 64 lowercase hexadecimal characters")
        return value

    @field_validator(*_NON_BLANK_FIELDS)
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        """Reject empty or whitespace-only identifiers and storage locations."""
        if not value.strip():
            raise ValueError("Envelope identifiers and storage locations must not be blank")
        return value

    @field_validator("retention_until", "created_at")
    @classmethod
    def normalize_utc(cls, value: datetime) -> datetime:
        """Require timezone awareness and normalize timestamps to UTC."""
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Envelope timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_trust_relationships(self) -> SealEnvelopeV1:
        """Enforce forward retention ordering.

        Byte-preserving formats such as FIREMARK audio intentionally bind the same source and
        sealed digest. The issuance service still requires distinct hashes for embedded PNGs.
        """
        if self.retention_until <= self.created_at:
            raise ValueError("retention_until must be later than created_at")
        return self

    def canonical_bytes(self) -> bytes:
        """Serialize the complete envelope as deterministic UTF-8 JSON."""
        values = self.model_dump(mode="python")
        values["retention_until"] = _canonical_timestamp(self.retention_until)
        values["created_at"] = _canonical_timestamp(self.created_at)
        return json.dumps(
            values,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


class SignedSealEnvelopeV1(BaseModel):
    """Immutable FIREMARK Seal Envelope with its detached Ed25519 signature."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    envelope: SealEnvelopeV1
    algorithm: Literal["Ed25519"] = "Ed25519"
    signature: str
    public_key_fingerprint: str

    @field_validator("signature")
    @classmethod
    def validate_signature(cls, value: str) -> str:
        """Require a canonical Base64 encoding of exactly 64 signature bytes."""
        try:
            decode_signature_base64(value)
        except KeyMaterialError as exc:
            raise ValueError(str(exc)) from exc
        return value

    @field_validator("public_key_fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        """Require the canonical FIREMARK public-key fingerprint shape."""
        if not _FINGERPRINT_PATTERN.fullmatch(value):
            raise ValueError("Invalid FIREMARK public-key fingerprint")
        return value


def sign_envelope(envelope: SealEnvelopeV1, signer: Ed25519Signer) -> SignedSealEnvelopeV1:
    """Sign the complete canonical envelope with a matching Ed25519 signer."""
    validated = SealEnvelopeV1.model_validate(envelope.model_dump())
    if not hmac.compare_digest(validated.signer_key_id, signer.signer_key_id):
        raise KeyMaterialError("Envelope signer_key_id does not match the signing key")
    return SignedSealEnvelopeV1(
        envelope=validated,
        signature=signer.sign(validated.canonical_bytes()),
        public_key_fingerprint=signer.fingerprint,
    )


def _verifier_from_public_key(public_key: object) -> Ed25519Signer:
    if isinstance(public_key, str):
        return Ed25519Signer.from_public_key_base64(public_key)
    if isinstance(public_key, Ed25519PublicKey):
        return Ed25519Signer(Ed25519KeyPair(public_key=public_key))
    raise KeyMaterialError("Unsupported Ed25519 public key value")


def verify_signed_envelope(
    signed_envelope: SignedSealEnvelopeV1,
    public_key: Ed25519PublicKey | str,
) -> bool:
    """Fail closed unless key identity and the detached signature all verify."""
    try:
        validated = SignedSealEnvelopeV1.model_validate(signed_envelope.model_dump())
        verifier = _verifier_from_public_key(public_key)
    except (KeyMaterialError, ValidationError, TypeError, ValueError):
        return False

    expected_fingerprint = public_key_fingerprint(verifier.public_key)
    expected_signer_key_id = public_key_signer_id(verifier.public_key)
    if not hmac.compare_digest(validated.public_key_fingerprint, expected_fingerprint):
        return False
    if not hmac.compare_digest(validated.envelope.signer_key_id, expected_signer_key_id):
        return False
    return verifier.verify(validated.envelope.canonical_bytes(), validated.signature)
