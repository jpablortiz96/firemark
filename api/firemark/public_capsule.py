"""Deterministic redacted FIREMARK capsule embedded in distributable PNGs."""

from __future__ import annotations

import json
import re
import struct
import zlib
from datetime import UTC, datetime
from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, field_validator

from api.firemark.generation.models import PNG_MAGIC

PUBLIC_CAPSULE_KEY = "firemark.public-capsule"
MAX_PUBLIC_CAPSULE_BYTES = 8 * 1024
_TEXT_CHUNKS = {b"tEXt", b"zTXt", b"iTXt"}


class PublicCapsuleError(ValueError):
    """A PNG does not contain exactly one valid safe FIREMARK capsule."""


class FiremarkPublicCapsuleV1(BaseModel):
    """Closed public provenance subset safe to ship inside a sealed PNG."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["firemark.public-capsule.v1"] = "firemark.public-capsule.v1"
    cert_id: str
    asset_id: str
    run_id: str
    canonical_hash: str
    source_sha256: str
    signer_key_id: str
    verify_url: AnyHttpUrl
    issued_at: datetime

    @field_validator("issued_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Capsule timestamp must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("canonical_hash", "source_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("Capsule hashes must be lowercase SHA-256 values")
        return value

    @field_validator("cert_id", "asset_id", "run_id", "signer_key_id")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
            raise ValueError("Capsule identifiers must use 1-128 safe characters")
        return value

    @field_validator("verify_url")
    @classmethod
    def validate_verify_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if value.scheme != "https" or value.username or value.password:
            raise ValueError("Capsule verify_url must be credential-free HTTPS")
        if value.query or value.fragment:
            raise ValueError("Capsule verify_url must not contain query or fragment metadata")
        return value

    def canonical_bytes(self) -> bytes:
        values = self.model_dump(mode="json")
        values["issued_at"] = self.issued_at.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
        payload = json.dumps(
            values,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        if len(payload) > MAX_PUBLIC_CAPSULE_BYTES:
            raise PublicCapsuleError("Public capsule exceeds the size limit")
        return payload


def _chunks(png: bytes) -> list[tuple[int, bytes, bytes, int]]:
    if not png.startswith(PNG_MAGIC):
        raise PublicCapsuleError("Media is not a PNG")
    chunks: list[tuple[int, bytes, bytes, int]] = []
    offset = len(PNG_MAGIC)
    saw_iend = False
    while offset < len(png):
        if len(png) - offset < 12:
            raise PublicCapsuleError("PNG chunk is truncated")
        length = struct.unpack(">I", png[offset : offset + 4])[0]
        end = offset + 12 + length
        if end > len(png):
            raise PublicCapsuleError("PNG chunk length is invalid")
        kind = png[offset + 4 : offset + 8]
        data = png[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", png[offset + 8 + length : end])[0]
        if zlib.crc32(kind + data) & 0xFFFFFFFF != expected_crc:
            raise PublicCapsuleError("PNG chunk CRC is invalid")
        chunks.append((offset, kind, data, end))
        offset = end
        if kind == b"IEND":
            saw_iend = True
            break
    if not saw_iend or offset != len(png):
        raise PublicCapsuleError("PNG must end with one IEND chunk")
    return chunks


def _reserved_payloads(png: bytes) -> list[bytes]:
    payloads: list[bytes] = []
    keyword = PUBLIC_CAPSULE_KEY.encode("ascii")
    for _, kind, data, _ in _chunks(png):
        if kind not in _TEXT_CHUNKS:
            continue
        separator = data.find(b"\0")
        if separator < 0 or data[:separator] != keyword:
            continue
        if kind != b"tEXt":
            raise PublicCapsuleError("Reserved FIREMARK metadata uses an unsupported encoding")
        payloads.append(data[separator + 1 :])
    return payloads


def detect_duplicate_capsules(png: bytes) -> bool:
    """Return whether more than one reserved FIREMARK metadata entry exists."""
    return len(_reserved_payloads(png)) > 1


def _text_chunk(payload: bytes) -> bytes:
    data = PUBLIC_CAPSULE_KEY.encode("ascii") + b"\0" + payload
    kind = b"tEXt"
    crc = zlib.crc32(kind + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)


def embed_public_capsule_png(png: bytes, capsule: FiremarkPublicCapsuleV1) -> bytes:
    """Insert one canonical tEXt capsule before IEND without changing pixel chunks."""
    canonical = capsule.canonical_bytes()
    existing = _reserved_payloads(png)
    if len(existing) > 1:
        raise PublicCapsuleError("PNG contains duplicate FIREMARK capsules")
    if existing:
        if existing[0] == canonical:
            return png
        raise PublicCapsuleError("PNG contains a conflicting FIREMARK capsule")
    iend_offset = next(offset for offset, kind, _, _ in _chunks(png) if kind == b"IEND")
    return png[:iend_offset] + _text_chunk(canonical) + png[iend_offset:]


def extract_public_capsule_png(png: bytes) -> FiremarkPublicCapsuleV1:
    """Extract and strictly validate exactly one reserved public capsule."""
    payloads = _reserved_payloads(png)
    if len(payloads) != 1:
        reason = "missing" if not payloads else "duplicated"
        raise PublicCapsuleError(f"FIREMARK capsule is {reason}")
    if len(payloads[0]) > MAX_PUBLIC_CAPSULE_BYTES:
        raise PublicCapsuleError("Public capsule exceeds the size limit")
    try:
        value = json.loads(payloads[0].decode("ascii"))
        if not isinstance(value, dict):
            raise TypeError
        capsule = FiremarkPublicCapsuleV1.model_validate(value)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PublicCapsuleError("FIREMARK capsule is malformed") from exc
    if capsule.canonical_bytes() != payloads[0]:
        raise PublicCapsuleError("FIREMARK capsule is not canonically encoded")
    return capsule


def validate_public_capsule_png(
    png: bytes,
    expected: FiremarkPublicCapsuleV1 | None = None,
) -> bool:
    """Return true only for one canonical capsule matching the optional expectation."""
    try:
        extracted = extract_public_capsule_png(png)
    except PublicCapsuleError:
        return False
    return expected is None or extracted == expected
