"""Deterministic PNG public-capsule privacy and integrity tests."""

from __future__ import annotations

import io
import json
import struct
import zlib
from datetime import UTC, datetime

import pytest
from PIL import Image
from pydantic import ValidationError

from api.firemark.generation.fake_provider import _TINY_PNG
from api.firemark.public_capsule import (
    PUBLIC_CAPSULE_KEY,
    FiremarkPublicCapsuleV1,
    PublicCapsuleError,
    detect_duplicate_capsules,
    embed_public_capsule_png,
    extract_public_capsule_png,
    validate_public_capsule_png,
)


def capsule(**updates: object) -> FiremarkPublicCapsuleV1:
    values: dict[str, object] = {
        "cert_id": "firemark-cert-test",
        "asset_id": "firemark-asset-test",
        "run_id": "firemark-run-test",
        "canonical_hash": "1" * 64,
        "source_sha256": "2" * 64,
        "signer_key_id": "firemark-ed25519-test",
        "verify_url": "https://verify.firemark.test/v1/certificates/firemark-cert-test",
        "issued_at": datetime(2026, 7, 30, 12, tzinfo=UTC),
    }
    values.update(updates)
    return FiremarkPublicCapsuleV1.model_validate(values)


def text_chunk(payload: bytes) -> bytes:
    data = PUBLIC_CAPSULE_KEY.encode() + b"\0" + payload
    kind = b"tEXt"
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def replace_capsule(png: bytes, payload: bytes) -> bytes:
    marker = PUBLIC_CAPSULE_KEY.encode() + b"\0"
    start = png.index(marker) - 8
    length = struct.unpack(">I", png[start : start + 4])[0]
    end = start + 12 + length
    return png[:start] + text_chunk(payload) + png[end:]


def test_canonical_embedding_is_deterministic_extractable_and_pixel_preserving() -> None:
    expected = capsule()
    sealed = embed_public_capsule_png(_TINY_PNG, expected)
    assert sealed != _TINY_PNG
    assert embed_public_capsule_png(sealed, expected) == sealed
    assert extract_public_capsule_png(sealed) == expected
    assert validate_public_capsule_png(sealed, expected)
    assert not detect_duplicate_capsules(sealed)
    with Image.open(io.BytesIO(_TINY_PNG)) as source, Image.open(io.BytesIO(sealed)) as result:
        assert source.size == result.size
        assert list(source.getdata()) == list(result.getdata())
    serialized = expected.canonical_bytes()
    for forbidden in (b"sealed_sha256", b"prompt", b"seed", b"signature", b"private"):
        assert forbidden not in serialized


def test_conflicting_duplicate_missing_and_invalid_pngs_fail_closed() -> None:
    sealed = embed_public_capsule_png(_TINY_PNG, capsule())
    with pytest.raises(PublicCapsuleError, match="conflicting"):
        embed_public_capsule_png(sealed, capsule(cert_id="different-cert"))
    duplicated = sealed[:-12] + text_chunk(capsule().canonical_bytes()) + sealed[-12:]
    assert detect_duplicate_capsules(duplicated)
    with pytest.raises(PublicCapsuleError, match="duplicate"):
        extract_public_capsule_png(duplicated)
    with pytest.raises(PublicCapsuleError, match="missing"):
        extract_public_capsule_png(_TINY_PNG)
    assert not validate_public_capsule_png(_TINY_PNG)
    with pytest.raises(PublicCapsuleError, match="not a PNG"):
        embed_public_capsule_png(b"not-png", capsule())
    corrupt = bytearray(_TINY_PNG)
    corrupt[-1] ^= 1
    with pytest.raises(PublicCapsuleError, match="CRC"):
        embed_public_capsule_png(bytes(corrupt), capsule())


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        json.dumps({"sealed_sha256": "3" * 64}).encode(),
        json.dumps(capsule().model_dump(mode="json"), indent=2).encode(),
        b"[]",
    ],
)
def test_malformed_private_extra_and_noncanonical_capsules_are_rejected(payload: bytes) -> None:
    sealed = embed_public_capsule_png(_TINY_PNG, capsule())
    with pytest.raises(PublicCapsuleError, match="malformed|canonical"):
        extract_public_capsule_png(replace_capsule(sealed, payload))


def test_model_is_closed_hashes_are_strict_and_capsule_size_is_bounded() -> None:
    with pytest.raises(ValidationError):
        capsule(prompt="must never ship")
    with pytest.raises(ValidationError, match="SHA-256"):
        capsule(source_sha256="bad")
    with pytest.raises(PublicCapsuleError, match="size"):
        capsule(verify_url="https://verify.firemark.test/" + "x" * 9000).canonical_bytes()
    with pytest.raises(ValidationError, match="HTTPS"):
        capsule(verify_url="http://verify.firemark.test/cert")
    with pytest.raises(ValidationError, match="query"):
        capsule(verify_url="https://verify.firemark.test/cert?token=private")
    with pytest.raises(ValidationError, match="safe characters"):
        capsule(cert_id="unsafe cert id")


def test_truncated_trailing_and_non_text_reserved_chunks_are_rejected() -> None:
    with pytest.raises(PublicCapsuleError, match="truncated"):
        embed_public_capsule_png(_TINY_PNG[:-5], capsule())
    with pytest.raises(PublicCapsuleError, match="IEND"):
        embed_public_capsule_png(_TINY_PNG + b"trailing", capsule())
    data = PUBLIC_CAPSULE_KEY.encode() + b"\0\0invalid"
    kind = b"iTXt"
    chunk = (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )
    png = _TINY_PNG[:-12] + chunk + _TINY_PNG[-12:]
    with pytest.raises(PublicCapsuleError, match="unsupported"):
        extract_public_capsule_png(png)
