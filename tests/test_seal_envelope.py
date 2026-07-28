"""Tests for canonical FIREMARK Seal Envelopes."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from api.firemark.seal_envelope import (
    SealEnvelopeV1,
    SignedSealEnvelopeV1,
    sign_envelope,
    verify_signed_envelope,
)
from api.firemark.signer import Ed25519Signer, KeyMaterialError


def envelope_values(signer: Ed25519Signer) -> dict[str, Any]:
    """Return clearly labeled local test values for a valid envelope."""
    created_at = datetime(2026, 2, 3, 4, 5, 6, 789, tzinfo=UTC)
    return {
        "schema_version": "1.0",
        "cert_id": "test-certificate-é",
        "run_id": "test-run",
        "canonical_hash": "a" * 64,
        "source_sha256": "b" * 64,
        "sealed_sha256": "c" * 64,
        "sealed_asset_bucket": "test-assets",
        "sealed_asset_key": "test/sealed.bin",
        "public_manifest_bucket": "test-public-manifests",
        "public_manifest_key": "test/public-manifest.json",
        "vault_bucket": "test-vault",
        "vault_source_key": "test/source.bin",
        "vault_source_version_id": "test-source-version",
        "vault_manifest_key": "test/private-manifest.json",
        "vault_manifest_version_id": "test-manifest-version",
        "retention_until": created_at + timedelta(days=30),
        "signer_key_id": signer.signer_key_id,
        "created_at": created_at,
    }


def test_valid_construction_and_canonical_bytes() -> None:
    signer = Ed25519Signer.generate()
    envelope = SealEnvelopeV1.model_validate(envelope_values(signer))
    first = envelope.canonical_bytes()
    second = envelope.canonical_bytes()
    decoded = first.decode("utf-8")

    assert first == second
    assert "é" in decoded
    assert not decoded.endswith("\n")
    assert ": " not in decoded
    assert decoded.index('"canonical_hash"') < decoded.index('"cert_id"')
    assert '"created_at":"2026-02-03T04:05:06.000789Z"' in decoded


def test_field_order_independence_through_reconstruction() -> None:
    signer = Ed25519Signer.generate()
    values = envelope_values(signer)
    original = SealEnvelopeV1.model_validate(values)
    reversed_values = dict(reversed(list(values.items())))
    reconstructed = SealEnvelopeV1.model_validate(reversed_values)

    assert reconstructed.canonical_bytes() == original.canonical_bytes()


@pytest.mark.parametrize(
    "digest",
    ["a" * 63, "a" * 65, "A" * 64, "g" * 64, "not-a-digest"],
)
@pytest.mark.parametrize("field", ["canonical_hash", "source_sha256", "sealed_sha256"])
def test_digest_validation(field: str, digest: str) -> None:
    signer = Ed25519Signer.generate()
    values = envelope_values(signer)
    values[field] = digest

    with pytest.raises(ValidationError, match="64 lowercase hexadecimal"):
        SealEnvelopeV1.model_validate(values)


def test_source_and_sealed_digest_must_differ() -> None:
    signer = Ed25519Signer.generate()
    values = envelope_values(signer)
    values["sealed_sha256"] = values["source_sha256"]

    with pytest.raises(ValidationError, match="must be different"):
        SealEnvelopeV1.model_validate(values)


def test_schema_version_is_fixed() -> None:
    signer = Ed25519Signer.generate()
    values = envelope_values(signer)
    values["schema_version"] = "2.0"

    with pytest.raises(ValidationError):
        SealEnvelopeV1.model_validate(values)


@pytest.mark.parametrize(
    "field",
    [
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
    ],
)
def test_blank_identifiers_and_storage_fields_are_rejected(field: str) -> None:
    signer = Ed25519Signer.generate()
    values = envelope_values(signer)
    values[field] = "  "

    with pytest.raises(ValidationError, match="must not be blank"):
        SealEnvelopeV1.model_validate(values)


@pytest.mark.parametrize("field", ["created_at", "retention_until"])
def test_naive_timestamp_is_rejected(field: str) -> None:
    signer = Ed25519Signer.generate()
    values = envelope_values(signer)
    values[field] = datetime(2026, 1, 1)

    with pytest.raises(ValidationError, match="timezone-aware"):
        SealEnvelopeV1.model_validate(values)


def test_timestamps_are_normalized_to_utc() -> None:
    signer = Ed25519Signer.generate()
    values = envelope_values(signer)
    offset = timezone(timedelta(hours=-5))
    values["created_at"] = datetime(2026, 1, 1, 7, tzinfo=offset)
    values["retention_until"] = datetime(2026, 1, 2, 7, tzinfo=offset)

    envelope = SealEnvelopeV1.model_validate(values)

    assert envelope.created_at == datetime(2026, 1, 1, 12, tzinfo=UTC)
    assert envelope.created_at.tzinfo is UTC
    assert envelope.retention_until.tzinfo is UTC


@pytest.mark.parametrize("delta", [timedelta(0), timedelta(seconds=-1)])
def test_retention_must_follow_creation(delta: timedelta) -> None:
    signer = Ed25519Signer.generate()
    values = envelope_values(signer)
    values["retention_until"] = values["created_at"] + delta

    with pytest.raises(ValidationError, match="must be later"):
        SealEnvelopeV1.model_validate(values)


def test_envelope_is_immutable_and_rejects_unknown_fields() -> None:
    signer = Ed25519Signer.generate()
    envelope = SealEnvelopeV1.model_validate(envelope_values(signer))

    with pytest.raises(ValidationError, match="frozen"):
        envelope.cert_id = "changed"

    values = envelope_values(signer)
    values["unknown"] = "rejected"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SealEnvelopeV1.model_validate(values)


def test_valid_sign_and_verify_with_base64_and_public_key_object() -> None:
    signer = Ed25519Signer.generate()
    envelope = SealEnvelopeV1.model_validate(envelope_values(signer))
    signed = sign_envelope(envelope, signer)

    assert verify_signed_envelope(signed, signer.export_public_key_base64())
    assert verify_signed_envelope(signed, signer.public_key)


SECURITY_FIELD_MUTATIONS: tuple[tuple[str, object], ...] = (
    ("cert_id", "changed-certificate"),
    ("run_id", "changed-run"),
    ("canonical_hash", "d" * 64),
    ("source_sha256", "e" * 64),
    ("sealed_sha256", "f" * 64),
    ("sealed_asset_bucket", "changed-assets"),
    ("sealed_asset_key", "changed/sealed.bin"),
    ("public_manifest_bucket", "changed-public"),
    ("public_manifest_key", "changed/public.json"),
    ("vault_bucket", "changed-vault"),
    ("vault_source_key", "changed/source.bin"),
    ("vault_source_version_id", "changed-source-version"),
    ("vault_manifest_key", "changed/private.json"),
    ("vault_manifest_version_id", "changed-manifest-version"),
    ("retention_until", datetime(2027, 1, 1, tzinfo=UTC)),
    ("created_at", datetime(2026, 1, 1, tzinfo=UTC)),
)


@pytest.mark.parametrize(("field", "changed_value"), SECURITY_FIELD_MUTATIONS)
def test_each_security_field_mutation_invalidates_signature(
    field: str,
    changed_value: object,
) -> None:
    signer = Ed25519Signer.generate()
    envelope = SealEnvelopeV1.model_validate(envelope_values(signer))
    signed = sign_envelope(envelope, signer)
    modified = SealEnvelopeV1.model_validate({**envelope.model_dump(), field: changed_value})
    modified_signed = signed.model_copy(update={"envelope": modified})

    assert modified.canonical_bytes() != envelope.canonical_bytes()
    assert not verify_signed_envelope(modified_signed, signer.export_public_key_base64())


def test_fingerprint_mismatch_fails() -> None:
    signer = Ed25519Signer.generate()
    other = Ed25519Signer.generate()
    envelope = SealEnvelopeV1.model_validate(envelope_values(signer))
    signed = sign_envelope(envelope, signer)
    changed = signed.model_copy(update={"public_key_fingerprint": other.fingerprint})

    assert not verify_signed_envelope(changed, signer.export_public_key_base64())


def test_signer_key_id_mismatch_fails_closed() -> None:
    signer = Ed25519Signer.generate()
    other = Ed25519Signer.generate()
    values = envelope_values(signer)
    values["signer_key_id"] = other.signer_key_id
    envelope = SealEnvelopeV1.model_validate(values)
    original = SealEnvelopeV1.model_validate(envelope_values(signer))

    assert envelope.canonical_bytes() != original.canonical_bytes()
    with pytest.raises(KeyMaterialError, match="does not match"):
        sign_envelope(envelope, signer)

    manually_signed = SignedSealEnvelopeV1(
        envelope=envelope,
        signature=signer.sign(envelope.canonical_bytes()),
        public_key_fingerprint=signer.fingerprint,
    )
    assert not verify_signed_envelope(manually_signed, signer.export_public_key_base64())


@pytest.mark.parametrize(
    "signature",
    [
        "not-base64",
        "",
        "c2hvcnQ=",
    ],
)
def test_invalid_signature_encoding_or_length_is_rejected(signature: str) -> None:
    signer = Ed25519Signer.generate()
    envelope = SealEnvelopeV1.model_validate(envelope_values(signer))

    with pytest.raises(ValidationError):
        SignedSealEnvelopeV1(
            envelope=envelope,
            signature=signature,
            public_key_fingerprint=signer.fingerprint,
        )


def test_invalid_public_key_and_revalidated_tampering_fail_closed() -> None:
    signer = Ed25519Signer.generate()
    envelope = SealEnvelopeV1.model_validate(envelope_values(signer))
    signed = sign_envelope(envelope, signer)

    assert not verify_signed_envelope(signed, "invalid-public-key")
    assert not verify_signed_envelope(signed, object())  # type: ignore[arg-type]

    invalid_envelope = envelope.model_copy(update={"sealed_sha256": envelope.source_sha256})
    invalid_signed = signed.model_copy(update={"envelope": invalid_envelope})
    assert not verify_signed_envelope(invalid_signed, signer.export_public_key_base64())


def test_signed_envelope_is_immutable_and_rejects_unknown_fields() -> None:
    signer = Ed25519Signer.generate()
    envelope = SealEnvelopeV1.model_validate(envelope_values(signer))
    signed = sign_envelope(envelope, signer)

    with pytest.raises(ValidationError, match="frozen"):
        signed.algorithm = "Ed25519"

    values = signed.model_dump()
    values["unknown"] = "rejected"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SignedSealEnvelopeV1.model_validate(values)


def test_signed_envelope_algorithm_and_fingerprint_are_validated() -> None:
    signer = Ed25519Signer.generate()
    envelope = SealEnvelopeV1.model_validate(envelope_values(signer))
    signed = sign_envelope(envelope, signer)

    values = signed.model_dump()
    values["algorithm"] = "RSA"
    with pytest.raises(ValidationError):
        SignedSealEnvelopeV1.model_validate(values)

    values = signed.model_dump()
    values["public_key_fingerprint"] = "SHA256:invalid"
    with pytest.raises(ValidationError, match="Invalid FIREMARK"):
        SignedSealEnvelopeV1.model_validate(values)


def test_canonical_json_contains_every_envelope_field() -> None:
    signer = Ed25519Signer.generate()
    envelope = SealEnvelopeV1.model_validate(envelope_values(signer))

    decoded = json.loads(envelope.canonical_bytes())

    assert set(decoded) == set(SealEnvelopeV1.model_fields)
