"""Tests for FIREMARK Ed25519 key handling and signatures."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from api.firemark.signer import Ed25519KeyPair, Ed25519Signer, KeyMaterialError
from scripts.keygen import main as keygen_main


def test_generated_key_and_signature_lengths() -> None:
    signer = Ed25519Signer.generate()
    private_value = signer.export_private_key_base64_for_provisioning()
    public_value = signer.export_public_key_base64()
    signature = signer.sign(b"length-test")

    assert len(base64.b64decode(private_value, validate=True)) == 32
    assert len(base64.b64decode(public_value, validate=True)) == 32
    assert len(base64.b64decode(signature, validate=True)) == 64


def test_export_and_load_roundtrip() -> None:
    original = Ed25519Signer.generate()
    loaded = Ed25519Signer.from_private_key_base64(
        original.export_private_key_base64_for_provisioning(),
        original.export_public_key_base64(),
    )
    payload = b"roundtrip payload"

    assert loaded.export_public_key_base64() == original.export_public_key_base64()
    assert loaded.verify(payload, loaded.sign(payload))


def test_private_and_public_file_load_roundtrip(tmp_path: Path) -> None:
    original = Ed25519Signer.generate()
    private_file = tmp_path / "private.b64"
    public_file = tmp_path / "public.b64"
    private_file.write_text(
        original.export_private_key_base64_for_provisioning() + "\n",
        encoding="utf-8",
    )
    public_file.write_text(original.export_public_key_base64() + "\n", encoding="utf-8")

    private_signer = Ed25519Signer.from_key_files(
        private_key_path=private_file,
        public_key_path=public_file,
    )
    public_verifier = Ed25519Signer.from_key_files(public_key_path=public_file)
    signature = private_signer.sign(b"file roundtrip")

    assert public_verifier.verify(b"file roundtrip", signature)
    assert not public_verifier.can_sign


def test_valid_signature_and_wrong_payload() -> None:
    signer = Ed25519Signer.generate()
    signature = signer.sign(b"original")

    assert signer.verify(b"original", signature)
    assert not signer.verify(b"modified", signature)


def test_wrong_public_key_fails() -> None:
    signer = Ed25519Signer.generate()
    other = Ed25519Signer.generate()

    assert not other.verify(b"payload", signer.sign(b"payload"))


@pytest.mark.parametrize("value", ["not base64!", "", "éééé"])
def test_malformed_key_base64_is_rejected(value: str) -> None:
    with pytest.raises(KeyMaterialError):
        Ed25519Signer.from_private_key_base64(value)
    with pytest.raises(KeyMaterialError):
        Ed25519Signer.from_public_key_base64(value)


def test_wrong_private_key_length_is_rejected() -> None:
    value = base64.b64encode(b"short private key").decode("ascii")

    with pytest.raises(KeyMaterialError, match="exactly 32 bytes"):
        Ed25519Signer.from_private_key_base64(value)


def test_wrong_public_key_length_is_rejected() -> None:
    value = base64.b64encode(b"short public key").decode("ascii")

    with pytest.raises(KeyMaterialError, match="exactly 32 bytes"):
        Ed25519Signer.from_public_key_base64(value)


@pytest.mark.parametrize("signature", ["not base64!", "", base64.b64encode(b"short").decode()])
def test_malformed_signature_fails_closed(signature: str) -> None:
    assert not Ed25519Signer.generate().verify(b"payload", signature)


def test_mismatched_supplied_key_pair_is_rejected() -> None:
    first = Ed25519Signer.generate()
    second = Ed25519Signer.generate()

    with pytest.raises(KeyMaterialError, match="do not match"):
        Ed25519Signer.from_private_key_base64(
            first.export_private_key_base64_for_provisioning(),
            second.export_public_key_base64(),
        )


def test_fingerprint_and_signer_key_id_are_deterministic() -> None:
    signer = Ed25519Signer.generate()
    public_bytes = base64.b64decode(signer.export_public_key_base64(), validate=True)
    digest = hashlib.sha256(public_bytes).digest()
    expected_fingerprint = "SHA256:" + base64.urlsafe_b64encode(digest).decode().rstrip("=")
    expected_key_id = f"firemark-ed25519-{hashlib.sha256(public_bytes).hexdigest()[:16]}"
    reloaded = Ed25519Signer.from_public_key_base64(signer.export_public_key_base64())

    assert signer.fingerprint == expected_fingerprint == reloaded.fingerprint
    assert signer.signer_key_id == expected_key_id == reloaded.signer_key_id


def test_repr_does_not_expose_private_key_material() -> None:
    signer = Ed25519Signer.generate()
    private_value = signer.export_private_key_base64_for_provisioning()
    pair = Ed25519KeyPair.from_private_base64(private_value)

    assert private_value not in repr(signer)
    assert private_value not in repr(pair)


def test_public_only_signer_cannot_export_or_sign() -> None:
    signer = Ed25519Signer.generate()
    verifier = Ed25519Signer.from_public_key_base64(signer.export_public_key_base64())

    with pytest.raises(KeyMaterialError, match="not available"):
        verifier.export_private_key_base64_for_provisioning()
    with pytest.raises(KeyMaterialError, match="required for signing"):
        verifier.sign(b"payload")


def test_missing_and_invalid_key_files_are_configuration_errors(tmp_path: Path) -> None:
    missing = tmp_path / "missing.b64"

    with pytest.raises(KeyMaterialError, match="Unable to read"):
        Ed25519Signer.from_key_files(private_key_path=missing)
    with pytest.raises(KeyMaterialError, match="At least one"):
        Ed25519Signer.from_key_files()

    empty = tmp_path / "empty.b64"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(KeyMaterialError, match="is empty"):
        Ed25519Signer.from_key_files(public_key_path=empty)


def test_keygen_uses_safe_files_and_overwrite_controls(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_directory = tmp_path / "clearly-labeled-test-secrets"
    evidence_file = tmp_path / "clearly-labeled-test-evidence" / "pubkey.txt"
    arguments = [
        "--output-dir",
        str(output_directory),
        "--evidence-file",
        str(evidence_file),
    ]

    assert keygen_main(arguments) == 0
    first_output = capsys.readouterr().out
    private_file = output_directory / "firemark_ed25519_private.b64"
    public_file = output_directory / "firemark_ed25519_public.b64"
    first_private_value = private_file.read_text(encoding="utf-8")
    public_value = public_file.read_text(encoding="utf-8")
    public_evidence = evidence_file.read_text(encoding="utf-8")

    assert first_private_value not in first_output
    assert first_private_value not in public_evidence
    assert public_value in public_evidence
    assert "algorithm=Ed25519" in public_evidence

    assert keygen_main(arguments) == 2
    refusal_output = capsys.readouterr().out
    assert first_private_value not in refusal_output
    assert private_file.read_text(encoding="utf-8") == first_private_value

    assert keygen_main([*arguments, "--force"]) == 0
    forced_output = capsys.readouterr().out
    second_private_value = private_file.read_text(encoding="utf-8")
    assert second_private_value != first_private_value
    assert second_private_value not in forced_output
