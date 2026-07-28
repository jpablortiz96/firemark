"""Local contract tests for Genblaze PNG provenance integration."""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NoReturn

import pytest
from genblaze_core import EmbeddingError, EmbedPolicy, Manifest, PromptVisibility
from genblaze_core.media import PngHandler, SmartEmbedder

import api.firemark.genblaze_provenance as provenance
from api.firemark.genblaze_provenance import (
    GenblazeProvenanceError,
    embed_manifest_copy,
    extract_complete_manifest,
    parse_complete_manifest_payload,
    read_json_payload,
    render_policy_payload,
)
from api.firemark.hashing import sha256_file
from api.firemark.seal_envelope import (
    SealEnvelopeV1,
    SignedSealEnvelopeV1,
    sign_envelope,
    verify_signed_envelope,
)
from api.firemark.signer import Ed25519Signer
from scripts.smoke_genblaze_roundtrip import (
    EXPECTED_OUTPUT_NAMES,
    FIXED_SEED,
    PRIVATE_PARAMETER_VALUE,
    SENSITIVE_PROMPT,
    build_local_fixture_manifest,
    create_deterministic_png,
)
from scripts.smoke_genblaze_roundtrip import (
    main as smoke_main,
)


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail if this local contract test attempts to open a network connection."""

    def fail_network(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("Network access is forbidden in local Genblaze contract tests")

    monkeypatch.setattr(socket, "create_connection", fail_network)


def fixture_manifest(tmp_path: Path) -> tuple[Path, str, Manifest]:
    """Create a deterministic local PNG and its real Genblaze Manifest."""
    source = tmp_path / "local-deterministic-source.png"
    create_deterministic_png(source)
    source_sha256 = sha256_file(source)
    return source, source_sha256, build_local_fixture_manifest(source, source_sha256)


def test_deterministic_png_fixture_is_byte_identical(tmp_path: Path) -> None:
    first = tmp_path / "first.png"
    second = tmp_path / "second.png"

    create_deterministic_png(first)
    create_deterministic_png(second)

    assert first.read_bytes() == second.read_bytes()


def test_builders_create_successful_verified_manifest(tmp_path: Path) -> None:
    source, source_sha256, manifest = fixture_manifest(tmp_path)
    step = manifest.run.steps[0]
    asset = step.assets[0]

    assert source.is_file()
    assert manifest.verify()
    assert manifest.run.run_id == "firemark-local-fixture-run-v1"
    assert step.provider == "firemark-local-fixture"
    assert step.model == "deterministic-png-v1"
    assert step.modality.value == "image"
    assert step.status.value == "succeeded"
    assert asset.media_type == "image/png"
    assert asset.sha256 == source_sha256


def test_missing_source_is_rejected(tmp_path: Path) -> None:
    _, _, manifest = fixture_manifest(tmp_path)

    with pytest.raises(FileNotFoundError, match="does not exist"):
        embed_manifest_copy(tmp_path / "missing.png", tmp_path / "sealed.png", manifest)


def test_directory_source_is_rejected(tmp_path: Path) -> None:
    _, _, manifest = fixture_manifest(tmp_path)

    with pytest.raises(IsADirectoryError, match="must be a file"):
        embed_manifest_copy(tmp_path, tmp_path / "sealed.png", manifest)


def test_same_source_and_destination_are_rejected(tmp_path: Path) -> None:
    source, _, manifest = fixture_manifest(tmp_path)

    with pytest.raises(GenblazeProvenanceError, match="must be different"):
        embed_manifest_copy(source, source, manifest)


def test_existing_destination_requires_explicit_overwrite(tmp_path: Path) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    destination = tmp_path / "sealed.png"
    destination.write_bytes(b"existing local fixture bytes")

    with pytest.raises(FileExistsError, match="already exists"):
        embed_manifest_copy(source, destination, manifest)

    result = embed_manifest_copy(source, destination, manifest, overwrite=True)

    assert result.sealed_path == destination.resolve()
    assert extract_complete_manifest(destination).verify()


def test_directory_destination_is_rejected(tmp_path: Path) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    destination = tmp_path / "destination"
    destination.mkdir()

    with pytest.raises(IsADirectoryError, match="must be a file"):
        embed_manifest_copy(source, destination, manifest)


def test_inline_embed_preserves_source_and_reports_dual_hashes(tmp_path: Path) -> None:
    source, source_sha256, manifest = fixture_manifest(tmp_path)
    source_bytes = source.read_bytes()
    destination = tmp_path / "sealed.png"

    result = embed_manifest_copy(source, destination, manifest)

    assert source.read_bytes() == source_bytes
    assert result.source_sha256 == source_sha256
    assert result.sealed_sha256 == sha256_file(destination)
    assert result.source_sha256 != result.sealed_sha256
    assert result.embed_method == "inline"
    assert result.sidecar_path is None
    assert result.mime_type == "image/png"
    assert result.canonical_hash == manifest.canonical_hash


def test_source_hash_is_calculated_before_embedding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    destination = tmp_path / "sealed.png"
    original_hash = provenance.sha256_file
    original_embed = SmartEmbedder.embed
    hashed_paths: list[Path] = []

    def tracking_hash(path: Path) -> str:
        hashed_paths.append(Path(path).resolve())
        return original_hash(path)

    def checking_embed(
        self: SmartEmbedder,
        source_arg: object,
        manifest_arg: Manifest,
        output_arg: object = None,
        **kwargs: object,
    ) -> object:
        assert hashed_paths == [source.resolve()]
        return original_embed(self, source_arg, manifest_arg, output_arg, **kwargs)

    monkeypatch.setattr(provenance, "sha256_file", tracking_hash)
    monkeypatch.setattr(SmartEmbedder, "embed", checking_embed)

    embed_manifest_copy(source, destination, manifest)

    assert hashed_paths[0] == source.resolve()
    assert hashed_paths[-1] != source.resolve()


def test_failed_embedding_cleans_temporary_output_and_redacts_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    destination = tmp_path / "sealed.png"

    def failing_embed(
        self: SmartEmbedder,
        source_arg: object,
        manifest_arg: Manifest,
        output_arg: object = None,
        **kwargs: object,
    ) -> NoReturn:
        Path(str(output_arg)).write_bytes(b"partial local fixture")
        raise EmbeddingError(SENSITIVE_PROMPT)

    monkeypatch.setattr(SmartEmbedder, "embed", failing_embed)

    with pytest.raises(GenblazeProvenanceError) as captured:
        embed_manifest_copy(source, destination, manifest)

    assert SENSITIVE_PROMPT not in str(captured.value)
    assert isinstance(captured.value.__cause__, EmbeddingError)
    assert not destination.exists()
    assert not list(tmp_path.glob(".sealed.png.*"))


def test_failed_overwrite_preserves_existing_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    destination = tmp_path / "sealed.png"
    original_destination = b"existing destination must survive"
    destination.write_bytes(original_destination)

    def failing_embed(
        self: SmartEmbedder,
        source_arg: object,
        manifest_arg: Manifest,
        output_arg: object = None,
        **kwargs: object,
    ) -> NoReturn:
        Path(str(output_arg)).write_bytes(b"partial replacement")
        raise EmbeddingError("simulated local fixture failure")

    monkeypatch.setattr(SmartEmbedder, "embed", failing_embed)

    with pytest.raises(GenblazeProvenanceError):
        embed_manifest_copy(source, destination, manifest, overwrite=True)

    assert destination.read_bytes() == original_destination


def test_sidecar_fallback_fails_closed_and_is_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    destination = tmp_path / "sealed.png"

    def fallback_embed(
        self: SmartEmbedder,
        source_arg: object,
        manifest_arg: Manifest,
        output_arg: object = None,
        **kwargs: object,
    ) -> object:
        output = Path(str(output_arg))
        sidecar = output.with_suffix(output.suffix + ".genblaze.json")
        sidecar.write_text("{}", encoding="utf-8")
        from genblaze_core.media import EmbedResult

        return EmbedResult(
            path=output,
            sidecar_path=sidecar,
            manifest_uri=None,
            method="sidecar",
        )

    monkeypatch.setattr(SmartEmbedder, "embed", fallback_embed)

    with pytest.raises(GenblazeProvenanceError, match="required inline"):
        embed_manifest_copy(source, destination, manifest)

    assert not destination.exists()
    assert not list(tmp_path.glob("*.genblaze.json"))


def test_invalid_or_unsupported_media_fails_closed(tmp_path: Path) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    unsupported = tmp_path / "unsupported.txt"
    unsupported.write_text("local fixture", encoding="utf-8")

    with pytest.raises(GenblazeProvenanceError, match="Unsupported media type"):
        embed_manifest_copy(unsupported, tmp_path / "sealed.txt", manifest)

    invalid_png = tmp_path / "invalid.png"
    invalid_png.write_bytes(b"not a PNG")
    with pytest.raises(GenblazeProvenanceError, match="required inline"):
        embed_manifest_copy(invalid_png, tmp_path / "invalid-sealed.png", manifest)

    assert source.is_file()


def test_unverified_manifest_is_rejected(tmp_path: Path) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    invalid = manifest.model_copy(deep=True)
    invalid.canonical_hash = "0" * 64

    with pytest.raises(GenblazeProvenanceError, match="unverified"):
        embed_manifest_copy(source, tmp_path / "sealed.png", invalid)


def test_full_png_roundtrip_preserves_manifest_contract(tmp_path: Path) -> None:
    source, source_sha256, manifest = fixture_manifest(tmp_path)
    destination = tmp_path / "full-embedded.png"
    result = embed_manifest_copy(source, destination, manifest)

    extracted = extract_complete_manifest(destination)
    reparsed = parse_complete_manifest_payload(extracted.to_canonical_json())
    step = reparsed.run.steps[0]

    assert extracted.verify()
    assert reparsed.verify()
    assert reparsed.canonical_hash == manifest.canonical_hash == result.canonical_hash
    assert reparsed.run.run_id == manifest.run.run_id
    assert step.provider == "firemark-local-fixture"
    assert step.model == "deterministic-png-v1"
    assert step.assets[0].media_type == "image/png"
    assert step.assets[0].sha256 == source_sha256


def test_pointer_policy_redacts_private_fields_and_preserves_hash(tmp_path: Path) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    pointer_manifest = manifest.model_copy(deep=True)
    pointer_manifest.manifest_uri = (tmp_path / "local-fixture-manifest.json").as_uri()
    policy = EmbedPolicy(
        prompt_visibility=PromptVisibility.PRIVATE,
        embed_mode="pointer",
        include_params=False,
        include_seed=False,
    )

    payload_bytes = render_policy_payload(pointer_manifest, policy)
    payload = json.loads(payload_bytes)

    assert set(payload) == {"schema_version", "canonical_hash", "manifest_uri"}
    assert payload["canonical_hash"] == manifest.canonical_hash
    assert SENSITIVE_PROMPT.encode() not in payload_bytes
    assert PRIVATE_PARAMETER_VALUE.encode() not in payload_bytes
    assert str(FIXED_SEED).encode() not in payload_bytes


def test_full_mode_redaction_is_rejected_by_installed_public_api(tmp_path: Path) -> None:
    _, _, manifest = fixture_manifest(tmp_path)
    policy = EmbedPolicy(
        prompt_visibility=PromptVisibility.PRIVATE,
        embed_mode="full",
        include_params=False,
        include_seed=False,
    )

    with pytest.raises(GenblazeProvenanceError, match="rejected"):
        render_policy_payload(manifest, policy)


def test_pointer_mode_actual_behavior_is_sidecar_and_not_complete_manifest(tmp_path: Path) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    pointer_manifest = manifest.model_copy(deep=True)
    pointer_manifest.manifest_uri = (tmp_path / "local-fixture-manifest.json").as_uri()
    public_png = tmp_path / "public-redacted.png"
    public_png.write_bytes(source.read_bytes())
    policy = EmbedPolicy(
        prompt_visibility=PromptVisibility.PRIVATE,
        embed_mode="pointer",
        include_params=False,
        include_seed=False,
    )

    result = SmartEmbedder().embed(source, pointer_manifest, public_png, policy=policy)
    assert result.method == "pointer"
    assert result.sidecar_path is not None
    payload = read_json_payload(result.sidecar_path)

    assert public_png.read_bytes() == source.read_bytes()
    assert "run" not in payload
    assert payload["canonical_hash"] == manifest.canonical_hash
    with pytest.raises(GenblazeProvenanceError, match="extraction failed"):
        extract_complete_manifest(public_png)
    with pytest.raises(GenblazeProvenanceError, match="not a complete"):
        parse_complete_manifest_payload(result.sidecar_path.read_bytes())


def test_json_payload_validation_fails_closed(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(FileNotFoundError):
        read_json_payload(missing)

    invalid = tmp_path / "invalid.json"
    invalid.write_text("not json", encoding="utf-8")
    with pytest.raises(GenblazeProvenanceError, match="not valid JSON"):
        read_json_payload(invalid)
    with pytest.raises(GenblazeProvenanceError, match="size limit"):
        read_json_payload(invalid, max_bytes=1)
    with pytest.raises(ValueError, match="positive integer"):
        read_json_payload(invalid, max_bytes=0)

    non_object = tmp_path / "array.json"
    non_object.write_text("[]", encoding="utf-8")
    with pytest.raises(GenblazeProvenanceError, match="JSON object"):
        read_json_payload(non_object)

    invalid_utf8 = tmp_path / "invalid-utf8.json"
    invalid_utf8.write_bytes(b"\xff\xfe")
    with pytest.raises(GenblazeProvenanceError, match="UTF-8"):
        read_json_payload(invalid_utf8)


def test_complete_manifest_parser_rejects_invalid_payloads(tmp_path: Path) -> None:
    _, _, manifest = fixture_manifest(tmp_path)

    with pytest.raises(GenblazeProvenanceError, match="UTF-8"):
        parse_complete_manifest_payload(b"\xff")
    with pytest.raises(GenblazeProvenanceError, match="parsing failed"):
        parse_complete_manifest_payload('{"run": "invalid-local-fixture"}')
    with pytest.raises(GenblazeProvenanceError, match="did not verify"):
        parse_complete_manifest_payload('{"run": {}}')

    invalid_manifest = manifest.model_copy(deep=True)
    invalid_manifest.canonical_hash = "0" * 64
    with pytest.raises(GenblazeProvenanceError, match="did not verify"):
        parse_complete_manifest_payload(invalid_manifest.to_canonical_json())


def test_policy_renderer_rejects_unverified_manifest(tmp_path: Path) -> None:
    _, _, manifest = fixture_manifest(tmp_path)
    invalid_manifest = manifest.model_copy(deep=True)
    invalid_manifest.canonical_hash = "0" * 64

    with pytest.raises(GenblazeProvenanceError, match="unverified"):
        render_policy_payload(invalid_manifest, EmbedPolicy())


def test_complete_extraction_rejects_unsupported_media(tmp_path: Path) -> None:
    unsupported = tmp_path / "unsupported.txt"
    unsupported.write_text("local fixture", encoding="utf-8")

    with pytest.raises(GenblazeProvenanceError, match="Unsupported media type"):
        extract_complete_manifest(unsupported)


def _local_envelope(
    manifest: Manifest,
    source_sha256: str,
    sealed_sha256: str,
    signer: Ed25519Signer,
) -> SealEnvelopeV1:
    created_at = datetime(2026, 3, 1, tzinfo=UTC)
    return SealEnvelopeV1(
        cert_id="local-fixture-certificate",
        run_id=manifest.run.run_id,
        canonical_hash=manifest.canonical_hash,
        source_sha256=source_sha256,
        sealed_sha256=sealed_sha256,
        sealed_asset_bucket="local-fixture-not-stored",
        sealed_asset_key="local-fixture/full.png",
        public_manifest_bucket="local-fixture-not-stored",
        public_manifest_key="local-fixture/pointer.json",
        vault_bucket="local-fixture-not-stored",
        vault_source_key="local-fixture/source-not-stored",
        vault_source_version_id="local-fixture-no-version",
        vault_manifest_key="local-fixture/manifest-not-stored",
        vault_manifest_version_id="local-fixture-no-version",
        retention_until=created_at + timedelta(days=1),
        signer_key_id=signer.signer_key_id,
        created_at=created_at,
    )


@pytest.mark.parametrize("field", ["canonical_hash", "source_sha256", "sealed_sha256"])
def test_firemark_envelope_binds_genblaze_and_dual_hashes(tmp_path: Path, field: str) -> None:
    source, source_sha256, manifest = fixture_manifest(tmp_path)
    sealed = tmp_path / "sealed.png"
    result = embed_manifest_copy(source, sealed, manifest)
    signer = Ed25519Signer.generate()
    envelope = _local_envelope(manifest, source_sha256, result.sealed_sha256, signer)
    signed = sign_envelope(envelope, signer)

    assert envelope.canonical_hash == manifest.canonical_hash
    assert envelope.source_sha256 != envelope.sealed_sha256
    assert verify_signed_envelope(signed, signer.export_public_key_base64())

    values = envelope.model_dump()
    values[field] = "d" * 64
    altered = SealEnvelopeV1.model_validate(values)
    altered_signed = SignedSealEnvelopeV1(
        envelope=altered,
        signature=signed.signature,
        public_key_fingerprint=signed.public_key_fingerprint,
    )
    assert not verify_signed_envelope(altered_signed, signer.export_public_key_base64())
    assert not verify_signed_envelope(signed, Ed25519Signer.generate().export_public_key_base64())


def test_one_byte_sealed_mutation_changes_digest(tmp_path: Path) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    sealed = tmp_path / "sealed.png"
    result = embed_manifest_copy(source, sealed, manifest)
    mutated = tmp_path / "mutated.png"
    mutated.write_bytes(sealed.read_bytes())

    with mutated.open("r+b") as stream:
        stream.seek(-1, 2)
        original = stream.read(1)
        stream.seek(-1, 2)
        stream.write(bytes((original[0] ^ 1,)))

    assert sha256_file(mutated) != result.sealed_sha256


def test_smoke_default_reports_safe_success(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert smoke_main([]) == 0

    output = capsys.readouterr().out
    assert "PASS" in output
    assert "local deterministic fixture" in output.lower()
    assert "not production evidence" in output
    assert "Network calls: 0" in output
    assert SENSITIVE_PROMPT not in output
    assert PRIVATE_PARAMETER_VALUE not in output
    assert "PRIVATE KEY" not in output


def test_smoke_persists_expected_files_and_protects_overwrite(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_directory = tmp_path / "persisted-local-fixtures"
    arguments = ["--output-dir", str(output_directory)]

    assert smoke_main(arguments) == 0
    capsys.readouterr()
    assert all((output_directory / name).is_file() for name in EXPECTED_OUTPUT_NAMES)
    assert (output_directory / "public_redacted.png.genblaze.json").is_file()
    report = json.loads((output_directory / "report.json").read_text(encoding="utf-8"))
    assert report["local_fixture"] is True
    assert report["production_evidence"] is False
    assert report["network_calls"] == 0

    assert smoke_main(arguments) == 1
    refusal = capsys.readouterr().out
    assert "FAIL" in refusal
    assert SENSITIVE_PROMPT not in refusal


def test_smoke_force_replaces_only_target_contents(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_directory = tmp_path / "target"
    output_directory.mkdir()
    stale = output_directory / "stale-local-fixture.txt"
    stale.write_text("stale", encoding="utf-8")
    sibling = tmp_path / "outside-target.txt"
    sibling.write_text("preserve", encoding="utf-8")

    assert smoke_main(["--output-dir", str(output_directory), "--force"]) == 0
    output = capsys.readouterr().out

    assert not stale.exists()
    assert sibling.read_text(encoding="utf-8") == "preserve"
    assert all((output_directory / name).is_file() for name in EXPECTED_OUTPUT_NAMES)
    assert SENSITIVE_PROMPT not in output


def test_png_handler_public_full_extract_verifies(tmp_path: Path) -> None:
    source, _, manifest = fixture_manifest(tmp_path)
    embedded = tmp_path / "handler-full.png"

    PngHandler().embed(source, manifest, embedded)
    extracted = PngHandler().extract(embedded)

    assert extracted.verify()
    assert extracted.canonical_hash == manifest.canonical_hash
