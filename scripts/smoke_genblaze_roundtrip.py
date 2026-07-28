"""Prove the local Genblaze PNG provenance contract without network access."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import shutil
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from genblaze_core import (
    EmbedPolicy,
    Manifest,
    Modality,
    PromptVisibility,
    RunBuilder,
    RunStatus,
    StepBuilder,
    StepStatus,
)
from genblaze_core.media import SmartEmbedder
from PIL import Image, PngImagePlugin

from api.firemark.genblaze_provenance import (
    GenblazeProvenanceError,
    embed_manifest_copy,
    extract_complete_manifest,
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

SENSITIVE_PROMPT = "CONFIDENTIAL_FIREMARK_PROMPT_MUST_NOT_SHIP"
PRIVATE_PARAMETER_VALUE = "private-local-fixture-parameter-must-not-ship"
FIXED_SEED = 424242
LOCAL_RUN_ID = "firemark-local-fixture-run-v1"
EXPECTED_OUTPUT_NAMES = (
    "source.png",
    "full_embedded.png",
    "public_redacted.png",
    "full_manifest.json",
    "public_embedded_payload.json",
    "signed_envelope.json",
    "report.json",
)


class SmokeRoundtripError(RuntimeError):
    """Raised when the local Genblaze contract cannot be proven safely."""


def create_deterministic_png(path: Path) -> None:
    """Create a fixed local PNG fixture that is not provider-generated media."""
    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGB", (8, 6))
    pixels = [
        ((x * 31 + y * 17) % 256, (x * 13 + y * 47) % 256, (x * 59 + y * 7) % 256)
        for y in range(6)
        for x in range(8)
    ]
    image.putdata(pixels)
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text(
        "fixture_notice",
        "FIREMARK local deterministic fixture; not AI-generated; not production evidence",
    )
    image.save(path, format="PNG", pnginfo=metadata, compress_level=9, optimize=False)


def build_local_fixture_manifest(source_path: Path, source_sha256: str) -> Manifest:
    """Build a clearly labeled local fixture Manifest through public builders."""
    step = (
        StepBuilder("firemark-local-fixture", "deterministic-png-v1")
        .prompt(SENSITIVE_PROMPT)
        .modality(Modality.IMAGE)
        .status(StepStatus.SUCCEEDED)
        .seed(FIXED_SEED)
        .params(
            private_fixture_parameter=PRIVATE_PARAMETER_VALUE,
            fixture_guidance=7.25,
        )
        .asset(
            source_path.resolve().as_uri(),
            "image/png",
            sha256=source_sha256,
            size_bytes=source_path.stat().st_size,
            width=8,
            height=6,
        )
        .meta(local_fixture=True, production_evidence=False)
        .build()
    )
    run = (
        RunBuilder("FIREMARK local deterministic PNG fixture")
        .run_id(LOCAL_RUN_ID)
        .status(RunStatus.COMPLETED)
        .add_step(step)
        .meta(
            local_fixture=True,
            ai_generated=False,
            provider_generated=False,
            production_evidence=False,
            network_calls=0,
        )
        .build()
    )
    return Manifest.from_run(run)


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def _atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=destination.suffix,
            dir=destination.parent,
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)
        with source.open("rb") as input_file, temporary_path.open("wb") as output_file:
            shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
            output_file.flush()
            os.fsync(output_file.fileno())
        os.replace(temporary_path, destination)
    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def _prepare_output_directory(path: Path, *, force: bool) -> None:
    if path.exists() and not path.is_dir():
        raise SmokeRoundtripError(f"Output path is not a directory: {path}")
    if path.exists() and any(path.iterdir()):
        if not force:
            raise SmokeRoundtripError(
                "Output directory is populated; use --force to replace local fixture artifacts"
            )
        for child in path.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    path.mkdir(parents=True, exist_ok=True)


def _signed_envelope_json(signed_envelope: SignedSealEnvelopeV1) -> bytes:
    value = {
        "local_fixture": True,
        "production_evidence": False,
        "signed_seal_envelope": signed_envelope.model_dump(mode="json"),
    }
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


def _report_json(report: dict[str, Any]) -> bytes:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


def run_roundtrip(output_directory: Path) -> tuple[list[tuple[str, bool]], dict[str, Any]]:
    """Create and validate all local fixture artifacts in one directory."""
    source_path = output_directory / "source.png"
    full_path = output_directory / "full_embedded.png"
    public_path = output_directory / "public_redacted.png"
    full_manifest_path = output_directory / "full_manifest.json"
    public_payload_path = output_directory / "public_embedded_payload.json"
    signed_envelope_path = output_directory / "signed_envelope.json"
    report_path = output_directory / "report.json"

    create_deterministic_png(source_path)
    source_sha256 = sha256_file(source_path)
    manifest = build_local_fixture_manifest(source_path, source_sha256)
    declared_asset = manifest.run.steps[0].assets[0]
    source_before = sha256_file(source_path)

    _atomic_write_bytes(full_manifest_path, manifest.to_canonical_json().encode("utf-8"))
    full_result = embed_manifest_copy(source_path, full_path, manifest)
    extracted = extract_complete_manifest(full_path)

    pointer_manifest = manifest.model_copy(deep=True)
    pointer_manifest.manifest_uri = full_manifest_path.resolve().as_uri()
    policy = EmbedPolicy(
        prompt_visibility=PromptVisibility.PRIVATE,
        embed_mode="pointer",
        include_params=False,
        include_seed=False,
    )
    expected_public_payload = render_policy_payload(pointer_manifest, policy)
    _atomic_copy(source_path, public_path)
    public_embed_result = SmartEmbedder().embed(
        source_path,
        pointer_manifest,
        public_path,
        policy=policy,
        mime_type="image/png",
    )
    if public_embed_result.method != "pointer" or public_embed_result.sidecar_path is None:
        raise SmokeRoundtripError("Genblaze pointer policy did not produce its documented sidecar")
    sidecar_path = public_embed_result.sidecar_path
    public_payload = read_json_payload(sidecar_path)
    public_payload_bytes = sidecar_path.read_bytes()
    _atomic_write_bytes(public_payload_path, public_payload_bytes)

    prompt_redacted = (
        SENSITIVE_PROMPT.encode("utf-8") not in expected_public_payload
        and SENSITIVE_PROMPT.encode("utf-8") not in public_payload_bytes
        and "prompt" not in public_payload
    )
    params_removed = (
        PRIVATE_PARAMETER_VALUE.encode("utf-8") not in expected_public_payload
        and PRIVATE_PARAMETER_VALUE.encode("utf-8") not in public_payload_bytes
        and "params" not in public_payload
    )
    seed_removed = str(FIXED_SEED).encode("ascii") not in public_payload_bytes and "seed" not in public_payload

    signer = Ed25519Signer.generate()
    created_at = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    envelope = SealEnvelopeV1(
        cert_id="local-fixture-certificate-not-production-evidence",
        run_id=manifest.run.run_id,
        canonical_hash=manifest.canonical_hash,
        source_sha256=full_result.source_sha256,
        sealed_sha256=full_result.sealed_sha256,
        sealed_asset_bucket="local-fixture-not-stored",
        sealed_asset_key="local-fixture/full_embedded.png",
        public_manifest_bucket="local-fixture-not-stored",
        public_manifest_key="local-fixture/public_embedded_payload.json",
        vault_bucket="local-fixture-not-stored",
        vault_source_key="local-fixture/source.png-not-stored",
        vault_source_version_id="local-fixture-no-version-id",
        vault_manifest_key="local-fixture/full_manifest.json-not-stored",
        vault_manifest_version_id="local-fixture-no-version-id",
        retention_until=created_at + timedelta(days=1),
        signer_key_id=signer.signer_key_id,
        created_at=created_at,
    )
    signed_envelope = sign_envelope(envelope, signer)
    signature_verified = verify_signed_envelope(
        signed_envelope,
        signer.export_public_key_base64(),
    )
    tampered_values = envelope.model_dump()
    tampered_values["sealed_asset_key"] = "local-fixture/tampered.png"
    tampered_envelope = SealEnvelopeV1.model_validate(tampered_values)
    tampered_signed = SignedSealEnvelopeV1(
        envelope=tampered_envelope,
        algorithm=signed_envelope.algorithm,
        signature=signed_envelope.signature,
        public_key_fingerprint=signed_envelope.public_key_fingerprint,
    )
    tampered_envelope_rejected = not verify_signed_envelope(
        tampered_signed,
        signer.export_public_key_base64(),
    )
    _atomic_write_bytes(signed_envelope_path, _signed_envelope_json(signed_envelope))

    with tempfile.TemporaryDirectory(prefix="tamper-check-", dir=output_directory) as raw:
        tampered_path = Path(raw) / "tampered.png"
        _atomic_copy(full_path, tampered_path)
        with tampered_path.open("r+b") as tampered_file:
            tampered_file.seek(-1, os.SEEK_END)
            original_byte = tampered_file.read(1)
            tampered_file.seek(-1, os.SEEK_END)
            tampered_file.write(bytes((original_byte[0] ^ 1,)))
        tampered_sealed_hash_rejected = sha256_file(tampered_path) != full_result.sealed_sha256

    source_unchanged = sha256_file(source_path) == source_before
    full_manifest_verified = manifest.verify()
    extracted_full_manifest_verified = extracted.verify()
    roundtrip_fields_preserved = (
        extracted.canonical_hash == manifest.canonical_hash
        and extracted.run.run_id == manifest.run.run_id
        and extracted.run.steps[0].provider == "firemark-local-fixture"
        and extracted.run.steps[0].model == "deterministic-png-v1"
        and extracted.run.steps[0].assets[0].media_type == "image/png"
        and extracted.run.steps[0].assets[0].sha256 == source_sha256
    )
    pointer_contract_preserved = (
        set(public_payload) == {"schema_version", "canonical_hash", "manifest_uri"}
        and public_payload.get("canonical_hash") == manifest.canonical_hash
    )

    checks = [
        ("local Manifest verifies", full_manifest_verified),
        ("declared asset hash matches source", declared_asset.sha256 == source_sha256),
        ("full PNG uses inline embedding", full_result.embed_method == "inline"),
        ("full extracted Manifest verifies", extracted_full_manifest_verified),
        ("full roundtrip fields survive", roundtrip_fields_preserved),
        ("source PNG remains unchanged", source_unchanged),
        ("source and full sealed hashes differ", source_sha256 != full_result.sealed_sha256),
        ("pointer policy uses documented sidecar", public_embed_result.method == "pointer"),
        ("pointer payload preserves canonical hash", pointer_contract_preserved),
        ("sensitive prompt is absent publicly", prompt_redacted),
        ("private parameters are absent publicly", params_removed),
        ("seed is absent publicly", seed_removed),
        ("FIREMARK signature verifies", signature_verified),
        ("tampered envelope is rejected", tampered_envelope_rejected),
        ("tampered sealed hash is rejected", tampered_sealed_hash_rejected),
    ]

    report: dict[str, Any] = {
        "genblaze_core_version": importlib.metadata.version("genblaze-core"),
        "genblaze_cli_version": importlib.metadata.version("genblaze-cli"),
        "source_sha256": source_sha256,
        "full_embedded_sha256": full_result.sealed_sha256,
        "public_sealed_sha256": sha256_file(public_path),
        "canonical_hash": manifest.canonical_hash,
        "full_manifest_verified": full_manifest_verified,
        "extracted_full_manifest_verified": extracted_full_manifest_verified,
        "prompt_redacted": prompt_redacted,
        "params_removed": params_removed,
        "seed_removed": seed_removed,
        "source_unchanged": source_unchanged,
        "firemark_signature_verified": signature_verified,
        "tampered_envelope_rejected": tampered_envelope_rejected,
        "tampered_sealed_hash_rejected": tampered_sealed_hash_rejected,
        "embed_methods": {
            "full_manifest": full_result.embed_method,
            "public_payload": public_embed_result.method,
        },
        "public_payload_location": sidecar_path.name,
        "public_png_contains_inline_payload": False,
        "custody": "local-fixture-not-stored",
        "local_fixture": True,
        "ai_generated": False,
        "provider_generated": False,
        "production_evidence": False,
        "network_calls": 0,
    }
    _atomic_write_bytes(report_path, _report_json(report))
    return checks, report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the zero-network FIREMARK Genblaze PNG contract smoke test.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Persist clearly labeled local fixture artifacts in this directory.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace contents of a populated local fixture output directory.",
    )
    return parser


def _print_result(checks: list[tuple[str, bool]], report: dict[str, Any]) -> None:
    print("FIREMARK Genblaze local PNG provenance roundtrip")
    print("Local deterministic fixture; not AI-generated or provider-generated.")
    print("This output is not production evidence. Network calls: 0.")
    print("Custody fields are local-fixture/not-stored placeholders; no B2 or Object Lock.")
    print(f"genblaze-core: {report['genblaze_core_version']}")
    print(f"genblaze-cli: {report['genblaze_cli_version']}")
    print(f"{'Check':48} Result")
    print(f"{'-' * 48} ------")
    for label, passed in checks:
        print(f"{label:48} {'PASS' if passed else 'FAIL'}")
    print(f"source_sha256: {report['source_sha256']}")
    print(f"full_embedded_sha256: {report['full_embedded_sha256']}")
    print(f"public_png_sha256: {report['public_sealed_sha256']}")
    print(f"canonical_hash: {report['canonical_hash']}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the smoke workflow and return a process-compatible exit code."""
    args = _build_parser().parse_args(argv)
    if args.force and args.output_dir is None:
        print("FAIL: --force requires --output-dir.")
        return 2

    try:
        if args.output_dir is None:
            with tempfile.TemporaryDirectory(prefix="firemark-genblaze-roundtrip-") as raw:
                output_directory = Path(raw)
                checks, report = run_roundtrip(output_directory)
        else:
            output_directory = args.output_dir.resolve()
            _prepare_output_directory(output_directory, force=args.force)
            checks, report = run_roundtrip(output_directory)
    except (GenblazeProvenanceError, SmokeRoundtripError, OSError, ValueError) as exc:
        print(f"FAIL: local roundtrip did not complete safely ({type(exc).__name__}).")
        return 1

    _print_result(checks, report)
    return 0 if all(passed for _, passed in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
