"""Explicit opt-in B2-only proof for Generate & Seal custody bytes."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from dotenv import load_dotenv
from genblaze_core import Manifest, Modality, RunBuilder, RunStatus, StepBuilder, StepStatus
from PIL import Image, PngImagePlugin

from api.firemark.b2_storage import (
    B2Error,
    B2FailureInfo,
    B2PersistedObjectError,
    classify_b2_failure,
    create_assets_client,
    create_vault_client,
    delete_unlocked_version_verified,
    sealed_asset_key,
    upload_bytes_verified,
    upload_locked_bytes,
    vault_manifest_key,
    vault_source_key,
)
from api.firemark.custody import LockedObjectReceipt, PartialB2Object, StoredObjectReceipt
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import FiremarkPublicCapsuleV1, embed_public_capsule_png
from api.firemark.settings import CompleteB2Config, load_settings

INFORMATIONAL_EXIT_CODE = 2
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = REPOSITORY_ROOT / ".env"
DEFAULT_REPORT = Path(".artifacts/generate-and-seal-b2-report.json")
STAGES = (
    "configuration_validation",
    "dependency_construction",
    "local_source_fixture",
    "source_hash",
    "private_manifest",
    "canonical_hash",
    "public_capsule_embedding",
    "sealed_hash",
    "vault_source_upload",
    "vault_source_hash_verification",
    "vault_source_retention_verification",
    "vault_manifest_upload",
    "vault_manifest_hash_verification",
    "vault_manifest_retention_verification",
    "sealed_asset_upload",
    "sealed_asset_hash_verification",
    "custody_receipt_construction",
    "exact_assets_cleanup",
    "safe_report",
)


class LocalCheckpointError(RuntimeError):
    """A safe local failure represented only by a normalized category."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


class StageTracker:
    """Record the active stage before each checkpoint operation."""

    def __init__(self) -> None:
        self.current = STAGES[0]
        self.rows: list[dict[str, str]] = []

    def begin(self, stage: str) -> None:
        if stage == self.current:
            return
        if STAGES.index(stage) < STAGES.index(self.current):
            raise LocalCheckpointError("LOCAL_ADAPTER_ERROR")
        self.rows.append({"stage": self.current, "status": "PASS"})
        self.current = stage

    def finish(self, status: str) -> tuple[dict[str, str], ...]:
        self.rows.append({"stage": self.current, "status": status})
        return tuple(self.rows)


@dataclass(frozen=True)
class B2Proof:
    run_id: str
    asset_id: str
    cert_id: str
    source_sha256: str
    canonical_hash: str
    sealed_sha256: str
    source: LockedObjectReceipt
    manifest: LockedObjectReceipt
    sealed: StoredObjectReceipt
    sealed_cleanup_verified: bool
    source_bytes: int
    manifest_bytes: int
    sealed_bytes: int


@dataclass(frozen=True)
class CheckpointOutcome:
    category: str
    exit_code: int
    stages: tuple[dict[str, str], ...]
    proof: B2Proof | None = None
    failure: B2FailureInfo | None = None
    bucket_role: str | None = None
    object_kind: str | None = None
    partial_objects: tuple[PartialB2Object, ...] = ()


def _create_fixture(path: Path) -> bytes:
    image = Image.new("RGB", (8, 6))
    image.putdata(
        [
            ((x * 31 + y * 17) % 256, (x * 13 + y * 47) % 256, (x * 59 + y * 7) % 256)
            for y in range(6)
            for x in range(8)
        ]
    )
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("fixture_notice", "FIREMARK local fixture; not AI-generated")
    image.save(path, format="PNG", pnginfo=metadata, compress_level=9, optimize=False)
    return path.read_bytes()


def _private_manifest(source: bytes, source_sha256: str, run_id: str) -> Manifest:
    step = (
        StepBuilder("firemark-local-fixture", "deterministic-png-v1")
        .prompt("private local fixture provenance")
        .modality(Modality.IMAGE)
        .status(StepStatus.SUCCEEDED)
        .seed(424242)
        .params(local_fixture=True)
        .asset(
            f"urn:sha256:{source_sha256}",
            "image/png",
            sha256=source_sha256,
            size_bytes=len(source),
            width=8,
            height=6,
        )
        .meta(local_fixture=True, ai_generated=False, production_evidence=False)
        .build()
    )
    run = (
        RunBuilder("FIREMARK Generate & Seal B2 local fixture")
        .run_id(run_id)
        .status(RunStatus.COMPLETED)
        .add_step(step)
        .meta(local_fixture=True, ai_generated=False, provider_generated=False)
        .build()
    )
    manifest = Manifest.from_run(run)
    if not manifest.verify():
        raise LocalCheckpointError("INVALID_OBJECT_BODY")
    return manifest


def _identifiers() -> tuple[str, str, str]:
    suffix = uuid4().hex
    return (
        f"firemark-run-b2-{suffix}",
        f"firemark-asset-b2-{suffix}",
        f"firemark-cert-b2-{suffix}",
    )


def _failure_context(stage: str) -> tuple[str | None, str | None]:
    role = "vault" if stage.startswith("vault_") else "assets" if stage.startswith("sealed_") else None
    if "source" in stage:
        return role, "source"
    if "manifest" in stage:
        return role, "manifest"
    if "sealed" in stage:
        return role, "sealed"
    return role, None


def execute_checkpoint(
    config: CompleteB2Config,
    *,
    assets_factory: Callable[[Any], Any] = create_assets_client,
    vault_factory: Callable[[Any], Any] = create_vault_client,
    now: Callable[[], datetime] | None = None,
    identifiers: Callable[[], tuple[str, str, str]] = _identifiers,
) -> CheckpointOutcome:
    """Execute one B2-only proof using local deterministic provenance."""
    tracker = StageTracker()
    sealed: StoredObjectReceipt | None = None
    assets_client: Any = None
    try:
        tracker.begin("dependency_construction")
        assets_client = assets_factory(config.assets)
        vault_client = vault_factory(config.vault)
        run_id, asset_id, cert_id = identifiers()
        timestamp = (now or (lambda: datetime.now(UTC)))().astimezone(UTC)
        retention_until = timestamp + timedelta(days=config.vault.retention_days)
        with tempfile.TemporaryDirectory(prefix="firemark-generate-seal-b2-") as directory:
            tracker.begin("local_source_fixture")
            source = _create_fixture(Path(directory) / "source.png")
            tracker.begin("source_hash")
            source_sha256 = sha256_bytes(source)
            tracker.begin("private_manifest")
            manifest = _private_manifest(source, source_sha256, run_id)
            manifest_body = manifest.to_canonical_json().encode("utf-8")
            tracker.begin("canonical_hash")
            canonical_hash = manifest.canonical_hash
            tracker.begin("public_capsule_embedding")
            capsule = FiremarkPublicCapsuleV1.model_validate(
                {
                    "cert_id": cert_id,
                    "asset_id": asset_id,
                    "run_id": run_id,
                    "canonical_hash": canonical_hash,
                    "source_sha256": source_sha256,
                    "signer_key_id": "firemark-local-fixture-signer",
                    "verify_url": f"https://firemark.invalid/v1/certificates/{cert_id}",
                    "issued_at": timestamp,
                }
            )
            sealed_body = embed_public_capsule_png(source, capsule)
            tracker.begin("sealed_hash")
            sealed_sha256 = sha256_bytes(sealed_body)
            source_receipt = upload_locked_bytes(
                vault_client,
                bucket=config.vault.bucket,
                key=vault_source_key(source_sha256, "png"),
                data=source,
                expected_sha256=source_sha256,
                content_type="image/png",
                retention_until=retention_until,
                metadata={"firemark-kind": "source", "firemark-schema": "1"},
                stage_callback=tracker.begin,
                upload_stage="vault_source_upload",
                hash_verification_stage="vault_source_hash_verification",
                retention_verification_stage="vault_source_retention_verification",
            )
            manifest_sha256 = sha256_bytes(manifest_body)
            manifest_receipt = upload_locked_bytes(
                vault_client,
                bucket=config.vault.bucket,
                key=vault_manifest_key(run_id, canonical_hash),
                data=manifest_body,
                expected_sha256=manifest_sha256,
                content_type="application/json",
                retention_until=retention_until,
                metadata={"firemark-kind": "manifest", "firemark-schema": "1"},
                stage_callback=tracker.begin,
                upload_stage="vault_manifest_upload",
                hash_verification_stage="vault_manifest_hash_verification",
                retention_verification_stage="vault_manifest_retention_verification",
            )
            sealed = upload_bytes_verified(
                assets_client,
                bucket=config.assets.bucket,
                key=sealed_asset_key(sealed_sha256),
                data=sealed_body,
                expected_sha256=sealed_sha256,
                content_type="image/png",
                metadata={
                    "firemark-kind": "sealed",
                    "firemark-schema": "1",
                    "firemark-cert-id": cert_id,
                },
                known_unlocked=True,
                stage_callback=tracker.begin,
                upload_stage="sealed_asset_upload",
                hash_verification_stage="sealed_asset_hash_verification",
            )
            tracker.begin("custody_receipt_construction")
            if sealed.version_id is None:
                raise LocalCheckpointError("VERSION_ID_MISSING")
            if source_receipt.bucket != config.vault.bucket or manifest_receipt.bucket != config.vault.bucket:
                raise LocalCheckpointError("LOCAL_ADAPTER_ERROR")
            if sealed.bucket != config.assets.bucket or sealed.sha256 != sealed_sha256:
                raise LocalCheckpointError("HASH_MISMATCH")
            tracker.begin("exact_assets_cleanup")
            cleanup = delete_unlocked_version_verified(
                assets_client,
                bucket=sealed.bucket,
                key=sealed.key,
                version_id=sealed.version_id,
                expected_sha256=sealed.sha256,
                known_unlocked=True,
            )
            if not cleanup:
                raise LocalCheckpointError("STORAGE_READBACK_FAILURE")
            tracker.begin("safe_report")
            proof = B2Proof(
                run_id=run_id,
                asset_id=asset_id,
                cert_id=cert_id,
                source_sha256=source_sha256,
                canonical_hash=canonical_hash,
                sealed_sha256=sealed_sha256,
                source=source_receipt,
                manifest=manifest_receipt,
                sealed=sealed,
                sealed_cleanup_verified=True,
                source_bytes=len(source),
                manifest_bytes=len(manifest_body),
                sealed_bytes=len(sealed_body),
            )
        return CheckpointOutcome("OK", 0, tracker.finish("PASS"), proof=proof)
    except Exception as exc:
        if sealed is not None and assets_client is not None and sealed.version_id is not None:
            try:
                delete_unlocked_version_verified(
                    assets_client,
                    bucket=sealed.bucket,
                    key=sealed.key,
                    version_id=sealed.version_id,
                    expected_sha256=sealed.sha256,
                    known_unlocked=True,
                )
            except B2Error:
                pass
        if isinstance(exc, LocalCheckpointError):
            failure = B2FailureInfo(exc.category)  # type: ignore[arg-type]
        else:
            failure = classify_b2_failure(exc, stage=tracker.current)
        role, kind = _failure_context(tracker.current)
        partial_objects: tuple[PartialB2Object, ...] = ()
        if (
            isinstance(exc, B2PersistedObjectError)
            and role in {"assets", "vault"}
            and kind in {"source", "manifest", "sealed"}
        ):
            partial_objects = (
                PartialB2Object(
                    role,  # type: ignore[arg-type]
                    kind,  # type: ignore[arg-type]
                    exc.key,
                    exc.version_id,
                    exc.retained,
                ),
            )
        return CheckpointOutcome(
            failure.category,
            1,
            tracker.finish("FAIL"),
            failure=failure,
            bucket_role=role,
            object_kind=kind,
            partial_objects=partial_objects,
        )


def _report(proof: B2Proof, stages: tuple[dict[str, str], ...], config: CompleteB2Config) -> dict[str, Any]:
    def retained(receipt: LockedObjectReceipt) -> dict[str, Any]:
        return {
            "bucket": receipt.bucket,
            "key": receipt.key,
            "sha256": receipt.sha256,
            "version_id": receipt.version_id,
            "retention_mode": receipt.retention_mode,
            "retention_until": receipt.retention_until.isoformat(),
            "size_bytes": receipt.size_bytes,
        }

    sealed = {
        "bucket": proof.sealed.bucket,
        "key": proof.sealed.key,
        "sha256": proof.sealed.sha256,
        "version_id": proof.sealed.version_id,
        "size_bytes": proof.sealed.size_bytes,
    }
    return {
        "schema_version": "firemark.generate-and-seal-b2-report.v1",
        "local_fixture": True,
        "ai_generated": False,
        "production_b2_generate_and_seal_evidence": True,
        "run_id": proof.run_id,
        "asset_id": proof.asset_id,
        "cert_id": proof.cert_id,
        "source_sha256": proof.source_sha256,
        "canonical_hash": proof.canonical_hash,
        "sealed_sha256": proof.sealed_sha256,
        "buckets": {"assets": config.assets.bucket, "vault": config.vault.bucket},
        "vault_source": retained(proof.source),
        "vault_manifest": retained(proof.manifest),
        "sealed_asset": sealed,
        "sealed_asset_cleanup_verified": proof.sealed_cleanup_verified,
        "byte_counts": {
            "source": proof.source_bytes,
            "manifest": proof.manifest_bytes,
            "sealed": proof.sealed_bytes,
        },
        "stages": stages,
    }


def _write_report(path: Path, report: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise LocalCheckpointError("LOCAL_ADAPTER_ERROR")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        temporary.write_text(
            json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _print_outcome(outcome: CheckpointOutcome) -> None:
    for row in outcome.stages:
        print(f"{row['status']}: {row['stage']}")
    print(f"normalized safe category: {outcome.category}")
    if outcome.failure is not None and outcome.failure.service_error_code is not None:
        print(f"safe B2 error code: {outcome.failure.service_error_code}")
    if outcome.bucket_role is not None:
        print(f"bucket role: {outcome.bucket_role}")
    if outcome.object_kind is not None:
        print(f"object kind: {outcome.object_kind}")
    for item in outcome.partial_objects:
        print(
            "partial exact version: "
            f"bucket_role={item.bucket_role}, object_kind={item.object_kind}, "
            f"key={item.key}, version_id={item.version_id or 'MISSING'}, "
            f"retained={str(item.retained).lower()}"
        )
    print(f"B2_GENERATE_AND_SEAL_EXIT_CODE={outcome.exit_code}")


def run_live(output_report: Path | None, *, force: bool) -> int:
    if output_report is not None and output_report.exists() and not force:
        outcome = CheckpointOutcome(
            "LOCAL_ADAPTER_ERROR",
            1,
            ({"stage": "configuration_validation", "status": "FAIL"},),
        )
        _print_outcome(outcome)
        return outcome.exit_code
    try:
        config = load_settings().require_complete_b2_config()
    except ValueError:
        outcome = CheckpointOutcome(
            "CONFIGURATION_ERROR",
            1,
            ({"stage": "configuration_validation", "status": "FAIL"},),
        )
        _print_outcome(outcome)
        return outcome.exit_code
    outcome = execute_checkpoint(config)
    if outcome.category == "OK" and outcome.proof is not None and output_report is not None:
        try:
            _write_report(output_report, _report(outcome.proof, outcome.stages, config), force=force)
        except LocalCheckpointError:
            outcome = CheckpointOutcome(
                "LOCAL_ADAPTER_ERROR",
                1,
                outcome.stages[:-1] + ({"stage": "safe_report", "status": "FAIL"},),
            )
    _print_outcome(outcome)
    return outcome.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one isolated Generate & Seal B2 custody proof with local fixture bytes."
    )
    parser.add_argument("--live", action="store_true", help="Allow real B2 writes and retention.")
    parser.add_argument("--output-report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.live:
        print("INFO: --live not supplied; zero network calls were made.")
        print("INFO: no B2 client was constructed; OpenAI and Supabase were not called.")
        return INFORMATIONAL_EXIT_CODE
    load_dotenv(DEFAULT_ENV_FILE, override=False)
    return run_live(args.output_report, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
