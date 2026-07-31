"""Zero-network tests for provider-free Generate & Seal recovery."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from api.firemark.b2_storage import sealed_asset_key
from api.firemark.generate_and_seal import _build_manifest
from api.firemark.generate_checkpoint import (
    CheckpointSerializationError,
    GenerateAndSealCheckpoint,
    checkpoint_object,
    read_checkpoint,
    serialize_checkpoint_payload,
    write_checkpoint_atomic,
    write_private_evidence_atomic,
)
from api.firemark.generation.fake_provider import _TINY_PNG
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import extract_public_capsule_png
from scripts import resume_generate_and_seal_checkpoint as resume
from tests.conftest import FakeS3Client

NOW = datetime(2026, 7, 30, 12, tzinfo=UTC)


class SafeState(Enum):
    READY = "ready"


@dataclass(frozen=True)
class FrozenEvidence:
    recorded_at: datetime
    path: Path


def production_evidence() -> tuple[bytes, bytes, str]:
    source = _TINY_PNG
    source_hash = sha256_bytes(source)
    request = GenerationRequest(
        prompt="private recovery prompt",
        model="gpt-image-test",
        size="1024x1024",
        request_id="firemark-run-recovery-test",
    )
    image = GeneratedImage(
        data=source,
        source_mime_type="image/png",
        provider="openai",
        model="gpt-image-test",
        provider_request_id="safe-test-request",
        provider_created_at=NOW,
        safe_generation_metadata={"production_evidence": True},
        ai_generated=True,
    )
    manifest = _build_manifest(
        image,
        request,
        run_id="firemark-run-recovery-test",
        source_sha256=source_hash,
    )
    return source, manifest.to_canonical_json().encode(), manifest.canonical_hash


def make_checkpoint(tmp_path: Path, **updates: Any) -> GenerateAndSealCheckpoint:
    source, manifest, canonical = production_evidence()
    source_path, manifest_path = write_private_evidence_atomic(
        tmp_path / "private",
        run_id="firemark-run-recovery-test",
        source_bytes=source,
        manifest_bytes=manifest,
    )
    values: dict[str, Any] = {
        "operation_state": "prepared",
        "run_id": "firemark-run-recovery-test",
        "asset_id": "firemark-asset-recovery-test",
        "cert_id": "firemark-cert-recovery-test",
        "source_sha256": sha256_bytes(source),
        "sealed_sha256": "b" * 64,
        "canonical_hash": canonical,
        "issued_at": NOW,
        "requested_retention_until": NOW + timedelta(days=90),
        "signer_key_id": "ed25519:test-signer",
        "provider": "openai",
        "model": "gpt-image-test",
        "size": "1024x1024",
        "generated_byte_count": len(source),
        "source_path": str(source_path),
        "manifest_path": str(manifest_path),
    }
    values.update(updates)
    return GenerateAndSealCheckpoint.model_validate(values)


def test_atomic_checkpoint_round_trip_and_secret_exclusion(tmp_path: Path) -> None:
    checkpoint = make_checkpoint(tmp_path)
    path = tmp_path / "checkpoint.json"
    write_checkpoint_atomic(path, checkpoint)
    assert read_checkpoint(path) == checkpoint
    serialized = path.read_text(encoding="utf-8")
    assert "private recovery prompt" not in serialized
    assert "api_key" not in serialized.lower()
    assert "presigned" not in serialized.lower()
    assert not list(tmp_path.glob(".checkpoint.json.*"))


def test_checkpoint_serializer_supports_safe_runtime_types(tmp_path: Path) -> None:
    checkpoint = make_checkpoint(tmp_path)
    payload = serialize_checkpoint_payload(
        {
            "timestamp": NOW,
            "state": SafeState.READY,
            "path": tmp_path / "private.bin",
            "items": ("one", None),
            "dataclass": FrozenEvidence(NOW, tmp_path / "evidence.bin"),
            "model": checkpoint,
            "optional_version_id": None,
        },
        stage="checkpoint_after_vault_manifest",
    )
    decoded = json.loads(payload)
    assert decoded["timestamp"] == "2026-07-30T12:00:00.000000Z"
    assert decoded["state"] == "ready"
    assert decoded["path"] == str(tmp_path / "private.bin")
    assert decoded["items"] == ["one", None]
    assert decoded["dataclass"]["recorded_at"].endswith("Z")
    assert decoded["model"]["operation_state"] == "prepared"
    assert decoded["optional_version_id"] is None


def test_unsupported_checkpoint_value_raises_safe_typed_error() -> None:
    raw_secret = "must-never-appear-in-checkpoint-error"

    class UnsupportedSecret:
        def __init__(self, value: str) -> None:
            self.value = value

    with pytest.raises(CheckpointSerializationError) as captured:
        serialize_checkpoint_payload(
            {"sealed_asset": UnsupportedSecret(raw_secret)},
            stage="checkpoint_after_vault_manifest",
        )
    error = captured.value
    assert error.stage == "checkpoint_after_vault_manifest"
    assert error.field_path == "$.sealed_asset"
    assert error.value_type == "UnsupportedSecret"
    assert raw_secret not in str(error)
    assert raw_secret not in repr(error)


@pytest.mark.parametrize(
    ("value", "value_type", "field_path"),
    [
        (float("nan"), "float", "$.value"),
        (datetime(2026, 7, 30, 12), "datetime", "$.value"),
        ({1: "not-a-checkpoint-field"}, "int", "$.value[1]"),
        (type("unsafe-type", (), {})(), "unsupported", "$.value"),
    ],
)
def test_checkpoint_serializer_rejects_unsafe_values_safely(
    value: object,
    value_type: str,
    field_path: str,
) -> None:
    with pytest.raises(CheckpointSerializationError) as captured:
        serialize_checkpoint_payload({"value": value}, stage="unsafe stage containing secret")
    error = captured.value
    assert error.stage == "checkpoint_serialization"
    assert error.field_path == field_path
    assert error.value_type == value_type
    assert "unsafe stage containing secret" not in str(error)


def test_checkpoint_rejects_unsafe_identity_time_and_missing_version(tmp_path: Path) -> None:
    checkpoint = make_checkpoint(tmp_path)
    values = checkpoint.model_dump()
    values["run_id"] = "../unsafe"
    with pytest.raises(ValueError, match="safe characters"):
        GenerateAndSealCheckpoint.model_validate(values)
    values = checkpoint.model_dump()
    values["issued_at"] = datetime(2026, 7, 30)
    with pytest.raises(ValueError, match="timezone-aware"):
        GenerateAndSealCheckpoint.model_validate(values)
    with pytest.raises(ValueError, match="VersionIds"):
        checkpoint_object(
            type("Receipt", (), {"version_id": None})(),
            bucket_role="assets",
            object_kind="sealed",
        )
    receipt = type(
        "Receipt",
        (),
        {
            "bucket": "assets-test",
            "key": "sealed/safe.png",
            "sha256": "a" * 64,
            "version_id": "exact-version",
            "size_bytes": 123,
        },
    )()
    projected = checkpoint_object(receipt, bucket_role="assets", object_kind="sealed")
    assert projected.version_id == "exact-version"
    assert projected.retention_mode is None
    with pytest.raises(ValueError, match="Unsafe checkpoint"):
        write_private_evidence_atomic(
            tmp_path,
            run_id="../unsafe",
            source_bytes=b"source",
            manifest_bytes=b"manifest",
        )


def test_checkpoint_first_local_evidence_and_manifest_validation(tmp_path: Path) -> None:
    checkpoint = make_checkpoint(tmp_path)
    source, manifest = resume._read_local_evidence(checkpoint, max_bytes=1024 * 1024)
    evidence = resume.validate_manifest_evidence(manifest, checkpoint)
    assert sha256_bytes(source) == checkpoint.source_sha256
    assert evidence.provider == "openai"
    assert evidence.run_id == checkpoint.run_id
    assert evidence.prompt == "private recovery prompt"


def test_missing_or_changed_checkpoint_evidence_fails_closed(tmp_path: Path) -> None:
    checkpoint = make_checkpoint(tmp_path)
    Path(checkpoint.source_path).write_bytes(b"changed")
    with pytest.raises(resume.RecoveryError, match="HASH_MISMATCH"):
        resume._read_local_evidence(checkpoint, max_bytes=1024 * 1024)
    Path(checkpoint.source_path).unlink()
    with pytest.raises(resume.RecoveryError, match="INCOMPLETE_EVIDENCE"):
        resume._read_local_evidence(checkpoint, max_bytes=1024 * 1024)


def test_invalid_provider_and_local_fixture_are_rejected(tmp_path: Path) -> None:
    checkpoint = make_checkpoint(tmp_path)
    manifest = json.loads(Path(checkpoint.manifest_path).read_text(encoding="utf-8"))
    manifest["run"]["steps"][0]["provider"] = "fake"
    payload = json.dumps(manifest).encode()
    with pytest.raises(resume.RecoveryError):
        resume.validate_manifest_evidence(payload)

    manifest = json.loads(Path(checkpoint.manifest_path).read_text(encoding="utf-8"))
    manifest["run"]["steps"][0]["metadata"]["local_fixture"] = True
    payload = json.dumps(manifest).encode()
    with pytest.raises(resume.RecoveryError):
        resume.validate_manifest_evidence(payload)


def test_candidate_selection_rejects_absence_and_ambiguity() -> None:
    with pytest.raises(resume.RecoveryError, match="CHECKPOINT_NOT_FOUND"):
        resume.select_single_candidate([])
    with pytest.raises(resume.RecoveryError, match="AMBIGUOUS_INCOMPLETE_BUNDLE"):
        resume.select_single_candidate([1, 2])
    assert resume.select_single_candidate(["only"]) == "only"


def test_b2_discovery_fallback_finds_one_exact_production_bundle() -> None:
    source, manifest, canonical = production_evidence()
    source_hash = sha256_bytes(source)
    manifest_hash = sha256_bytes(manifest)
    source_key = f"vault/sources/{source_hash[:2]}/{source_hash[2:4]}/{source_hash}.png"
    manifest_key = f"vault/manifests/firemark-run-recovery-test/{canonical}.json"

    class DiscoveryS3(FakeS3Client):
        def list_object_versions(self, **kwargs: Any) -> dict[str, Any]:
            prefix = kwargs["Prefix"]
            return {
                "Versions": [
                    {"Key": key, "VersionId": version}
                    for (_bucket, key, version) in self.objects
                    if key.startswith(prefix)
                ]
            }

    client = DiscoveryS3()
    client.put_object(
        Bucket="vault-test",
        Key=source_key,
        Body=source,
        ContentType="image/png",
        Metadata={"firemark-sha256": source_hash},
        ObjectLockRetainUntilDate=datetime(2030, 1, 1, tzinfo=UTC),
    )
    client.put_object(
        Bucket="vault-test",
        Key=manifest_key,
        Body=manifest,
        ContentType="application/json",
        Metadata={"firemark-sha256": manifest_hash},
        ObjectLockRetainUntilDate=datetime(2030, 1, 1, tzinfo=UTC),
    )
    candidate = resume.discover_legacy_b2_bundle(
        client, vault_bucket="vault-test", max_bytes=1024 * 1024
    )
    assert candidate == {
        "run_id": "firemark-run-recovery-test",
        "manifest_key": manifest_key,
        "manifest_version_id": "test-version-2",
        "source_key": source_key,
        "source_version_id": "test-version-1",
    }


def test_capsule_and_sealed_reconstruction_is_deterministic(tmp_path: Path) -> None:
    checkpoint = make_checkpoint(tmp_path)
    source = Path(checkpoint.source_path).read_bytes()
    preliminary = checkpoint.model_copy(update={"sealed_sha256": "0" * 64})
    with pytest.raises(resume.RecoveryError, match="SEALED_RECONSTRUCTION_FAILED"):
        resume.reconstruct_sealed_bytes(
            preliminary, source, public_base_url="https://firemark.test"
        )

    capsule_only = preliminary.model_copy(update={"sealed_sha256": "0" * 64})
    from api.firemark.public_capsule import FiremarkPublicCapsuleV1, embed_public_capsule_png

    capsule = FiremarkPublicCapsuleV1.model_validate(
        {
            "cert_id": capsule_only.cert_id,
            "asset_id": capsule_only.asset_id,
            "run_id": capsule_only.run_id,
            "canonical_hash": capsule_only.canonical_hash,
            "source_sha256": capsule_only.source_sha256,
            "signer_key_id": capsule_only.signer_key_id,
            "verify_url": f"https://firemark.test/v1/certificates/{capsule_only.cert_id}",
            "issued_at": capsule_only.issued_at,
        }
    )
    expected = embed_public_capsule_png(source, capsule)
    checkpoint = checkpoint.model_copy(update={"sealed_sha256": sha256_bytes(expected)})
    first, first_capsule = resume.reconstruct_sealed_bytes(
        checkpoint, source, public_base_url="https://firemark.test"
    )
    second, _ = resume.reconstruct_sealed_bytes(
        checkpoint, source, public_base_url="https://firemark.test/"
    )
    assert first == second == expected
    assert extract_public_capsule_png(first) == first_capsule
    assert sealed_asset_key(checkpoint.sealed_sha256).endswith(f"/{checkpoint.sealed_sha256}.png")


def test_partial_exact_versions_are_required(tmp_path: Path) -> None:
    checkpoint = make_checkpoint(tmp_path)
    with pytest.raises(resume.RecoveryError, match="VERSION_ID_MISSING"):
        resume._partial_version(checkpoint, object_kind="source")
    partial = {
        "bucket_role": "vault",
        "object_kind": "source",
        "key": "vault/source.png",
        "version_id": "exact-source-version",
        "retained": True,
    }
    values = checkpoint.model_dump()
    values["partial_objects"] = (partial,)
    checkpoint = GenerateAndSealCheckpoint.model_validate(values)
    assert resume._partial_version(checkpoint, object_kind="source") == (
        "vault/source.png",
        "exact-source-version",
    )


def test_recovery_reuses_exact_vault_version_without_new_upload() -> None:
    client = FakeS3Client()
    payload = b"retained-existing-source"
    digest = sha256_bytes(payload)
    client.put_object(
        Bucket="vault-test",
        Key="vault/source.png",
        Body=payload,
        ContentType="image/png",
        Metadata={"firemark-sha256": digest},
        ObjectLockRetainUntilDate=datetime(2030, 1, 1, tzinfo=UTC),
    )
    put_count = [name for name, _ in client.calls].count("put_object")
    receipt, downloaded = resume._verify_locked(
        client,
        bucket="vault-test",
        key="vault/source.png",
        version_id="test-version-1",
        digest=digest,
        max_bytes=1024,
    )
    assert receipt.version_id == "test-version-1"
    assert downloaded == payload
    assert [name for name, _ in client.calls].count("put_object") == put_count
    exact_calls = [
        values
        for name, values in client.calls
        if name in {"head_object", "get_object", "get_object_retention"}
    ]
    assert all(values["VersionId"] == "test-version-1" for values in exact_calls)


def test_recovery_retention_comparison_accepts_safe_subsecond_normalization() -> None:
    requested = datetime(2030, 1, 1, microsecond=500_000, tzinfo=UTC)
    returned = requested.replace(microsecond=0)
    assert resume._retention_covers(returned, requested)
    assert not resume._retention_covers(requested - timedelta(seconds=1), requested)


def test_identical_sealed_asset_is_reused_and_conflict_is_rejected() -> None:
    client = FakeS3Client()
    payload = b"sealed-test-bytes"
    digest = sha256_bytes(payload)
    key = sealed_asset_key(digest)
    first = resume._ensure_unlocked(
        client,
        bucket="assets-test",
        key=key,
        payload=payload,
        digest=digest,
        content_type="image/png",
        kind="sealed",
        metadata={"firemark-cert-id": "cert-safe"},
    )
    second = resume._ensure_unlocked(
        client,
        bucket="assets-test",
        key=key,
        payload=payload,
        digest=digest,
        content_type="image/png",
        kind="sealed",
        metadata={"firemark-cert-id": "cert-safe"},
    )
    assert first.version_id == second.version_id == "test-version-1"
    assert [name for name, _ in client.calls].count("put_object") == 1
    client.objects[("assets-test", key, "test-version-1")]["Metadata"]["firemark-sha256"] = "f" * 64
    with pytest.raises(resume.RecoveryError, match="HASH_MISMATCH"):
        resume._ensure_unlocked(
            client,
            bucket="assets-test",
            key=key,
            payload=payload,
            digest=digest,
            content_type="image/png",
            kind="sealed",
        )


def test_recovery_completes_atomic_registration_and_is_idempotent(tmp_path: Path) -> None:
    checkpoint = make_checkpoint(tmp_path)
    calls: list[str] = []
    resume._complete_registration(
        None,
        checkpoint,
        lambda: calls.append("atomic_supabase_registration"),
    )
    assert calls == ["atomic_supabase_registration"]

    existing = SimpleNamespace(
        cert_id=checkpoint.cert_id,
        asset_id=checkpoint.asset_id,
        run_id=checkpoint.run_id,
        source_sha256=checkpoint.source_sha256,
        sealed_sha256=checkpoint.sealed_sha256,
        canonical_hash=checkpoint.canonical_hash,
        signer_key_id=checkpoint.signer_key_id,
    )
    resume._complete_registration(
        existing,
        checkpoint,
        lambda: pytest.fail("identical registration must be reused"),
    )
    with pytest.raises(resume.RecoveryError, match="CONFLICTING_CERTIFICATE"):
        resume._complete_registration(
            SimpleNamespace(**{**existing.__dict__, "asset_id": "conflicting-asset"}),
            checkpoint,
            lambda: None,
        )
    with pytest.raises(resume.RecoveryError, match="REGISTRATION_FAILURE"):
        resume._complete_registration(
            None,
            checkpoint,
            lambda: (_ for _ in ()).throw(RuntimeError("private database detail")),
        )


def test_non_live_mode_constructs_no_clients_or_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        resume,
        "run_live",
        lambda *_args, **_kwargs: pytest.fail("live composition must not run"),
    )
    assert resume.main([]) == 2
    assert "OpenAI" not in " ".join(resume.__dict__)


def test_safe_report_writer_is_atomic_and_contains_no_url(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    resume._safe_report_write(
        path,
        {"category": "OK", "new_provider_calls": 0},
        force=False,
    )
    payload = path.read_text(encoding="utf-8")
    assert "download_url" not in payload
    assert "presigned" not in payload
    with pytest.raises(resume.RecoveryError):
        resume._safe_report_write(path, {"category": "OK"}, force=False)


def test_all_recovery_stages_are_attributed_in_order() -> None:
    tracker = resume.StageTracker()
    for stage in resume.STAGES[1:]:
        tracker.begin(stage)
    tracker.complete_current()
    assert [item["stage"] for item in tracker.completed] == list(resume.STAGES)
