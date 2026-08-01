"""Zero-network tests for the recovery-safe live multimodal checkpoint."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

import scripts.smoke_multimodal_generate_and_seal as smoke
from api.firemark.custody import StoredObjectReceipt
from api.firemark.generate_checkpoint import checkpoint_object
from api.firemark.generation.fake_provider import _TINY_MP3, _TINY_PNG
from api.firemark.generation.models import GeneratedAudio, GeneratedImage
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import extract_public_capsule_png
from api.firemark.settings import load_settings
from api.firemark.signer import Ed25519Signer

NOW = datetime(2026, 7, 30, 20, tzinfo=UTC)


def make_store(tmp_path: Path, media_type: smoke.MediaKind) -> smoke.CheckpointStore:
    provider = "google_gemini" if media_type == "image" else "elevenlabs"
    store = smoke.CheckpointStore(
        tmp_path / f"{provider}-checkpoint.json", tmp_path / "private" / provider
    )
    smoke._initialize_checkpoint(
        store,
        media_type=media_type,
        provider=provider,
        model="safe-model",
        size="1024x1024" if media_type == "image" else None,
        signer=Ed25519Signer.generate(),
        retention_days=90,
    )
    return store


def generated_image() -> GeneratedImage:
    return GeneratedImage(
        data=_TINY_PNG,
        provider="google_gemini",
        model="safe-model",
        provider_request_id="safe-request",
        provider_created_at=NOW,
        safe_generation_metadata={"output_format": "png"},
        ai_generated=True,
    )


def generated_audio() -> GeneratedAudio:
    return GeneratedAudio(
        data=_TINY_MP3,
        provider="elevenlabs",
        model="safe-model",
        voice_id="private-voice-id",
        provider_request_id="safe-request",
        provider_created_at=NOW,
        safe_generation_metadata={"output_format": "mp3_44100_128"},
        ai_generated=True,
    )


def persist_generated(
    store: smoke.CheckpointStore, media: GeneratedImage | GeneratedAudio
) -> None:
    store.update(operation_state="provider_call_started", new_provider_calls=1)
    store.persist_generated(media)


def prepare_store(
    tmp_path: Path, media_type: smoke.MediaKind
) -> tuple[smoke.CheckpointStore, smoke.MultimodalCheckpoint, bytes]:
    store = make_store(tmp_path, media_type)
    media = generated_image() if media_type == "image" else generated_audio()
    persist_generated(store, media)
    checkpoint = store.read()
    canonical_hash = "a" * 64
    common = {
        "cert_id": checkpoint.cert_id,
        "asset_id": checkpoint.asset_id,
        "run_id": checkpoint.run_id,
        "canonical_hash": canonical_hash,
        "source_sha256": sha256_bytes(media.data),
        "signer_key_id": checkpoint.signer_key_id,
        "verify_url": f"https://verify.firemark.test/v1/certificates/{checkpoint.cert_id}",
        "issued_at": checkpoint.issued_at,
    }
    if media_type == "image":
        capsule = smoke.FiremarkPublicCapsuleV1.model_validate(common)
        sealed = smoke.embed_public_capsule_png(media.data, capsule)
    else:
        sealed = media.data
    store.checkpoint_event(
        "prepared",
        {
            "source_bytes": media.data,
            "manifest_bytes": b"{}",
            "source_sha256": sha256_bytes(media.data),
            "sealed_sha256": sha256_bytes(sealed),
            "canonical_hash": canonical_hash,
            "issued_at": checkpoint.issued_at,
            "requested_retention_until": checkpoint.requested_retention_until,
            "signer_key_id": checkpoint.signer_key_id,
        },
    )
    return store, store.read(), sealed


def test_non_live_mode_constructs_zero_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("non-live mode must not construct an external client")

    monkeypatch.setattr(smoke, "load_settings", forbidden)
    monkeypatch.setattr(smoke, "create_assets_client", forbidden)
    monkeypatch.setattr(smoke, "create_vault_client", forbidden)
    assert smoke.main([]) == 2


def test_help_is_available_without_live_configuration() -> None:
    with pytest.raises(SystemExit) as caught:
        smoke.main(["--help"])
    assert caught.value.code == 0


def test_image_checkpoint_is_atomic_and_safe(tmp_path: Path) -> None:
    store = make_store(tmp_path, "image")
    payload = store.path.read_text("utf-8")
    assert json.loads(payload)["provider"] == "google_gemini"
    assert smoke.GEMINI_PROMPT not in payload
    assert "api_key" not in payload.lower()


def test_audio_checkpoint_excludes_text_and_private_voice(tmp_path: Path) -> None:
    store = make_store(tmp_path, "audio")
    persist_generated(store, generated_audio())
    payload = store.path.read_text("utf-8")
    assert smoke.ELEVENLABS_TEXT not in payload
    assert "private-voice-id" not in payload
    assert "voice_id" not in payload


def test_exactly_one_gemini_call_is_persisted(tmp_path: Path) -> None:
    store = make_store(tmp_path, "image")

    class Provider:
        calls = 0

        def generate_image(self, _request: Any) -> GeneratedImage:
            self.calls += 1
            return generated_image()

    provider = Provider()
    captured = smoke.CapturedGeminiProvider(
        provider, store, smoke.StageTracker(store, "gemini")  # type: ignore[arg-type]
    )
    captured.generate_image(object())  # type: ignore[arg-type]
    assert provider.calls == 1
    assert store.read().new_provider_calls == 1


def test_exactly_one_elevenlabs_call_is_persisted(tmp_path: Path) -> None:
    store = make_store(tmp_path, "audio")

    class Provider:
        calls = 0

        def generate_audio(self, _request: Any) -> GeneratedAudio:
            self.calls += 1
            return generated_audio()

    provider = Provider()
    captured = smoke.CapturedElevenLabsProvider(
        provider, store, smoke.StageTracker(store, "elevenlabs")  # type: ignore[arg-type]
    )
    captured.generate_audio(object())  # type: ignore[arg-type]
    assert provider.calls == 1
    assert store.read().new_provider_calls == 1


def test_failed_provider_call_is_marked_ambiguous_and_never_retried(tmp_path: Path) -> None:
    store = make_store(tmp_path, "image")

    class FailedProvider:
        def generate_image(self, _request: Any) -> GeneratedImage:
            raise GenerationProviderError("timeout")

    captured = smoke.CapturedGeminiProvider(
        FailedProvider(),  # type: ignore[arg-type]
        store,
        smoke.StageTracker(store, "gemini"),
    )
    with pytest.raises(GenerationProviderError, match="timeout"):
        captured.generate_image(object())  # type: ignore[arg-type]
    checkpoint = store.read()
    assert checkpoint.operation_state == "provider_rejected"
    assert checkpoint.new_provider_calls == 1
    assert checkpoint.provider_failure_code == "timeout"
    assert checkpoint.provider_retry_allowed is False
    assert not smoke._checkpoint_retry_allowed(checkpoint)


@pytest.mark.parametrize("media_type", ["image", "audio"])
def test_provider_call_is_not_repeated_after_capture(
    tmp_path: Path, media_type: smoke.MediaKind
) -> None:
    store = make_store(tmp_path, media_type)
    media = generated_image() if media_type == "image" else generated_audio()
    persist_generated(store, media)
    if media_type == "image":
        provider = smoke.CapturedGeminiProvider(
            object(), store, smoke.StageTracker(store, "gemini")  # type: ignore[arg-type]
        )
        with pytest.raises(smoke.LiveCheckpointError):
            provider.generate_image(object())  # type: ignore[arg-type]
    else:
        audio_provider = smoke.CapturedElevenLabsProvider(
            object(), store, smoke.StageTracker(store, "elevenlabs")  # type: ignore[arg-type]
        )
        with pytest.raises(smoke.LiveCheckpointError):
            audio_provider.generate_audio(object())  # type: ignore[arg-type]


def test_generated_gemini_bytes_resume_without_external_provider(tmp_path: Path) -> None:
    store = make_store(tmp_path, "image")
    persist_generated(store, generated_image())
    recovered = smoke._read_generated_media(store.read())
    assert isinstance(recovered, GeneratedImage)
    assert smoke.RecoveredImageProvider(recovered).generate_image(
        type("Request", (), {"model": "safe-model"})()
    ).data == _TINY_PNG


def test_generated_audio_bytes_resume_without_external_provider(tmp_path: Path) -> None:
    store = make_store(tmp_path, "audio")
    persist_generated(store, generated_audio())
    recovered = smoke._read_generated_media(store.read())
    assert isinstance(recovered, GeneratedAudio)
    request = type(
        "Request", (), {"model": "safe-model", "voice_id": "private-voice-id"}
    )()
    assert smoke.RecoveredAudioProvider(recovered).generate_audio(request).data == _TINY_MP3


def test_valid_gemini_png_reconstructs_capsule(tmp_path: Path) -> None:
    _, checkpoint, sealed = prepare_store(tmp_path, "image")
    reconstructed, manifest = smoke._reconstruct_sealed(
        checkpoint, _TINY_PNG, public_base_url="https://verify.firemark.test"
    )
    assert reconstructed == sealed
    assert extract_public_capsule_png(reconstructed).cert_id == checkpoint.cert_id
    assert "sealed_sha256" not in manifest


def test_valid_elevenlabs_mp3_is_byte_preserving(tmp_path: Path) -> None:
    _, checkpoint, _ = prepare_store(tmp_path, "audio")
    reconstructed, manifest = smoke._reconstruct_sealed(
        checkpoint, _TINY_MP3, public_base_url="https://verify.firemark.test"
    )
    assert reconstructed == _TINY_MP3
    assert checkpoint.source_sha256 == checkpoint.sealed_sha256
    assert manifest["embedded"] is False
    assert manifest["verification_method"] == "cert_id+sha256"


def test_invalid_gemini_sealed_hash_fails_closed(tmp_path: Path) -> None:
    store, checkpoint, _ = prepare_store(tmp_path, "image")
    store.update(sealed_sha256="f" * 64)
    with pytest.raises(smoke.LiveCheckpointError, match="VERIFICATION_FAILURE"):
        smoke._reconstruct_sealed(
            store.read(), _TINY_PNG, public_base_url="https://verify.firemark.test"
        )
    assert checkpoint.new_provider_calls == 1


def test_invalid_mp3_output_is_classified() -> None:
    with pytest.raises(ValueError, match="MP3"):
        GeneratedAudio(
            data=b"not-mp3",
            provider="elevenlabs",
            model="safe-model",
            voice_id="voice",
            provider_created_at=NOW,
            ai_generated=True,
        )
    assert smoke._PROVIDER_CATEGORIES["non_mp3_response"] == "NON_MP3_RESPONSE"


def test_invalid_gemini_output_category_is_safe() -> None:
    error = GenerationProviderError("non_png_response")
    assert smoke._PROVIDER_CATEGORIES[error.code] == "NON_PNG_RESPONSE"
    assert "provider response" not in str(error).lower()


def test_gemini_failure_prevents_elevenlabs_runner() -> None:
    calls: list[str] = []

    def gemini() -> dict[str, object]:
        calls.append("gemini")
        raise smoke.LiveCheckpointError("QUOTA_OR_BILLING_FAILURE")

    def elevenlabs() -> dict[str, object]:
        calls.append("elevenlabs")
        return {}

    with pytest.raises(smoke.LiveCheckpointError):
        smoke._run_sequential_operations(gemini, elevenlabs)
    assert calls == ["gemini"]


@pytest.mark.parametrize("state", ["generated", "prepared", "custody_persisted", "sealed_persisted"])
def test_recovery_states_retain_single_provider_call(
    tmp_path: Path, state: smoke.OperationState
) -> None:
    store = make_store(tmp_path, "audio")
    persist_generated(store, generated_audio())
    store.update(operation_state=state)
    assert store.read().new_provider_calls == 1


def test_b2_failure_checkpoint_keeps_local_generated_bytes(tmp_path: Path) -> None:
    store, checkpoint, _ = prepare_store(tmp_path, "image")
    assert Path(checkpoint.source_path or "").read_bytes() == _TINY_PNG
    assert checkpoint.operation_state == "prepared"
    assert checkpoint.new_provider_calls == 1


def test_supabase_failure_checkpoint_keeps_exact_sealed_version(tmp_path: Path) -> None:
    store, _, _ = prepare_store(tmp_path, "audio")
    receipt = StoredObjectReceipt(
        bucket="assets",
        key="sealed/aa/asset.mp3",
        sha256=store.read().sealed_sha256 or "a" * 64,
        content_type="audio/mpeg",
        size_bytes=len(_TINY_MP3),
        version_id="exact-sealed-version",
        created_at=NOW,
    )
    store.checkpoint_event("sealed_persisted", {"sealed_receipt": receipt})
    checkpoint = store.read()
    assert checkpoint.operation_state == "sealed_persisted"
    assert checkpoint.sealed_asset is not None
    assert checkpoint.sealed_asset.version_id == "exact-sealed-version"
    assert checkpoint.new_provider_calls == 1


def test_checkpoint_object_requires_exact_version_id() -> None:
    receipt = type("Receipt", (), {"version_id": None})()
    with pytest.raises(ValueError, match="VersionIds"):
        checkpoint_object(receipt, bucket_role="assets", object_kind="sealed")


def test_compliance_retention_is_preserved_in_checkpoint(tmp_path: Path) -> None:
    store, _, _ = prepare_store(tmp_path, "image")
    checkpoint = store.read()
    assert checkpoint.requested_retention_until > checkpoint.issued_at


def test_stage_results_are_persisted_atomically(tmp_path: Path) -> None:
    store = make_store(tmp_path, "image")
    tracker = smoke.StageTracker(store, "gemini")
    tracker.begin("gemini_configuration_validation")
    tracker.begin("gemini_request_construction")
    tracker.complete_current()
    stages = [item["stage"] for item in store.read().stage_results]
    assert stages == ["gemini_configuration_validation", "gemini_request_construction"]


def test_safe_report_is_atomic_and_contains_no_private_input(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    smoke._write_safe_report(
        path,
        {
            "provider": "google_gemini",
            "model": "safe-model",
            "new_gemini_calls": 1,
        },
        force=False,
    )
    payload = path.read_text("utf-8")
    assert smoke.GEMINI_PROMPT not in payload
    assert smoke.ELEVENLABS_TEXT not in payload
    with pytest.raises(smoke.LiveCheckpointError):
        smoke._write_safe_report(path, {"provider": "google_gemini"}, force=False)


@pytest.mark.parametrize(
    "forbidden",
    ["api_key", "authorization", "private_manifest", "download_url", "x-amz-signature"],
)
def test_safe_report_rejects_secret_or_transient_markers(forbidden: str) -> None:
    with pytest.raises(smoke.LiveCheckpointError):
        smoke._safe_report_bytes({forbidden: "redacted"})


def test_non_live_source_has_no_alternate_provider_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        smoke,
        "run_live",
        lambda *_args, **_kwargs: pytest.fail("live path must remain opt-in"),
    )
    assert smoke.main([]) == 2



# --------------------------------------------------------------------------
# Finalization: accurate terminal stages and a clean successful exit
# --------------------------------------------------------------------------


def operation_report(
    *,
    provider: str,
    media_type: str,
    stages: tuple[str, ...],
    source: str = "a" * 64,
    sealed: str | None = None,
    cert_id: str = "firemark-cert-report",
) -> dict[str, object]:
    """A complete safe operation report, shaped exactly like `_operation_report`."""
    return {
        "provider": provider,
        "model": "safe-model",
        "media_type": media_type,
        "mime_type": "image/png" if media_type == "image" else "audio/mpeg",
        "source_mime_type": "image/jpeg" if media_type == "image" else "audio/mpeg",
        "byte_size": 4096,
        "run_id": "firemark-run-report",
        "asset_id": "firemark-asset-report",
        "cert_id": cert_id,
        "source_sha256": source,
        "sealed_sha256": sealed if sealed is not None else "b" * 64,
        "canonical_hash": "c" * 64,
        "signer_key_id": "firemark-signer-1",
        "sealed_asset_key": "assets/ab/cd/sealed",
        "sealed_asset_version_id": "sealed-version-1",
        "vault_source_key": "vault/sources/ab/cd/source",
        "vault_source_version_id": "vault-source-version-1",
        "vault_manifest_key": "vault/manifests/run/hash.json",
        "vault_manifest_version_id": "vault-manifest-version-1",
        "retention_until": "2026-10-29T00:00:00+00:00",
        "ai_generated": True,
        "new_provider_calls": 1,
        "stages": [{"stage": stage, "status": "PASS"} for stage in stages],
    }


def complete_gemini_report(**kwargs: object) -> dict[str, object]:
    values: dict[str, object] = {
        "provider": "google_gemini",
        "media_type": "image",
        "stages": smoke.GEMINI_STAGES,
        "cert_id": "firemark-cert-gemini",
    }
    values.update(kwargs)
    return operation_report(**values)  # type: ignore[arg-type]


def complete_elevenlabs_report(**kwargs: object) -> dict[str, object]:
    values: dict[str, object] = {
        "provider": "elevenlabs",
        "media_type": "audio",
        "stages": smoke.ELEVENLABS_STAGES,
        "source": "d" * 64,
        "sealed": "d" * 64,
        "cert_id": "firemark-cert-elevenlabs",
    }
    values.update(kwargs)
    return operation_report(**values)  # type: ignore[arg-type]


def finalize_reports(
    tmp_path: Path,
    gemini: dict[str, object] | None = None,
    elevenlabs: dict[str, object] | None = None,
    *,
    new_gemini_calls: int = 1,
    new_elevenlabs_calls: int = 1,
    force: bool = False,
) -> tuple[dict[str, object], list[str]]:
    stages: list[str] = []
    report = smoke.finalize(
        gemini if gemini is not None else complete_gemini_report(),
        elevenlabs if elevenlabs is not None else complete_elevenlabs_report(),
        tmp_path / "report.json",
        force=force,
        new_gemini_calls=new_gemini_calls,
        new_elevenlabs_calls=new_elevenlabs_calls,
        stage_callback=stages.append,
    )
    return report, stages


def test_every_declared_stage_passes_and_is_reported_once() -> None:
    """The stage vocabulary itself must contain no duplicates."""
    combined = list(smoke.GEMINI_STAGES) + list(smoke.ELEVENLABS_STAGES)
    combined += list(smoke.FINALIZATION_STAGES)
    assert len(combined) == len(set(combined))
    assert len(smoke.GEMINI_STAGES) == 17
    assert len(smoke.ELEVENLABS_STAGES) == 16
    assert smoke.ALL_STAGES == frozenset(smoke.GEMINI_STAGES) | frozenset(
        smoke.ELEVENLABS_STAGES
    )


def test_a_fully_successful_finalization_reports_each_stage_once(tmp_path: Path) -> None:
    report, stages = finalize_reports(tmp_path)
    assert stages == list(smoke.FINALIZATION_STAGES)
    assert len(stages) == len(set(stages))
    assert (tmp_path / "report.json").is_file()
    assert report["production_gemini_evidence"] is True
    assert report["production_elevenlabs_evidence"] is True
    assert report["production_multimodal_evidence"] is True
    gemini_stages = [row["stage"] for row in report["gemini"]["stages"]]  # type: ignore[index]
    audio_stages = [row["stage"] for row in report["elevenlabs"]["stages"]]  # type: ignore[index]
    assert gemini_stages == list(smoke.GEMINI_STAGES)
    assert audio_stages == list(smoke.ELEVENLABS_STAGES)
    assert len(gemini_stages) == len(set(gemini_stages))
    assert len(audio_stages) == len(set(audio_stages))


def test_private_manifest_stage_names_no_longer_fail_the_secret_scan(tmp_path: Path) -> None:
    """The regression: stage labels are FIREMARK vocabulary, not provider data."""
    assert "gemini_private_manifest" in smoke.GEMINI_STAGES
    assert "elevenlabs_private_manifest" in smoke.ELEVENLABS_STAGES
    assert "private_manifest" in smoke._FORBIDDEN_REPORT_MARKERS
    report, _stages = finalize_reports(tmp_path)
    payload = (tmp_path / "report.json").read_text("utf-8")
    assert "gemini_private_manifest" in payload
    assert "elevenlabs_private_manifest" in payload
    assert report["new_gemini_calls"] == 1


def test_report_serialization_failure_receives_its_own_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("private serialization detail")

    monkeypatch.setattr(smoke.importlib.metadata, "version", refuse)
    stages: list[str] = []
    with pytest.raises(RuntimeError):
        smoke.finalize(
            complete_gemini_report(),
            complete_elevenlabs_report(),
            tmp_path / "report.json",
            force=False,
            new_gemini_calls=1,
            new_elevenlabs_calls=1,
            stage_callback=stages.append,
        )
    assert stages[-1] == "report_serialization"
    assert "elevenlabs_configuration_validation" not in stages


def test_evidence_validation_failure_receives_its_own_stage(tmp_path: Path) -> None:
    stages: list[str] = []
    with pytest.raises(smoke.LiveCheckpointError) as caught:
        smoke.finalize(
            complete_gemini_report(sealed="a" * 64),
            complete_elevenlabs_report(),
            tmp_path / "report.json",
            force=False,
            new_gemini_calls=1,
            new_elevenlabs_calls=1,
            stage_callback=stages.append,
        )
    assert caught.value.category == "VERIFICATION_FAILURE"
    assert stages == ["multimodal_evidence_validation"]
    assert not (tmp_path / "report.json").exists()


def test_secret_scan_failure_receives_its_own_stage(tmp_path: Path) -> None:
    stages: list[str] = []
    with pytest.raises(smoke.LiveCheckpointError):
        smoke.finalize(
            complete_gemini_report(),
            complete_elevenlabs_report(),
            tmp_path / "report.json",
            force=False,
            new_gemini_calls=1,
            new_elevenlabs_calls=1,
            stage_callback=lambda name: (
                stages.append(name),
                _inject_marker(name),
            )[0],
        )
    assert stages[-1] == "report_secret_scan"


_MARKER_STATE: dict[str, object] = {}


def _inject_marker(name: str) -> None:
    """Make the scan copy carry a genuine forbidden marker outside stage rows."""
    if name == "report_secret_scan":
        original = smoke._scannable_report

        def poisoned(report: Any) -> dict[str, object]:
            scanned = original(report)
            scanned["leak"] = "presigned"
            return scanned

        _MARKER_STATE["original"] = original
        smoke._scannable_report = poisoned  # type: ignore[assignment]


@pytest.fixture(autouse=True)
def _restore_scannable() -> Any:
    yield
    original = _MARKER_STATE.pop("original", None)
    if original is not None:
        smoke._scannable_report = original  # type: ignore[assignment]


@pytest.mark.parametrize(
    "rows",
    [
        "not-a-list",
        [{"stage": "unknown_stage", "status": "PASS"}],
        [{"stage": "gemini_source_hash", "status": "FAIL"}],
        [{"stage": "gemini_source_hash"}],
        [{"stage": "gemini_source_hash", "status": "PASS", "extra": 1}],
        ["not-a-mapping"],
    ],
)
def test_stage_rows_are_structurally_validated(rows: object) -> None:
    with pytest.raises(smoke.LiveCheckpointError):
        smoke._validated_stage_rows(rows)


def test_forbidden_markers_outside_stage_rows_still_fail() -> None:
    poisoned = complete_gemini_report()
    poisoned["sealed_asset_key"] = "assets/presigned/leak"
    with pytest.raises(smoke.LiveCheckpointError):
        smoke._safe_report_bytes({"gemini": poisoned})


@pytest.mark.parametrize(
    ("gemini", "elevenlabs"),
    [
        (complete_gemini_report(provider="openai"), complete_elevenlabs_report()),
        (complete_gemini_report(media_type="audio"), complete_elevenlabs_report()),
        (complete_gemini_report(), complete_elevenlabs_report(sealed="e" * 64)),
        (
            complete_gemini_report(cert_id="firemark-cert-same"),
            complete_elevenlabs_report(cert_id="firemark-cert-same"),
        ),
        (complete_gemini_report(stages=smoke.GEMINI_STAGES[:3]), complete_elevenlabs_report()),
    ],
)
def test_incomplete_or_inconsistent_evidence_is_rejected(
    gemini: dict[str, object], elevenlabs: dict[str, object]
) -> None:
    with pytest.raises(smoke.LiveCheckpointError):
        smoke._validate_multimodal_evidence(gemini, elevenlabs)


@pytest.mark.parametrize(
    "field",
    ["run_id", "asset_id", "cert_id", "source_sha256", "sealed_asset_version_id"],
)
def test_missing_evidence_identifiers_are_rejected(field: str) -> None:
    gemini = complete_gemini_report()
    gemini[field] = ""
    with pytest.raises(smoke.LiveCheckpointError):
        smoke._validate_multimodal_evidence(gemini, complete_elevenlabs_report())


def test_a_finalization_defect_is_never_labelled_a_provider_configuration_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The exact regression: a terminal failure reported as ElevenLabs config."""
    monkeypatch.setattr(
        smoke,
        "load_dotenv",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            smoke.LiveCheckpointError("SAFE_UNEXPECTED_FAILURE")
        ),
    )
    assert smoke.run_live(tmp_path / "report.json", force=False) == 1
    output = capsys.readouterr().out
    assert "FAIL: gemini_configuration_validation" in output

    for stage in smoke.FINALIZATION_STAGES:
        assert not stage.startswith("elevenlabs_")
        assert not stage.startswith("gemini_")


# --------------------------------------------------------------------------
# --resume-existing performs zero provider calls
# --------------------------------------------------------------------------


def completed_store(
    tmp_path: Path, media_type: str, *, provider: str, name: str
) -> smoke.CheckpointStore:
    store = smoke.CheckpointStore(
        tmp_path / f"{name}.json", tmp_path / "private" / name
    )
    signer = smoke.Ed25519Signer.generate()
    smoke._initialize_checkpoint(
        store,
        media_type=media_type,  # type: ignore[arg-type]
        provider=provider,  # type: ignore[arg-type]
        model="safe-model",
        size="1024x1024" if media_type == "image" else None,
        signer=signer,
        retention_days=90,
    )
    def object_reference(bucket_role: str, object_kind: str) -> Any:
        return smoke.CheckpointObject.model_validate(
            {
                "bucket": "firemark-bucket",
                "key": f"{bucket_role}/{object_kind}/ab/cd/object",
                "version_id": "version-1",
                "sha256": "a" * 64,
                "size_bytes": 4096,
                "bucket_role": bucket_role,
                "object_kind": object_kind,
            }
        )

    reference = object_reference("vault", "source")
    sealed = object_reference("assets", "sealed")
    store.update(
        operation_state="complete",
        new_provider_calls=1,
        source_sha256="a" * 64 if media_type == "image" else "d" * 64,
        sealed_sha256="b" * 64 if media_type == "image" else "d" * 64,
        canonical_hash="c" * 64,
        source_mime_type="image/jpeg" if media_type == "image" else "audio/mpeg",
        source_extension="jpg" if media_type == "image" else "mp3",
        assets_source=object_reference("assets", "source"),
        assets_manifest=object_reference("assets", "manifest"),
        vault_source=reference,
        vault_manifest=object_reference("vault", "manifest"),
        sealed_asset=sealed,
        stage_results=tuple(
            {"stage": stage, "status": "PASS"}
            for stage in (
                smoke.GEMINI_STAGES if media_type == "image" else smoke.ELEVENLABS_STAGES
            )
        ),
    )
    return store


def prepare_completed_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    gemini_path = tmp_path / "gemini.json"
    audio_path = tmp_path / "elevenlabs.json"
    completed_store(tmp_path, "image", provider="google_gemini", name="gemini")
    completed_store(tmp_path, "audio", provider="elevenlabs", name="elevenlabs")
    monkeypatch.setattr(smoke, "DEFAULT_GEMINI_CHECKPOINT", gemini_path)
    monkeypatch.setattr(smoke, "DEFAULT_ELEVENLABS_CHECKPOINT", audio_path)
    monkeypatch.setattr(smoke, "DEFAULT_PRIVATE_ROOT", tmp_path / "private")


def forbid_all_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        pytest.fail("resume must not contact any provider or service")

    monkeypatch.setattr(smoke, "GeminiImageProvider", refuse)
    monkeypatch.setattr(smoke, "ElevenLabsAudioProvider", refuse)
    monkeypatch.setattr(smoke, "create_assets_client", refuse)
    monkeypatch.setattr(smoke, "create_vault_client", refuse)
    monkeypatch.setattr(smoke, "SupabaseCertificateRepository", refuse)
    monkeypatch.setattr(smoke, "load_settings", refuse)
    monkeypatch.setattr(httpx.Client, "send", refuse)


def test_resume_existing_performs_zero_provider_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prepare_completed_run(tmp_path, monkeypatch)
    forbid_all_network(monkeypatch)
    report_path = tmp_path / "report.json"
    assert smoke.main(["--resume-existing", "--output-report", str(report_path)]) == 0
    output = capsys.readouterr().out
    assert "NEW_GEMINI_CALLS=0" in output
    assert "NEW_ELEVENLABS_CALLS=0" in output
    assert "no Gemini, ElevenLabs, B2, or Supabase client was constructed" in output
    for stage in smoke.FINALIZATION_STAGES:
        assert f"PASS: {stage}" in output

    report = json.loads(report_path.read_text("utf-8"))
    assert report["new_gemini_calls"] == 0
    assert report["new_elevenlabs_calls"] == 0
    assert report["recorded_gemini_calls"] == 1
    assert report["recorded_elevenlabs_calls"] == 1
    assert report["production_gemini_evidence"] is True
    assert report["production_elevenlabs_evidence"] is True
    assert report["production_multimodal_evidence"] is True
    assert report["production_b2_custody_evidence"] is True
    assert report["production_supabase_evidence"] is True


def test_resume_existing_reuses_persisted_versions_idempotently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepare_completed_run(tmp_path, monkeypatch)
    forbid_all_network(monkeypatch)
    report_path = tmp_path / "report.json"
    assert smoke.main(["--resume-existing", "--output-report", str(report_path)]) == 0
    first = report_path.read_bytes()
    gemini_before = (tmp_path / "gemini.json").read_bytes()
    audio_before = (tmp_path / "elevenlabs.json").read_bytes()

    assert (
        smoke.main(["--resume-existing", "--output-report", str(report_path), "--force"]) == 0
    )
    assert report_path.read_bytes() == first
    # Neither checkpoint is rewritten and no duplicate object or record is made.
    assert (tmp_path / "gemini.json").read_bytes() == gemini_before
    assert (tmp_path / "elevenlabs.json").read_bytes() == audio_before

    report = json.loads(report_path.read_text("utf-8"))
    assert report["gemini"]["vault_source_version_id"] == "version-1"
    assert report["elevenlabs"]["sealed_asset_version_id"] == "version-1"


def test_resume_existing_refuses_incomplete_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prepare_completed_run(tmp_path, monkeypatch)
    forbid_all_network(monkeypatch)
    store = smoke.CheckpointStore(tmp_path / "elevenlabs.json", tmp_path / "private")
    store.update(operation_state="registered")
    assert smoke.main(["--resume-existing", "--output-report", str(tmp_path / "r.json")]) == 1
    output = capsys.readouterr().out
    assert "FAIL: multimodal_evidence_validation (CATEGORY=INCOMPLETE_EVIDENCE)" in output


def test_resume_existing_refuses_a_missing_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(smoke, "DEFAULT_GEMINI_CHECKPOINT", tmp_path / "absent.json")
    monkeypatch.setattr(smoke, "DEFAULT_ELEVENLABS_CHECKPOINT", tmp_path / "absent2.json")
    forbid_all_network(monkeypatch)
    assert smoke.main(["--resume-existing", "--output-report", str(tmp_path / "r.json")]) == 1


def test_resume_output_excludes_secrets_prompts_and_transient_urls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    prepare_completed_run(tmp_path, monkeypatch)
    forbid_all_network(monkeypatch)
    report_path = tmp_path / "report.json"
    assert smoke.main(["--resume-existing", "--output-report", str(report_path)]) == 0
    payload = report_path.read_text("utf-8")
    output = capsys.readouterr().out
    for haystack in (payload, output):
        assert smoke.GEMINI_PROMPT not in haystack
        assert smoke.ELEVENLABS_TEXT not in haystack
        for marker in smoke._FORBIDDEN_REPORT_MARKERS:
            if marker == "private_manifest":
                continue  # a stage label, validated structurally instead
            assert marker not in haystack.lower()


def test_help_documents_resume_existing() -> None:
    help_text = " ".join(smoke.build_parser().format_help().split())
    assert "--resume-existing" in help_text
    assert "zero Gemini and zero ElevenLabs generation requests" in help_text


def test_non_live_without_resume_remains_zero_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forbid_all_network(monkeypatch)
    monkeypatch.setattr(
        smoke, "run_live", lambda *_a, **_k: pytest.fail("live must stay opt-in")
    )
    monkeypatch.setattr(
        smoke, "resume_existing", lambda *_a, **_k: pytest.fail("resume must be explicit")
    )
    assert smoke.main([]) == 2


# --------------------------------------------------------------------------
# Canonical B2 environment variable names
# --------------------------------------------------------------------------


def test_canonical_b2_environment_names_and_aliases_are_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`B2_ENDPOINT_URL` and `B2_REGION_NAME` are not FIREMARK variables."""
    for name in (
        "B2_ENDPOINT",
        "B2_REGION",
        "B2_ASSETS_BUCKET",
        "B2_ASSETS_KEY_ID",
        "B2_VAULT_BUCKET",
        "B2_VAULT_KEY_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("B2_ENDPOINT", "https://s3.us-west-004.backblazeb2.com")
    monkeypatch.setenv("B2_REGION", "us-west-004")
    monkeypatch.setenv("B2_ASSETS_BUCKET", "firemark-assets")
    monkeypatch.setenv("B2_ASSETS_KEY_ID", "assets-key-id")
    monkeypatch.setenv("B2_ASSETS_APPLICATION_KEY", "assets-application-key")
    monkeypatch.setenv("B2_VAULT_BUCKET", "firemark-vault")
    monkeypatch.setenv("B2_VAULT_KEY_ID", "vault-key-id")
    monkeypatch.setenv("B2_VAULT_APP_KEY", "vault-legacy-alias-key")
    monkeypatch.setenv("FIREMARK_VAULT_RETENTION_DAYS", "90")
    monkeypatch.setenv("B2_ENDPOINT_URL", "https://ignored.invalid")
    monkeypatch.setenv("B2_REGION_NAME", "ignored-region")

    settings = load_settings()
    assert settings.b2_endpoint == "https://s3.us-west-004.backblazeb2.com"
    assert settings.b2_region == "us-west-004"
    complete = settings.require_complete_b2_config()
    assert complete.assets.bucket == "firemark-assets"
    assert complete.vault.bucket == "firemark-vault"
    assert complete.assets.app_key.get_secret_value() == "assets-application-key"
    assert complete.vault.app_key.get_secret_value() == "vault-legacy-alias-key"


def test_noncanonical_b2_names_are_not_settings_fields() -> None:
    from api.firemark import settings as settings_module

    assert "B2_ENDPOINT_URL" not in settings_module._ENVIRONMENT_FIELDS
    assert "B2_REGION_NAME" not in settings_module._ENVIRONMENT_FIELDS
    assert settings_module._ENVIRONMENT_FIELDS["B2_ENDPOINT"] == "b2_endpoint"
    assert settings_module._ENVIRONMENT_FIELDS["B2_REGION"] == "b2_region"
    assert settings_module._ENVIRONMENT_ALIASES["b2_assets_app_key"] == (
        "B2_ASSETS_APPLICATION_KEY",
        "B2_ASSETS_APP_KEY",
    )
    assert settings_module._ENVIRONMENT_ALIASES["b2_vault_app_key"] == (
        "B2_VAULT_APPLICATION_KEY",
        "B2_VAULT_APP_KEY",
    )
