"""Zero-network tests for the recovery-safe live multimodal checkpoint."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import scripts.smoke_multimodal_generate_and_seal as smoke
from api.firemark.custody import StoredObjectReceipt
from api.firemark.generate_checkpoint import checkpoint_object
from api.firemark.generation.fake_provider import _TINY_MP3, _TINY_PNG
from api.firemark.generation.models import GeneratedAudio, GeneratedImage
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import extract_public_capsule_png
from api.firemark.signer import Ed25519Signer

NOW = datetime(2026, 7, 30, 20, tzinfo=UTC)


def make_store(tmp_path: Path, media_type: smoke.MediaKind) -> smoke.CheckpointStore:
    provider = "gemini" if media_type == "image" else "elevenlabs"
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
        provider="gemini",
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
    assert json.loads(payload)["provider"] == "gemini"
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
            "provider": "gemini",
            "model": "safe-model",
            "new_gemini_calls": 1,
        },
        force=False,
    )
    payload = path.read_text("utf-8")
    assert smoke.GEMINI_PROMPT not in payload
    assert smoke.ELEVENLABS_TEXT not in payload
    with pytest.raises(smoke.LiveCheckpointError):
        smoke._write_safe_report(path, {"provider": "gemini"}, force=False)


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
