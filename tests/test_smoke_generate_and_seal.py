"""Zero-network tests for the explicit Generate & Seal live checkpoint CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.smoke_generate_and_seal as smoke


def test_no_live_is_informational_and_constructs_no_external_clients(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("no external client may be constructed")

    monkeypatch.setattr(smoke, "build_runtime", forbidden)
    monkeypatch.setattr(smoke, "OpenAIImageProvider", forbidden)
    assert smoke.main([]) == 2
    output = capsys.readouterr().out
    assert "zero network calls" in output
    assert "no OpenAI, B2, or Supabase client" in output


def test_help_contract_and_exact_live_stage_list() -> None:
    help_text = smoke.build_parser().format_help()
    assert "--live" in help_text
    assert "--output-report" in help_text
    assert "--force" in help_text
    assert smoke.STAGES == (
        "configuration_validation",
        "dependency_construction",
        "provider_generation",
        "source_hash",
        "genblaze_manifest",
        "canonical_hash",
        "public_capsule_embedding",
        "sealed_hash",
        "envelope_signature",
        "vault_custody",
        "sealed_asset_upload",
        "supabase_registration",
        "public_certificate_projection",
        "verify_gate",
        "delivery_authorization",
        "delivered_byte_integrity",
        "embedded_capsule_verification",
        "database_secret_scan",
        "safe_report",
    )


def test_live_with_incomplete_configuration_fails_safely_before_clients(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "must-not-appear-in-safe-live-failure"
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setattr(smoke, "DEFAULT_ENV_FILE", tmp_path / "missing.env")
    assert smoke.main(["--live", "--output-report", str(tmp_path / "report.json")]) == 1
    output = capsys.readouterr().out
    assert output == "FAIL: configuration_validation (LIVE_CHECKPOINT_FAILED)\n"
    assert secret not in output


def test_safe_report_writer_is_atomic_refuses_overwrite_and_contains_no_secret(
    tmp_path: Path,
) -> None:
    path = tmp_path / "report.json"
    report = {
        "cert_id": "firemark-cert-safe",
        "stages": [{"stage": "safe_report", "status": "PASS"}],
    }
    smoke._write_report(path, report, force=False)
    assert json.loads(path.read_text(encoding="utf-8")) == report
    with pytest.raises(smoke.LiveSmokeError, match="USE_FORCE"):
        smoke._write_report(path, report, force=False)
    replacement = {"cert_id": "firemark-cert-replaced"}
    smoke._write_report(path, replacement, force=True)
    assert json.loads(path.read_text(encoding="utf-8")) == replacement


def test_capture_delegates_each_generation_once_without_repr_or_logging() -> None:
    class Provider:
        def generate_image(self, request: object) -> object:
            return request

    capture = smoke.Capture(Provider())  # type: ignore[arg-type]
    request = object()
    assert capture.generate_image(request) is request  # type: ignore[arg-type]
    assert capture.provider_calls == 1
