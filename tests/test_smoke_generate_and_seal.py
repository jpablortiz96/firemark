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
        "provider_request_construction",
        "provider_generation",
        "provider_response_validation",
        "source_hash",
        "genblaze_manifest",
        "canonical_hash",
        "public_capsule_embedding",
        "sealed_hash",
        "vault_source_upload",
        "vault_source_hash_verification",
        "vault_source_retention_verification",
        "vault_manifest_upload",
        "vault_manifest_hash_verification",
        "vault_manifest_retention_readback",
        "vault_manifest_retention_validation",
        "checkpoint_after_vault_manifest",
        "sealed_asset_upload",
        "sealed_asset_hash_verification",
        "custody_receipt_construction",
        "envelope_signature",
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
    assert output == (
        "FAIL: configuration_validation "
        "(CATEGORY=CONFIGURATION_ERROR, EXCEPTION_CLASS=ValueError)\n"
    )
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
        def build_request_parameters(self, request: object) -> dict[str, object]:
            return {"request": request}

        def construct_client(self) -> object:
            return object()

        def request_image(self, client: object, parameters: object) -> object:
            del client
            return parameters

        def validate_response(self, response: object, request: object) -> object:
            del response
            return request

    capture = smoke.Capture(Provider())  # type: ignore[arg-type]
    request = object()
    assert capture.generate_image(request) is request  # type: ignore[arg-type]
    assert capture.provider_calls == 1


def test_full_smoke_failure_keeps_exact_provider_stage_and_safe_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from types import SimpleNamespace

    from pydantic import SecretStr

    from api.firemark.generation.provider import GenerationProviderError

    config = SimpleNamespace(
        openai_api_key=SecretStr("private-openai-value"),
        generation_timeout_seconds=30,
        max_generated_image_bytes=1024 * 1024,
        b2=SimpleNamespace(assets=object(), vault=object()),
    )
    settings = SimpleNamespace(
        require_generate_and_seal_config=lambda: config,
        require_live_supabase_control_plane_config=lambda: object(),
    )

    class Service:
        def __init__(self, callback: object) -> None:
            self.callback = callback

        def generate_and_seal(self, request: object, *, idempotency_key: str) -> None:
            del request, idempotency_key
            self.callback("provider_request_construction")  # type: ignore[operator]
            self.callback("provider_generation")  # type: ignore[operator]
            raise GenerationProviderError("authentication")

    def fake_runtime(incoming: object, *, production_overrides: dict[str, object]) -> object:
        assert incoming is settings
        return SimpleNamespace(
            generate_and_seal_service=Service(production_overrides["stage_callback"])
        )

    monkeypatch.setattr(smoke, "DEFAULT_ENV_FILE", tmp_path / "missing.env")
    monkeypatch.setattr(smoke, "load_settings", lambda: settings)
    monkeypatch.setattr(smoke, "build_runtime", fake_runtime)
    assert smoke.run_live(tmp_path / "report.json", force=False) == 1
    output = capsys.readouterr().out
    assert "PASS: configuration_validation" in output
    assert "PASS: dependency_construction" in output
    assert "PASS: provider_request_construction" in output
    assert output.endswith(
        "FAIL: provider_generation "
        "(CATEGORY=AUTHENTICATION_FAILURE, PROVIDER_CODE=authentication)\n"
    )
    assert "private-openai-value" not in output


def test_full_smoke_preserves_exact_b2_stage_category_and_partial_versions(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from api.firemark.custody import B2CustodyWorkflowError, PartialB2Object

    tracker = smoke.StageTracker()
    tracker.begin("dependency_construction")
    error = B2CustodyWorkflowError(
        "private raw service failure",
        stage="vault_manifest_hash_verification",
        category="HASH_MISMATCH",
        service_error_code="BadDigest",
        bucket_role="vault",
        object_kind="manifest",
        partial_objects=(
            PartialB2Object(
                "vault",
                "source",
                "vault/sources/safe.png",
                "source-version-exact",
                True,
            ),
        ),
    )
    tracker.fail(error)
    output = capsys.readouterr().out
    assert "FAIL: vault_manifest_hash_verification" in output
    assert "CATEGORY=HASH_MISMATCH" in output
    assert "B2_CODE=BadDigest" in output
    assert "VERSION_ID=source-version-exact" in output
    assert "private raw service failure" not in output


def test_checkpoint_failure_reports_exact_safe_stage_type_without_raw_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from api.firemark.generate_checkpoint import CheckpointSerializationError

    tracker = smoke.StageTracker()
    tracker.begin("checkpoint_after_vault_manifest")
    secret = "must-not-appear-in-checkpoint-diagnostic"
    error = CheckpointSerializationError(
        stage="checkpoint_after_vault_manifest",
        field_path="$.vault_manifest.retention_until",
        value_type="UnsupportedSecret",
    )
    error.__cause__ = ValueError(secret)
    tracker.fail(error)
    output = capsys.readouterr().out
    assert output.endswith(
        "FAIL: checkpoint_after_vault_manifest "
        "(CATEGORY=CHECKPOINT_SERIALIZATION_ERROR, "
        "EXCEPTION_CLASS=CheckpointSerializationError, "
        "FIELD_PATH=$.vault_manifest.retention_until, "
        "VALUE_TYPE=UnsupportedSecret)\n"
    )
    assert secret not in output


def test_local_retention_validation_failure_has_exact_stage_and_allowlisted_class(
    capsys: pytest.CaptureFixture[str],
) -> None:
    tracker = smoke.StageTracker()
    tracker.begin("vault_manifest_retention_validation")
    tracker.fail(ValueError("private validation detail"))
    output = capsys.readouterr().out
    assert output.endswith(
        "FAIL: vault_manifest_retention_validation "
        "(CATEGORY=LOCAL_VALIDATION_ERROR, EXCEPTION_CLASS=ValueError)\n"
    )
    assert "private validation detail" not in output
