from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.smoke_deployed_stack as smoke


def _evidence() -> dict[str, object]:
    return {
        "schema_version": "firemark.generate-and-seal-report.v1",
        "cert_id": "firemark-cert-existing",
        "asset_id": "firemark-asset-existing",
        "run_id": "firemark-run-existing",
        "sealed_sha256": "a" * 64,
        "canonical_hash": "b" * 64,
        "source_sha256": "c" * 64,
    }


def test_non_live_mode_is_zero_network(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden_client(*args: object, **kwargs: object) -> None:
        raise AssertionError("network client constructed")

    monkeypatch.setattr(smoke.httpx, "Client", forbidden_client)
    assert smoke.main([]) == 2
    output = capsys.readouterr().out
    assert "zero network calls" in output
    assert "no OpenAI, B2, Supabase, or deployed HTTP client" in output


def test_help_lists_live_report_and_force_options(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        smoke.main(["--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--live" in output and "--output-report" in output and "--force" in output


def test_existing_certificate_report_parsing(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_evidence()), encoding="utf-8")
    evidence = smoke.load_existing_evidence(report)
    assert evidence.cert_id == "firemark-cert-existing"
    assert evidence.sealed_sha256 == "a" * 64


@pytest.mark.parametrize("change", [{"schema_version": "bad"}, {"sealed_sha256": "bad"}])
def test_existing_certificate_report_rejects_invalid_contract(
    tmp_path: Path, change: dict[str, object]
) -> None:
    value = {**_evidence(), **change}
    report = tmp_path / "report.json"
    report.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(smoke.SmokeFailure):
        smoke.load_existing_evidence(report)


def test_response_leak_detection_is_recursive_and_exact() -> None:
    assert smoke.contains_forbidden_private_fields({"public": {"prompt_private": "hidden"}})
    assert smoke.contains_forbidden_private_fields({"vault_version_id": "hidden"})
    assert not smoke.contains_forbidden_private_fields(
        {"source_sha256": "a" * 64, "public_manifest": {"provider": "openai"}}
    )
    assert smoke.text_contains_private_fields("seed_private")
    assert not smoke.text_contains_private_fields("Prompts remain private.")


def test_deployed_urls_are_never_logged_on_safe_configuration_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env_file = tmp_path / ".env"
    api_url = "https://private-api-host.example"
    web_url = "https://private-web-host.example"
    env_file.write_text(
        f"FIREMARK_DEPLOYED_API_BASE_URL={api_url}\n"
        f"FIREMARK_DEPLOYED_WEB_BASE_URL={web_url}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(smoke, "DEFAULT_ENV_FILE", env_file)
    monkeypatch.setattr(smoke, "DEFAULT_EVIDENCE_REPORT", tmp_path / "missing.json")
    assert smoke.run_live(tmp_path / "output.json", force=False) == 1
    output = capsys.readouterr().out
    assert api_url not in output and web_url not in output
    assert output == (
        "FAIL: configuration_validation CODE=DEPLOYED_STACK_CHECK_FAILED\n"
    )


def test_safe_report_writer_is_atomic_and_excludes_raw_url(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    report = {"api_hostname": "api.example", "stages": []}
    smoke._write_report(path, report, force=False)
    assert json.loads(path.read_text(encoding="utf-8")) == report
    with pytest.raises(smoke.SmokeFailure):
        smoke._write_report(path, report, force=False)
    text = path.read_text(encoding="utf-8")
    assert "download_url" not in text and "authorization" not in text
