from __future__ import annotations

from pathlib import Path

import pytest

import scripts.check_production_readiness as readiness


def _valid_environment() -> dict[str, str]:
    return {
        "FIREMARK_REPOSITORY_BACKEND": "supabase",
        "FIREMARK_ADMIN_API_KEY": "admin-test-value",
        "FIREMARK_DELIVERY_API_KEY": "delivery-test-value",
        "FIREMARK_SIGNING_PRIVATE_KEY_B64": "private-test-value",
        "FIREMARK_SIGNING_PUBLIC_KEY_B64": "public-test-value",
        "FIREMARK_PUBLIC_BASE_URL": "https://firemark.example",
        "FIREMARK_ALLOWED_ORIGINS": '["https://firemark.example"]',
        "FIREMARK_DELIVERY_TTL_SECONDS": "300",
        "FIREMARK_GENERATION_TIMEOUT_SECONDS": "120",
        "FIREMARK_MAX_GENERATED_IMAGE_BYTES": "20971520",
        "FIREMARK_MAX_GENERATED_AUDIO_BYTES": "52428800",
        "FIREMARK_VAULT_RETENTION_DAYS": "90",
        "FIREMARK_PRESIGNED_URL_TTL_SECONDS": "300",
        "OPENAI_API_KEY": "openai-test-value",
        "OPENAI_IMAGE_MODEL": "gpt-image-1.5",
        "OPENAI_IMAGE_SIZE": "1024x1024",
        "GEMINI_API_KEY": "gemini-test-value",
        "GEMINI_IMAGE_MODEL": "gemini-3.1-flash-image",
        "ELEVENLABS_API_KEY": "eleven-test-value",
        "ELEVENLABS_VOICE_ID": "voice-test",
        "ELEVENLABS_MODEL_ID": "eleven_multilingual_v2",
        "SUPABASE_URL": "https://project.supabase.co",
        "SUPABASE_PUBLISHABLE_KEY": "sb_publishable_test",
        "SUPABASE_SERVICE_ROLE_KEY": "sb_secret_test",
        "B2_ENDPOINT": "https://s3.example.test",
        "B2_REGION": "us-east-1",
        "B2_ASSETS_BUCKET": "firemark-assets",
        "B2_ASSETS_KEY_ID": "assets-key-id",
        "B2_ASSETS_APPLICATION_KEY": "assets-app-key",
        "B2_VAULT_BUCKET": "firemark-vault",
        "B2_VAULT_KEY_ID": "vault-key-id",
        "B2_VAULT_APPLICATION_KEY": "vault-app-key",
        "NEXT_PUBLIC_FIREMARK_API_BASE_URL": "https://api.firemark.example",
        "FIREMARK_PUBLIC_SITE_URL": "https://firemark.example",
    }


@pytest.fixture
def valid_environment(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    monkeypatch.setattr(
        readiness.Ed25519Signer,
        "from_private_key_base64",
        staticmethod(lambda private, public: object()),
    )
    return _valid_environment()


def _statuses(checks: list[readiness.FieldCheck]) -> dict[tuple[str, str], str]:
    return {(check.scope, check.name): check.status for check in checks}


def test_complete_production_inventory_is_valid(valid_environment: dict[str, str]) -> None:
    checks = readiness.evaluate_readiness(valid_environment)
    assert all(check.status == "VALID" for check in checks)
    assert {check.name for check in checks if check.scope == "BACKEND"} == set(
        readiness.BACKEND_FIELDS
    )
    assert {check.name for check in checks if check.scope == "FRONTEND"} == set(
        readiness.FRONTEND_FIELDS
    )


def test_missing_variables_are_reported_without_values() -> None:
    checks = readiness.evaluate_readiness({})
    assert all(check.status == "MISSING" for check in checks)


def test_mismatched_frontend_delivery_key_is_invalid(
    valid_environment: dict[str, str],
) -> None:
    frontend = dict(valid_environment)
    frontend["FIREMARK_DELIVERY_API_KEY"] = "different-delivery-test-value"
    statuses = _statuses(readiness.evaluate_readiness(valid_environment, frontend))
    assert statuses[("BACKEND", "FIREMARK_DELIVERY_API_KEY")] == "INVALID"
    assert statuses[("FRONTEND", "FIREMARK_DELIVERY_API_KEY")] == "INVALID"


@pytest.mark.parametrize(
    "origins",
    ["not-json", "[]", '["*"]', '["http://firemark.example"]'],
)
def test_invalid_and_wildcard_origins_are_rejected(
    valid_environment: dict[str, str], origins: str
) -> None:
    valid_environment["FIREMARK_ALLOWED_ORIGINS"] = origins
    statuses = _statuses(readiness.evaluate_readiness(valid_environment))
    assert statuses[("BACKEND", "FIREMARK_ALLOWED_ORIGINS")] == "INVALID"


def test_legacy_b2_application_key_names_remain_accepted(
    valid_environment: dict[str, str],
) -> None:
    valid_environment["B2_ASSETS_APP_KEY"] = valid_environment.pop(
        "B2_ASSETS_APPLICATION_KEY"
    )
    valid_environment["B2_VAULT_APP_KEY"] = valid_environment.pop(
        "B2_VAULT_APPLICATION_KEY"
    )
    assert all(
        check.status == "VALID" for check in readiness.evaluate_readiness(valid_environment)
    )


def test_load_environment_explicitly_reads_requested_dotenv(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("FIREMARK_REPOSITORY_BACKEND=supabase\n", encoding="utf-8")
    assert readiness.load_environment(env_file) == {
        "FIREMARK_REPOSITORY_BACKEND": "supabase"
    }
    assert readiness.load_environment(tmp_path / "missing") == {}


def test_readiness_output_contains_statuses_but_no_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "must-not-appear-in-readiness-output"
    monkeypatch.setattr(readiness, "load_environment", lambda: {"OPENAI_API_KEY": secret})
    assert readiness.main() == 1
    output = capsys.readouterr().out
    assert secret not in output
    assert "BACKEND.OPENAI_API_KEY=VALID" in output


def test_deployment_files_enforce_container_and_ci_contracts() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    railway = (root / "railway.toml").read_text(encoding="utf-8")
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "FROM python:3.12-slim" in dockerfile
    assert "USER firemark" in dockerfile
    assert "COPY ." not in dockerfile
    assert ".env" in dockerignore and ".artifacts" in dockerignore and "tests" in dockerignore
    assert "${PORT}" in dockerfile and 'healthcheckPath = "/healthz"' in railway
    for gate in (
        "pip check",
        "python -m pytest",
        "--cov-fail-under=95",
        "ruff check",
        "mypy api scripts",
        "npm ci",
        "npm run lint",
        "npm run typecheck",
        "npm run test",
        "npm run build",
    ):
        assert gate in workflow


def test_vercel_delivery_secret_remains_server_only_and_headers_are_configured() -> None:
    root = Path(__file__).resolve().parents[1]
    route = (root / "web/src/app/api/delivery/[certId]/route.ts").read_text(encoding="utf-8")
    config = (root / "web/next.config.ts").read_text(encoding="utf-8")
    assert "process.env.FIREMARK_DELIVERY_API_KEY" in route
    assert "NEXT_PUBLIC_FIREMARK_DELIVERY" not in route
    assert "X-Content-Type-Options" in config
    assert "Referrer-Policy" in config
    assert "Permissions-Policy" in config
    assert "frame-ancestors 'none'" in config
