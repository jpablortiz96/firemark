"""Tests for explicit, credential-optional settings loading."""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from api.firemark.settings import Settings, load_settings

ENVIRONMENT_VARIABLES = (
    "FIREMARK_ENV",
    "FIREMARK_BASE_URL",
    "FIREMARK_SIGNING_KEY",
    "FIREMARK_PUBLIC_KEY",
    "FIREMARK_SIGNER_KEY_ID",
    "B2_KEY_ID",
    "B2_APP_KEY",
    "B2_REGION",
    "B2_ENDPOINT",
    "B2_ASSETS_BUCKET",
    "B2_VAULT_BUCKET",
    "SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
    "GMI_API_KEY",
    "ELEVENLABS_API_KEY",
    "REPLICATE_API_TOKEN",
)


@pytest.fixture(autouse=True)
def clear_firemark_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate settings tests from credentials in the developer environment."""
    for variable_name in ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(variable_name, raising=False)


def test_default_environment_is_local() -> None:
    settings = load_settings()

    assert settings.environment == "local"


def test_production_environment_is_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREMARK_ENV", "production")

    settings = load_settings()

    assert settings.environment == "production"


def test_invalid_environment_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREMARK_ENV", "development")

    with pytest.raises(ValidationError, match="FIREMARK_ENV must be one of"):
        load_settings()


def test_secrets_use_secret_str_and_are_redacted() -> None:
    secret_value = "test-only-secret"
    settings = Settings(
        signing_key=secret_value,
        b2_key_id=secret_value,
        b2_app_key=secret_value,
        supabase_service_role_key=secret_value,
        gmi_api_key=secret_value,
        elevenlabs_api_key=secret_value,
        replicate_api_token=secret_value,
    )

    assert isinstance(settings.signing_key, SecretStr)
    assert isinstance(settings.b2_key_id, SecretStr)
    assert isinstance(settings.b2_app_key, SecretStr)
    assert isinstance(settings.supabase_service_role_key, SecretStr)
    assert isinstance(settings.gmi_api_key, SecretStr)
    assert isinstance(settings.elevenlabs_api_key, SecretStr)
    assert isinstance(settings.replicate_api_token, SecretStr)
    assert secret_value not in repr(settings)
    assert "**********" in repr(settings)


def test_loading_without_external_credentials_succeeds() -> None:
    settings = load_settings()

    assert settings.signing_key is None
    assert settings.b2_app_key is None
    assert settings.supabase_service_role_key is None
    assert settings.gmi_api_key is None
    assert settings.elevenlabs_api_key is None
    assert settings.replicate_api_token is None
