"""Tests for explicit, credential-optional settings loading."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from api.firemark.settings import Settings, classify_supabase_key, load_settings

ENVIRONMENT_VARIABLES = (
    "FIREMARK_ENV",
    "FIREMARK_REPOSITORY_BACKEND",
    "FIREMARK_ALLOWED_ORIGINS",
    "FIREMARK_BASE_URL",
    "FIREMARK_SIGNING_KEY",
    "FIREMARK_PUBLIC_KEY",
    "FIREMARK_SIGNING_KEY_FILE",
    "FIREMARK_PUBLIC_KEY_FILE",
    "FIREMARK_SIGNER_KEY_ID",
    "B2_KEY_ID",
    "B2_APP_KEY",
    "B2_ENDPOINT",
    "B2_REGION",
    "B2_ASSETS_BUCKET",
    "B2_ASSETS_KEY_ID",
    "B2_ASSETS_APP_KEY",
    "B2_VAULT_BUCKET",
    "B2_VAULT_KEY_ID",
    "B2_VAULT_APP_KEY",
    "FIREMARK_VAULT_RETENTION_DAYS",
    "FIREMARK_PRESIGNED_URL_TTL_SECONDS",
    "SUPABASE_URL",
    "SUPABASE_PUBLISHABLE_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "FIREMARK_PUBLIC_BASE_URL",
    "FIREMARK_DELIVERY_TTL_SECONDS",
    "FIREMARK_ADMIN_API_KEY",
    "FIREMARK_DELIVERY_API_KEY",
    "FIREMARK_SIGNING_PRIVATE_KEY_B64",
    "FIREMARK_SIGNING_PUBLIC_KEY_B64",
    "OPENAI_API_KEY",
    "OPENAI_IMAGE_MODEL",
    "OPENAI_IMAGE_SIZE",
    "FIREMARK_GENERATION_TIMEOUT_SECONDS",
    "FIREMARK_MAX_GENERATED_IMAGE_BYTES",
    "GMI_API_KEY",
    "ELEVENLABS_API_KEY",
    "REPLICATE_API_TOKEN",
)


@pytest.fixture(autouse=True)
def clear_firemark_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable_name in ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(variable_name, raising=False)


def complete_values() -> dict[str, object]:
    return {
        "b2_endpoint": "https://s3.test.invalid/",
        "b2_region": " test-region ",
        "b2_assets_bucket": "assets-test",
        "b2_assets_key_id": "assets-key-id",
        "b2_assets_app_key": "assets-app-key",
        "b2_vault_bucket": "vault-test",
        "b2_vault_key_id": "vault-key-id",
        "b2_vault_app_key": "vault-app-key",
        "vault_retention_days": 90,
        "presigned_url_ttl_seconds": 300,
    }


def legacy_supabase_jwt(role: str) -> str:
    def encode(value: dict[str, str]) -> str:
        data = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    return f"{encode({'alg': 'HS256', 'typ': 'JWT'})}.{encode({'role': role})}.test-signature"


def test_defaults_allow_zero_network_imports_without_credentials() -> None:
    settings = load_settings()
    assert settings.environment == "local"
    assert settings.b2_assets_app_key is None
    assert settings.vault_retention_days is None
    assert settings.presigned_url_ttl_seconds == 300
    assert settings.allowed_origins == (
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    )


def test_allowed_origins_load_as_strict_normalized_json_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "FIREMARK_ALLOWED_ORIGINS",
        '["https://app.firemark.test/", "http://localhost:3100"]',
    )
    assert load_settings().allowed_origins == (
        "https://app.firemark.test",
        "http://localhost:3100",
    )


@pytest.mark.parametrize(
    "origins",
    [
        "https://app.firemark.test",
        '["*"]',
        '["http://app.firemark.test"]',
        '["https://user:secret@app.firemark.test"]',
        '["https://app.firemark.test/path"]',
        '["https://app.firemark.test?private=value"]',
        '["https://app.firemark.test:invalid"]',
    ],
)
def test_allowed_origins_reject_unsafe_or_non_list_values(origins: str) -> None:
    with pytest.raises(ValidationError, match="FIREMARK_ALLOWED_ORIGINS"):
        Settings(allowed_origins=origins)  # type: ignore[arg-type]


def test_complete_separate_assets_and_vault_configuration() -> None:
    settings = Settings.model_validate(complete_values())
    complete = settings.require_complete_b2_config()
    assert complete.assets.endpoint == "https://s3.test.invalid"
    assert complete.assets.region == "test-region"
    assert complete.assets.bucket == "assets-test"
    assert complete.vault.bucket == "vault-test"
    assert complete.vault.retention_days == 90


def test_environment_loader_uses_new_separate_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    values = complete_values()
    mapping = {
        "B2_ENDPOINT": values["b2_endpoint"],
        "B2_REGION": values["b2_region"],
        "B2_ASSETS_BUCKET": values["b2_assets_bucket"],
        "B2_ASSETS_KEY_ID": values["b2_assets_key_id"],
        "B2_ASSETS_APP_KEY": values["b2_assets_app_key"],
        "B2_VAULT_BUCKET": values["b2_vault_bucket"],
        "B2_VAULT_KEY_ID": values["b2_vault_key_id"],
        "B2_VAULT_APP_KEY": values["b2_vault_app_key"],
        "FIREMARK_VAULT_RETENTION_DAYS": "90",
    }
    for name, value in mapping.items():
        monkeypatch.setenv(name, str(value))
    assert load_settings().require_complete_b2_config().vault.retention_days == 90


@pytest.mark.parametrize(
    "values",
    [
        {"b2_assets_bucket": "assets-test"},
        {"b2_assets_bucket": "assets-test", "b2_assets_key_id": "key"},
        {"b2_vault_bucket": "vault-test", "b2_vault_app_key": "secret"},
    ],
)
def test_partial_credential_groups_are_rejected(values: dict[str, str]) -> None:
    with pytest.raises(ValidationError, match="must be complete"):
        Settings.model_validate(values)


def test_helpers_reject_missing_shared_or_retention_configuration() -> None:
    values = complete_values()
    values.pop("b2_endpoint")
    settings = Settings.model_validate(values)
    with pytest.raises(ValueError, match="assets"):
        settings.require_assets_b2_config()
    with pytest.raises(ValueError, match="vault"):
        settings.require_vault_b2_config()


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://s3.test.invalid",
        "https://",
        "https://user:password@s3.test.invalid",
        "https://s3.test.invalid/path",
        "https://s3.test.invalid?query=yes",
        "https://s3.test.invalid#fragment",
    ],
)
def test_endpoint_is_strict_https_origin(endpoint: str) -> None:
    with pytest.raises(ValidationError, match="B2_ENDPOINT"):
        Settings(b2_endpoint=endpoint)


def test_same_bucket_and_invalid_bucket_names_are_rejected() -> None:
    values = complete_values()
    values["b2_vault_bucket"] = values["b2_assets_bucket"]
    with pytest.raises(ValidationError, match="must be different"):
        Settings.model_validate(values)
    with pytest.raises(ValidationError, match="bucket names"):
        Settings(b2_assets_bucket="bad")

    values = complete_values()
    values["b2_vault_key_id"] = values["b2_assets_key_id"]
    with pytest.raises(ValidationError, match="different key IDs"):
        Settings.model_validate(values)


@pytest.mark.parametrize("value", [0, 3651, True])
def test_retention_bounds(value: object) -> None:
    with pytest.raises(ValidationError, match="between 1 and 3650"):
        Settings(vault_retention_days=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [59, 901, True])
def test_presigned_ttl_bounds(value: object) -> None:
    with pytest.raises(ValidationError, match="between 60 and 900"):
        Settings(presigned_url_ttl_seconds=value)  # type: ignore[arg-type]


def test_all_b2_credentials_are_redacted_from_repr() -> None:
    assets_secret = "clearly-labeled-assets-test-secret"
    vault_secret = "clearly-labeled-vault-test-secret"
    settings = Settings(
        b2_assets_bucket="assets-test",
        b2_assets_key_id=assets_secret,
        b2_assets_app_key=assets_secret,
        b2_vault_bucket="vault-test",
        b2_vault_key_id=vault_secret,
        b2_vault_app_key=vault_secret,
    )
    assert isinstance(settings.b2_assets_app_key, SecretStr)
    assert isinstance(settings.b2_vault_app_key, SecretStr)
    assert assets_secret not in repr(settings)
    assert vault_secret not in repr(settings)
    assert "**********" in repr(settings)


def test_legacy_generic_b2_environment_variables_are_not_applied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("B2_KEY_ID", "legacy-key")
    monkeypatch.setenv("B2_APP_KEY", "legacy-secret")
    settings = load_settings()
    assert settings.b2_assets_key_id is None
    assert "legacy-secret" not in repr(settings)


def test_complete_live_supabase_configuration_is_explicit_and_separated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SUPABASE_URL", "https://project.supabase.co")
    monkeypatch.setenv("SUPABASE_PUBLISHABLE_KEY", "sb_publishable_test-value")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "sb_secret_test-value")
    monkeypatch.setenv("FIREMARK_PUBLIC_BASE_URL", "https://verify.firemark.test")
    monkeypatch.setenv("FIREMARK_DELIVERY_TTL_SECONDS", "300")
    config = load_settings().require_live_supabase_control_plane_config()
    assert config.publishable_key == "sb_publishable_test-value"
    assert config.service_role_key.get_secret_value() == "sb_secret_test-value"
    assert config.delivery_ttl_seconds == 300
    assert "sb_secret_test-value" not in repr(config)


@pytest.mark.parametrize(
    ("value", "family"),
    [
        ("sb_publishable_test-value", "SB_PUBLISHABLE"),
        ("sb_secret_test-value", "SB_SECRET"),
        (legacy_supabase_jwt("anon"), "LEGACY_ANON_JWT"),
        (legacy_supabase_jwt("service_role"), "LEGACY_SERVICE_ROLE_JWT"),
        (legacy_supabase_jwt("authenticated"), "UNKNOWN"),
        ("unknown-key-family", "UNKNOWN"),
    ],
)
def test_supabase_key_families_are_classified_intentionally(value: str, family: str) -> None:
    assert classify_supabase_key(value) == family


def test_legacy_anon_and_service_role_pair_remains_supported() -> None:
    config = Settings(
        supabase_url="https://project.supabase.co",
        supabase_publishable_key=legacy_supabase_jwt("anon"),
        supabase_service_role_key=legacy_supabase_jwt("service_role"),
        public_base_url="https://firemark.local",
        delivery_ttl_seconds=300,
    ).require_live_supabase_control_plane_config()
    assert classify_supabase_key(config.publishable_key) == "LEGACY_ANON_JWT"
    assert classify_supabase_key(config.service_role_key.get_secret_value()) == (
        "LEGACY_SERVICE_ROLE_JWT"
    )
    assert config.public_base_url == "https://firemark.local"


def test_live_supabase_configuration_rejects_missing_explicit_values() -> None:
    settings = Settings(
        supabase_url="https://project.supabase.co",
        supabase_publishable_key="sb_publishable_test-value",
        supabase_service_role_key="sb_secret_test-value",
        public_base_url="https://verify.firemark.test",
    )
    with pytest.raises(ValueError, match="Complete live Supabase"):
        settings.require_live_supabase_control_plane_config()


def test_live_supabase_configuration_rejects_identical_or_confused_keys() -> None:
    common = {
        "supabase_url": "https://project.supabase.co",
        "public_base_url": "https://verify.firemark.test",
        "delivery_ttl_seconds": 300,
    }
    with pytest.raises(ValueError, match="must be different"):
        Settings(
            **common,
            supabase_publishable_key="same-key",
            supabase_service_role_key="same-key",
        ).require_live_supabase_control_plane_config()
    with pytest.raises(ValueError, match="unsupported key family"):
        Settings(
            **common,
            supabase_publishable_key="not-a-publishable-key",
            supabase_service_role_key="sb_secret_test-value",
        ).require_live_supabase_control_plane_config()
    with pytest.raises(ValueError, match="unsupported backend key family"):
        Settings(
            **common,
            supabase_publishable_key="sb_publishable_test-value",
            supabase_service_role_key="legacy-secret",
        ).require_live_supabase_control_plane_config()
    with pytest.raises(ValueError, match="unsupported key family"):
        Settings(
            **common,
            supabase_publishable_key=legacy_supabase_jwt("service_role"),
            supabase_service_role_key="sb_secret_test-value",
        ).require_live_supabase_control_plane_config()
    with pytest.raises(ValueError, match="unsupported backend key family"):
        Settings(
            **common,
            supabase_publishable_key="sb_publishable_test-value",
            supabase_service_role_key=legacy_supabase_jwt("anon"),
        ).require_live_supabase_control_plane_config()


def test_environment_and_signing_configuration_remain_supported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FIREMARK_ENV", "production")
    private_path = tmp_path / "not-read-private.b64"
    monkeypatch.setenv("FIREMARK_SIGNING_KEY_FILE", str(private_path))
    settings = load_settings()
    assert settings.environment == "production"
    assert settings.require_private_key_source() == private_path

    with pytest.raises(ValueError, match="Exactly one"):
        Settings().require_private_key_source()
    with pytest.raises(ValidationError, match="only one"):
        Settings(signing_key="test", signing_key_file=private_path)
    with pytest.raises(ValidationError, match="FIREMARK_ENV"):
        Settings(environment="development")  # type: ignore[arg-type]


def test_openai_only_configuration_requires_no_other_live_dependency() -> None:
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        Settings().require_openai_image_config()
    config = Settings(
        openai_api_key="test-openai-key",
        openai_image_model="gpt-image-test",
        openai_image_size="1024x1024",
        generation_timeout_seconds=45,
        max_generated_image_bytes=2 * 1024 * 1024,
    ).require_openai_image_config()
    assert config.api_key.get_secret_value() == "test-openai-key"
    assert config.model == "gpt-image-test"
    assert config.size == "1024x1024"
    assert config.timeout_seconds == 45
    assert config.max_image_bytes == 2 * 1024 * 1024
