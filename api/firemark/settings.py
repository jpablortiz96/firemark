"""Application settings loaded explicitly from the process environment."""

from __future__ import annotations

import os
from typing import Literal

from pydantic import BaseModel, ConfigDict, SecretStr, field_validator

Environment = Literal["local", "test", "staging", "production"]


class Settings(BaseModel):
    """Typed configuration without import-time credential requirements."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: Environment = "local"
    base_url: str | None = None
    signing_key: SecretStr | None = None
    public_key: str | None = None
    signer_key_id: str | None = None
    b2_key_id: SecretStr | None = None
    b2_app_key: SecretStr | None = None
    b2_region: str | None = None
    b2_endpoint: str | None = None
    b2_assets_bucket: str | None = None
    b2_vault_bucket: str | None = None
    supabase_url: str | None = None
    supabase_service_role_key: SecretStr | None = None
    gmi_api_key: SecretStr | None = None
    elevenlabs_api_key: SecretStr | None = None
    replicate_api_token: SecretStr | None = None

    @field_validator("environment", mode="before")
    @classmethod
    def validate_environment(cls, value: object) -> object:
        """Reject unsupported deployment environments with a clear error."""
        allowed = {"local", "test", "staging", "production"}
        if not isinstance(value, str) or value not in allowed:
            choices = ", ".join(sorted(allowed))
            raise ValueError(f"FIREMARK_ENV must be one of: {choices}")
        return value


_ENVIRONMENT_FIELDS = {
    "FIREMARK_ENV": "environment",
    "FIREMARK_BASE_URL": "base_url",
    "FIREMARK_SIGNING_KEY": "signing_key",
    "FIREMARK_PUBLIC_KEY": "public_key",
    "FIREMARK_SIGNER_KEY_ID": "signer_key_id",
    "B2_KEY_ID": "b2_key_id",
    "B2_APP_KEY": "b2_app_key",
    "B2_REGION": "b2_region",
    "B2_ENDPOINT": "b2_endpoint",
    "B2_ASSETS_BUCKET": "b2_assets_bucket",
    "B2_VAULT_BUCKET": "b2_vault_bucket",
    "SUPABASE_URL": "supabase_url",
    "SUPABASE_SERVICE_ROLE_KEY": "supabase_service_role_key",
    "GMI_API_KEY": "gmi_api_key",
    "ELEVENLABS_API_KEY": "elevenlabs_api_key",
    "REPLICATE_API_TOKEN": "replicate_api_token",
}


def load_settings() -> Settings:
    """Build settings from environment variables without network access."""
    values = {
        field_name: value
        for environment_name, field_name in _ENVIRONMENT_FIELDS.items()
        if (value := os.getenv(environment_name)) is not None
    }
    return Settings.model_validate(values)
