"""Application settings loaded explicitly from the process environment."""

from __future__ import annotations

import hmac
import os
import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, SecretStr, field_validator, model_validator

Environment = Literal["local", "test", "staging", "production"]
_BUCKET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{4,48}[A-Za-z0-9]$")


class B2AssetsConfig(BaseModel):
    """Complete private assets-bucket configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str
    region: str
    bucket: str
    key_id: SecretStr
    app_key: SecretStr
    presigned_url_ttl_seconds: int


class B2VaultConfig(BaseModel):
    """Complete private vault-bucket configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str
    region: str
    bucket: str
    key_id: SecretStr
    app_key: SecretStr
    retention_days: int


class CompleteB2Config(BaseModel):
    """Separated assets and vault configuration required for live custody."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    assets: B2AssetsConfig
    vault: B2VaultConfig


class SupabaseConfig(BaseModel):
    """Complete server-side Supabase configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    service_role_key: SecretStr


class LiveSupabaseControlPlaneConfig(BaseModel):
    """Complete, separated configuration for the explicit live Supabase checkpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    publishable_key: str
    service_role_key: SecretStr
    public_base_url: str
    delivery_ttl_seconds: int


class Settings(BaseModel):
    """Typed configuration without import-time credential requirements."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: Environment = "local"
    base_url: str | None = None
    signing_key: SecretStr | None = None
    public_key: str | None = None
    signing_key_file: Path | None = None
    public_key_file: Path | None = None
    signer_key_id: str | None = None
    b2_endpoint: str | None = None
    b2_region: str | None = None
    b2_assets_bucket: str | None = None
    b2_assets_key_id: SecretStr | None = None
    b2_assets_app_key: SecretStr | None = None
    b2_vault_bucket: str | None = None
    b2_vault_key_id: SecretStr | None = None
    b2_vault_app_key: SecretStr | None = None
    vault_retention_days: int | None = None
    presigned_url_ttl_seconds: int = 300
    supabase_url: str | None = None
    supabase_publishable_key: str | None = None
    supabase_service_role_key: SecretStr | None = None
    public_base_url: str | None = None
    delivery_ttl_seconds: int = 300
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

    @field_validator("b2_endpoint")
    @classmethod
    def validate_endpoint(cls, value: str | None) -> str | None:
        """Require an origin-only HTTPS endpoint and remove one trailing slash."""
        if value is None:
            return None
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("B2_ENDPOINT must be an HTTPS URL with a hostname")
        if parsed.username or parsed.password:
            raise ValueError("B2_ENDPOINT must not contain user information")
        if parsed.query or parsed.fragment:
            raise ValueError("B2_ENDPOINT must not contain a query string or fragment")
        if parsed.path not in ("", "/"):
            raise ValueError("B2_ENDPOINT must not contain a path")
        return urlunsplit(("https", parsed.netloc, "", "", ""))

    @field_validator("supabase_url", "public_base_url")
    @classmethod
    def validate_external_url(cls, value: str | None) -> str | None:
        """Require credential-free HTTPS origins for external control-plane URLs."""
        if value is None:
            return None
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("External control-plane URLs must use HTTPS")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("External control-plane URLs must not contain credentials or metadata")
        if parsed.path not in ("", "/"):
            raise ValueError("External control-plane URLs must be origins without a path")
        return urlunsplit(("https", parsed.netloc, "", "", ""))

    @field_validator("b2_region")
    @classmethod
    def validate_region(cls, value: str | None) -> str | None:
        """Normalize and validate the configured B2 region."""
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("B2_REGION must not be blank")
        return normalized

    @field_validator("b2_assets_bucket", "b2_vault_bucket")
    @classmethod
    def validate_bucket(cls, value: str | None) -> str | None:
        """Require a conservative Backblaze-compatible bucket name."""
        if value is not None and not _BUCKET_PATTERN.fullmatch(value):
            raise ValueError("B2 bucket names must be 6-50 letters, digits, or hyphens")
        return value

    @field_validator("vault_retention_days", mode="before")
    @classmethod
    def validate_retention_days(cls, value: object) -> object:
        """Bound explicitly configured retention to 1 through 3650 days."""
        if value is None:
            return None
        if isinstance(value, bool):
            raise ValueError("FIREMARK_VAULT_RETENTION_DAYS must be between 1 and 3650")
        try:
            parsed = int(value) if isinstance(value, (int, str)) else -1
        except ValueError as exc:
            raise ValueError(
                "FIREMARK_VAULT_RETENTION_DAYS must be between 1 and 3650"
            ) from exc
        if not 1 <= parsed <= 3650:
            raise ValueError("FIREMARK_VAULT_RETENTION_DAYS must be between 1 and 3650")
        return parsed

    @field_validator("presigned_url_ttl_seconds", mode="before")
    @classmethod
    def validate_presigned_ttl(cls, value: object) -> object:
        """Bound private download URLs to 60 through 900 seconds."""
        if isinstance(value, bool):
            raise ValueError("FIREMARK_PRESIGNED_URL_TTL_SECONDS must be between 60 and 900")
        try:
            parsed = int(value) if isinstance(value, (int, str)) else -1
        except ValueError as exc:
            raise ValueError(
                "FIREMARK_PRESIGNED_URL_TTL_SECONDS must be between 60 and 900"
            ) from exc
        if not 60 <= parsed <= 900:
            raise ValueError("FIREMARK_PRESIGNED_URL_TTL_SECONDS must be between 60 and 900")
        return parsed

    @field_validator("delivery_ttl_seconds", mode="before")
    @classmethod
    def validate_delivery_ttl(cls, value: object) -> object:
        """Bound Verify Gate delivery grants to 60 through 900 seconds."""
        if isinstance(value, bool):
            raise ValueError("FIREMARK_DELIVERY_TTL_SECONDS must be between 60 and 900")
        try:
            parsed = int(value) if isinstance(value, (int, str)) else -1
        except ValueError as exc:
            raise ValueError(
                "FIREMARK_DELIVERY_TTL_SECONDS must be between 60 and 900"
            ) from exc
        if not 60 <= parsed <= 900:
            raise ValueError("FIREMARK_DELIVERY_TTL_SECONDS must be between 60 and 900")
        return parsed

    @model_validator(mode="after")
    def reject_ambiguous_configuration(self) -> Settings:
        """Reject conflicting key sources and partial B2 credential groups."""
        if self.signing_key is not None and self.signing_key_file is not None:
            raise ValueError("Configure only one private signing key source")
        if self.public_key is not None and self.public_key_file is not None:
            raise ValueError("Configure only one public signing key source")
        if (self.supabase_url is None) != (self.supabase_service_role_key is None):
            raise ValueError("Supabase URL and service-role key must be configured together")

        assets = (self.b2_assets_bucket, self.b2_assets_key_id, self.b2_assets_app_key)
        vault = (self.b2_vault_bucket, self.b2_vault_key_id, self.b2_vault_app_key)
        if any(value is not None for value in assets) and not all(
            value is not None for value in assets
        ):
            raise ValueError("Assets B2 bucket, key ID, and application key must be complete")
        if any(value is not None for value in vault) and not all(
            value is not None for value in vault
        ):
            raise ValueError("Vault B2 bucket, key ID, and application key must be complete")
        if self.b2_assets_bucket is not None and self.b2_assets_bucket == self.b2_vault_bucket:
            raise ValueError("Assets and vault buckets must be different")
        if (
            self.b2_assets_key_id is not None
            and self.b2_vault_key_id is not None
            and self.b2_assets_key_id.get_secret_value()
            == self.b2_vault_key_id.get_secret_value()
        ):
            raise ValueError("Assets and vault credentials must use different key IDs")
        return self

    def require_private_key_source(self) -> SecretStr | Path:
        """Return the sole private key source or fail for production startup."""
        if self.signing_key is not None:
            return self.signing_key
        if self.signing_key_file is not None:
            return self.signing_key_file
        raise ValueError("Exactly one private signing key source is required")

    def require_assets_b2_config(self) -> B2AssetsConfig:
        """Return complete assets configuration or fail before client construction."""
        values = (
            self.b2_endpoint,
            self.b2_region,
            self.b2_assets_bucket,
            self.b2_assets_key_id,
            self.b2_assets_app_key,
        )
        if any(value is None for value in values):
            raise ValueError("Complete assets B2 configuration is required")
        assert self.b2_endpoint is not None
        assert self.b2_region is not None
        assert self.b2_assets_bucket is not None
        assert self.b2_assets_key_id is not None
        assert self.b2_assets_app_key is not None
        return B2AssetsConfig(
            endpoint=self.b2_endpoint,
            region=self.b2_region,
            bucket=self.b2_assets_bucket,
            key_id=self.b2_assets_key_id,
            app_key=self.b2_assets_app_key,
            presigned_url_ttl_seconds=self.presigned_url_ttl_seconds,
        )

    def require_vault_b2_config(self) -> B2VaultConfig:
        """Return complete vault configuration with explicit retention."""
        values = (
            self.b2_endpoint,
            self.b2_region,
            self.b2_vault_bucket,
            self.b2_vault_key_id,
            self.b2_vault_app_key,
            self.vault_retention_days,
        )
        if any(value is None for value in values):
            raise ValueError("Complete vault B2 configuration and retention are required")
        assert self.b2_endpoint is not None
        assert self.b2_region is not None
        assert self.b2_vault_bucket is not None
        assert self.b2_vault_key_id is not None
        assert self.b2_vault_app_key is not None
        assert self.vault_retention_days is not None
        return B2VaultConfig(
            endpoint=self.b2_endpoint,
            region=self.b2_region,
            bucket=self.b2_vault_bucket,
            key_id=self.b2_vault_key_id,
            app_key=self.b2_vault_app_key,
            retention_days=self.vault_retention_days,
        )

    def require_complete_b2_config(self) -> CompleteB2Config:
        """Return both separately scoped configurations."""
        return CompleteB2Config(
            assets=self.require_assets_b2_config(),
            vault=self.require_vault_b2_config(),
        )

    def require_supabase_config(self) -> SupabaseConfig:
        """Return complete Supabase configuration or fail before client construction."""
        if self.supabase_url is None or self.supabase_service_role_key is None:
            raise ValueError("Complete Supabase configuration is required")
        return SupabaseConfig(
            url=self.supabase_url,
            service_role_key=self.supabase_service_role_key,
        )

    def require_live_supabase_control_plane_config(
        self,
    ) -> LiveSupabaseControlPlaneConfig:
        """Return complete, deliberately separated live-checkpoint configuration."""
        values = (
            self.supabase_url,
            self.supabase_publishable_key,
            self.supabase_service_role_key,
            self.public_base_url,
        )
        if any(value is None for value in values) or (
            "delivery_ttl_seconds" not in self.model_fields_set
        ):
            raise ValueError("Complete live Supabase Control Plane configuration is required")
        assert self.supabase_url is not None
        assert self.supabase_publishable_key is not None
        assert self.supabase_service_role_key is not None
        assert self.public_base_url is not None
        service_key = self.supabase_service_role_key.get_secret_value()
        if hmac.compare_digest(self.supabase_publishable_key, service_key):
            raise ValueError("Supabase publishable and backend secret keys must be different")
        if not self.supabase_publishable_key.startswith("sb_publishable_"):
            raise ValueError("SUPABASE_PUBLISHABLE_KEY must be a publishable key")
        if not service_key.startswith("sb_secret_"):
            raise ValueError("SUPABASE_SERVICE_ROLE_KEY must be an sb_secret_ backend key")
        return LiveSupabaseControlPlaneConfig(
            url=self.supabase_url,
            publishable_key=self.supabase_publishable_key,
            service_role_key=self.supabase_service_role_key,
            public_base_url=self.public_base_url,
            delivery_ttl_seconds=self.delivery_ttl_seconds,
        )


_ENVIRONMENT_FIELDS = {
    "FIREMARK_ENV": "environment",
    "FIREMARK_BASE_URL": "base_url",
    "FIREMARK_SIGNING_KEY": "signing_key",
    "FIREMARK_PUBLIC_KEY": "public_key",
    "FIREMARK_SIGNING_KEY_FILE": "signing_key_file",
    "FIREMARK_PUBLIC_KEY_FILE": "public_key_file",
    "FIREMARK_SIGNER_KEY_ID": "signer_key_id",
    "B2_ENDPOINT": "b2_endpoint",
    "B2_REGION": "b2_region",
    "B2_ASSETS_BUCKET": "b2_assets_bucket",
    "B2_ASSETS_KEY_ID": "b2_assets_key_id",
    "B2_ASSETS_APP_KEY": "b2_assets_app_key",
    "B2_VAULT_BUCKET": "b2_vault_bucket",
    "B2_VAULT_KEY_ID": "b2_vault_key_id",
    "B2_VAULT_APP_KEY": "b2_vault_app_key",
    "FIREMARK_VAULT_RETENTION_DAYS": "vault_retention_days",
    "FIREMARK_PRESIGNED_URL_TTL_SECONDS": "presigned_url_ttl_seconds",
    "SUPABASE_URL": "supabase_url",
    "SUPABASE_PUBLISHABLE_KEY": "supabase_publishable_key",
    "SUPABASE_SERVICE_ROLE_KEY": "supabase_service_role_key",
    "FIREMARK_PUBLIC_BASE_URL": "public_base_url",
    "FIREMARK_DELIVERY_TTL_SECONDS": "delivery_ttl_seconds",
    "GMI_API_KEY": "gmi_api_key",
    "ELEVENLABS_API_KEY": "elevenlabs_api_key",
    "REPLICATE_API_TOKEN": "replicate_api_token",
}


def load_settings() -> Settings:
    """Build settings from environment variables without network access."""
    values = {
        field_name: value
        for environment_name, field_name in _ENVIRONMENT_FIELDS.items()
        if (value := os.getenv(environment_name)) not in (None, "")
    }
    return Settings.model_validate(values)
