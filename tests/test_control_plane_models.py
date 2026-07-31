"""Closed model and settings contracts for the Control Plane."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from api.firemark.control_plane.models import (
    AssetRecord,
    DeliveryAuthorization,
    PublicCertificate,
    VerificationRequest,
)
from api.firemark.settings import Settings, load_settings
from tests.control_plane_helpers import build_evidence, registered_service


def test_models_are_frozen_forbid_extra_and_validate_hashes() -> None:
    evidence = build_evidence()
    with pytest.raises(ValidationError):
        AssetRecord.model_validate({**evidence.asset.model_dump(), "unknown": True})
    with pytest.raises(ValidationError):
        evidence.asset.source_sha256 = "0" * 64  # type: ignore[misc]
    with pytest.raises(ValidationError):
        VerificationRequest(cert_id="firemark-cert-1", presented_sha256="ABC")
    with pytest.raises(ValidationError):
        DeliveryAuthorization(presented_sha256="0" * 63)
    with pytest.raises(ValidationError):
        AssetRecord.model_validate(
            {**evidence.asset.model_dump(), "sealed_sha256": evidence.asset.source_sha256}
        )


def test_public_certificate_has_only_safe_fields_and_utc_time() -> None:
    service, _, _ = registered_service()
    certificate = service.get_public_certificate("firemark-cert-1")
    assert isinstance(certificate, PublicCertificate)
    payload = certificate.model_dump(mode="json")
    assert set(payload) == {
            "schema_version", "cert_id", "asset_id", "run_id", "provider", "model",
            "provider_model_name",
            "media_type", "mime_type", "byte_size", "ai_generated", "width", "height",
            "duration_ms", "source_sha256", "sealed_sha256",
        "canonical_hash", "signer_key_id", "signer_public_key_b64", "signature_b64",
        "public_manifest", "certificate_status", "issued_at", "verify_url",
    }
    assert not {"prompt_private", "parameters_private", "seed_private"} & payload.keys()
    assert certificate.issued_at.utcoffset().total_seconds() == 0
    with pytest.raises(ValidationError):
        PublicCertificate.model_validate({**payload, "issued_at": datetime(2026, 1, 1)})


def test_supabase_settings_are_complete_https_redacted_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        supabase_url="https://project.supabase.co/",
        supabase_service_role_key="service-secret",
        public_base_url="https://verify.firemark.test/",
        delivery_ttl_seconds="60",  # type: ignore[arg-type]
    )
    config = settings.require_supabase_config()
    assert config.url == "https://project.supabase.co"
    assert "service-secret" not in repr(settings)
    assert "service-secret" not in repr(config)
    assert settings.delivery_ttl_seconds == 60
    monkeypatch.setenv("SUPABASE_URL", "https://project.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "environment-secret")
    monkeypatch.setenv("FIREMARK_PUBLIC_BASE_URL", "https://verify.firemark.test")
    monkeypatch.setenv("FIREMARK_DELIVERY_TTL_SECONDS", "900")
    loaded = load_settings()
    assert loaded.delivery_ttl_seconds == 900
    assert loaded.require_supabase_config().service_role_key.get_secret_value() == "environment-secret"


@pytest.mark.parametrize("values", [
    {"supabase_url": "https://project.supabase.co"},
    {"supabase_service_role_key": "secret"},
])
def test_partial_supabase_configuration_is_rejected(values: dict[str, str]) -> None:
    with pytest.raises(ValidationError, match="configured together"):
        Settings(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["supabase_url", "public_base_url"])
def test_external_urls_require_https_origins(field: str) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: "http://example.test"})
    with pytest.raises(ValidationError):
        Settings(**{field: "https://user:pass@example.test/path?secret=x"})


@pytest.mark.parametrize("value", [59, 901, True, "bad"])
def test_delivery_ttl_bounds(value: object) -> None:
    with pytest.raises(ValidationError):
        Settings(delivery_ttl_seconds=value)  # type: ignore[arg-type]


def test_missing_supabase_configuration_helper_fails() -> None:
    with pytest.raises(ValueError, match="Complete Supabase"):
        Settings().require_supabase_config()
