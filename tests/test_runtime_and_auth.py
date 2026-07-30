"""Production composition and constant-time API authentication tests."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from api.firemark.api import auth
from api.firemark.app import create_app
from api.firemark.bootstrap import build_runtime
from api.firemark.control_plane.memory_repository import MemoryCertificateRepository
from api.firemark.control_plane.supabase_repository import SupabaseCertificateRepository
from api.firemark.generate_and_seal import (
    GenerateAndSealError,
    GenerateAndSealResult,
    IdempotencyConflictError,
)
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.runtime import LazyDeliveryStorage
from api.firemark.settings import Settings, load_settings
from api.firemark.signer import Ed25519Signer

ADMIN = "test-only-admin-api-key-value"
DELIVERY = "test-only-delivery-api-key-value"


def signing_values() -> tuple[str, str]:
    signer = Ed25519Signer.generate()
    return (
        signer.export_private_key_base64_for_provisioning(),
        signer.export_public_key_base64(),
    )


def production_settings() -> Settings:
    private, public = signing_values()
    return Settings(
        environment="production",
        repository_backend="supabase",
        admin_api_key=ADMIN,
        delivery_api_key=DELIVERY,
        signing_private_key_b64=private,
        signing_public_key_b64=public,
        openai_api_key="test-only-openai-key",
        openai_image_model="gpt-image-test",
        openai_image_size="1024x1024",
        generation_timeout_seconds=30,
        max_generated_image_bytes=2 * 1024 * 1024,
        b2_endpoint="https://s3.test.invalid",
        b2_region="test-region",
        b2_assets_bucket="assets-test",
        b2_assets_key_id="assets-key-id",
        b2_assets_app_key="assets-app-key",
        b2_vault_bucket="vault-test",
        b2_vault_key_id="vault-key-id",
        b2_vault_app_key="vault-app-key",
        vault_retention_days=90,
        supabase_url="https://project.supabase.co",
        supabase_service_role_key="sb_secret_test-value",
        public_base_url="https://verify.firemark.test",
        delivery_ttl_seconds=300,
    )


def test_repository_selection_is_explicit_and_factory_constructs_no_clients() -> None:
    configured_but_memory = build_runtime(
        Settings(
            supabase_url="https://project.supabase.co",
            supabase_service_role_key="sb_secret_test-value",
        )
    )
    assert isinstance(configured_but_memory.repository, MemoryCertificateRepository)
    supabase = build_runtime(
        Settings(
            repository_backend="supabase",
            supabase_url="https://project.supabase.co",
            supabase_service_role_key="sb_secret_test-value",
        )
    )
    assert isinstance(supabase.repository, SupabaseCertificateRepository)
    assert supabase.generate_and_seal_service is None

    calls: list[str] = []
    complete = build_runtime(
        production_settings(),
        production_overrides={
            "provider_factory": lambda: calls.append("provider"),
            "signer_factory": lambda: calls.append("signer"),
            "assets_client_factory": lambda: calls.append("assets"),
            "vault_client_factory": lambda: calls.append("vault"),
        },
    )
    assert complete.generate_and_seal_service is not None
    assert calls == []


def test_production_configuration_derives_public_key_and_redacts_all_secrets() -> None:
    private, _ = signing_values()
    settings = production_settings().model_copy(
        update={"signing_private_key_b64": SecretStr(private), "signing_public_key_b64": None}
    )
    config = Settings.model_validate(settings.model_dump()).require_generate_and_seal_config()
    derived = Ed25519Signer.from_private_key_base64(private).export_public_key_base64()
    assert config.signing_public_key_b64 == derived
    rendered = repr(config)
    for secret in (ADMIN, DELIVERY, private, "test-only-openai-key", "assets-app-key"):
        assert secret not in rendered
    assert isinstance(config.admin_api_key, SecretStr)
    assert isinstance(config.signing_private_key_b64, SecretStr)


def test_signing_mismatch_and_generation_bounds_fail_closed() -> None:
    first_private, _ = signing_values()
    _, other_public = signing_values()
    with pytest.raises(ValidationError, match="mismatched"):
        Settings(
            signing_private_key_b64=first_private,
            signing_public_key_b64=other_public,
        )
    for value in (4, 301, True):
        with pytest.raises(ValidationError, match="between 5 and 300"):
            Settings(generation_timeout_seconds=value)  # type: ignore[arg-type]
    for value in (1024, 51 * 1024 * 1024, True):
        with pytest.raises(ValidationError, match="between 1 and 50 MiB"):
            Settings(max_generated_image_bytes=value)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="OPENAI_IMAGE_SIZE"):
        Settings(openai_image_size="unsafe")
    with pytest.raises(ValidationError, match="OPENAI_IMAGE_MODEL"):
        Settings(openai_image_model="bad model")
    with pytest.raises(ValidationError, match="must not be blank"):
        Settings(admin_api_key="   ")
    with pytest.raises(ValidationError, match="must be different"):
        Settings(admin_api_key=ADMIN, delivery_api_key=ADMIN)


def test_new_environment_names_load_explicitly_without_dotenv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FIREMARK_REPOSITORY_BACKEND", "memory")
    monkeypatch.setenv("FIREMARK_ADMIN_API_KEY", ADMIN)
    monkeypatch.setenv("FIREMARK_DELIVERY_API_KEY", DELIVERY)
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-openai-key")
    monkeypatch.setenv("OPENAI_IMAGE_MODEL", "gpt-image-test")
    monkeypatch.setenv("OPENAI_IMAGE_SIZE", "512x512")
    monkeypatch.setenv("FIREMARK_GENERATION_TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("FIREMARK_MAX_GENERATED_IMAGE_BYTES", str(3 * 1024 * 1024))
    loaded = load_settings()
    assert loaded.repository_backend == "memory"
    assert loaded.admin_api_key is not None
    assert loaded.openai_image_model == "gpt-image-test"
    assert loaded.openai_image_size == "512x512"
    assert loaded.generation_timeout_seconds == 45


def test_lazy_delivery_storage_constructs_once_on_first_issue() -> None:
    calls: list[str] = []

    class Storage:
        def issue_download(self, asset: object, *, ttl_seconds: int) -> tuple[object, int]:
            return asset, ttl_seconds

    lazy = LazyDeliveryStorage(lambda: calls.append("constructed") or Storage())
    asset = object()
    assert lazy.issue_download(asset, ttl_seconds=60) == (asset, 60)
    assert lazy.issue_download(asset, ttl_seconds=120) == (asset, 120)
    assert calls == ["constructed"]


class StubGenerationService:
    def __init__(self) -> None:
        self.calls = 0

    def generate_and_seal(self, request: object, *, idempotency_key: str) -> GenerateAndSealResult:
        del request, idempotency_key
        self.calls += 1
        return GenerateAndSealResult.model_validate(
            {
                "run_id": "firemark-run-test",
                "asset_id": "firemark-asset-test",
                "cert_id": "firemark-cert-test",
                "source_sha256": "1" * 64,
                "sealed_sha256": "2" * 64,
                "canonical_hash": "3" * 64,
                "certificate_url": "https://verify.firemark.test/v1/certificates/firemark-cert-test",
                "verify_url": "https://verify.firemark.test/v1/certificates/firemark-cert-test",
            }
        )


def test_generate_auth_missing_invalid_valid_and_secret_absence_from_logs(caplog: Any) -> None:
    service = StubGenerationService()
    app = create_app(
        Settings(admin_api_key=ADMIN),
        generate_and_seal_service=service,  # type: ignore[arg-type]
    )
    client = TestClient(app)
    payload = {"prompt": "private prompt"}
    missing = client.post(
        "/v1/generate-and-seal", json=payload, headers={"Idempotency-Key": "test-key-0001"}
    )
    invalid = client.post(
        "/v1/generate-and-seal",
        json=payload,
        headers={"Idempotency-Key": "test-key-0001", "Authorization": "Bearer wrong"},
    )
    with caplog.at_level(logging.INFO, logger="firemark.api"):
        valid = client.post(
            "/v1/generate-and-seal",
            json=payload,
            headers={
                "Idempotency-Key": "test-key-0001",
                "Authorization": f"Bearer {ADMIN}",
            },
        )
    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert valid.status_code == 201
    assert service.calls == 1
    assert ADMIN not in caplog.text
    assert "private prompt" not in valid.text


def test_constant_time_compare_path_and_unconfigured_generation_are_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []
    real_compare = auth.hmac.compare_digest

    def observed(left: str, right: str) -> bool:
        calls.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(auth.hmac, "compare_digest", observed)
    client = TestClient(create_app(Settings(admin_api_key=ADMIN)))
    response = client.post(
        "/v1/generate-and-seal",
        json={"prompt": "private prompt"},
        headers={
            "Idempotency-Key": "test-key-0001",
            "Authorization": f"Bearer {ADMIN}",
        },
    )
    assert calls == [(ADMIN, ADMIN)]
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "GENERATION_NOT_CONFIGURED"


def test_configured_key_missing_at_runtime_and_non_bearer_are_safe() -> None:
    client = TestClient(create_app(Settings()))
    headers = {"Idempotency-Key": "test-key-0001", "Authorization": "Bearer supplied"}
    unavailable = client.post(
        "/v1/generate-and-seal", json={"prompt": "private"}, headers=headers
    )
    basic = client.post(
        "/v1/generate-and-seal",
        json={"prompt": "private"},
        headers={"Idempotency-Key": "test-key-0001", "Authorization": "Basic value"},
    )
    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "AUTHENTICATION_UNAVAILABLE"
    assert basic.status_code == 401


@pytest.mark.parametrize(
    ("failure", "status", "code"),
    [
        (IdempotencyConflictError(), 409, "IDEMPOTENCY_CONFLICT"),
        (GenerationProviderError("timeout"), 502, "PROVIDER_TIMEOUT"),
        (GenerateAndSealError("CUSTODY_NOT_VERIFIED"), 503, "CUSTODY_NOT_VERIFIED"),
    ],
)
def test_generate_route_normalizes_domain_failures(
    failure: Exception, status: int, code: str
) -> None:
    class FailingService:
        def generate_and_seal(self, request: object, *, idempotency_key: str) -> object:
            del request, idempotency_key
            raise failure

    client = TestClient(
        create_app(
            Settings(admin_api_key=ADMIN),
            generate_and_seal_service=FailingService(),  # type: ignore[arg-type]
        )
    )
    response = client.post(
        "/v1/generate-and-seal",
        json={"prompt": "private prompt"},
        headers={
            "Idempotency-Key": "test-key-0001",
            "Authorization": f"Bearer {ADMIN}",
        },
    )
    assert response.status_code == status
    assert response.json()["error"]["code"] == code


def test_generate_route_maps_invalid_idempotency_to_validation_error() -> None:
    class Service:
        def generate_and_seal(self, request: object, *, idempotency_key: str) -> object:
            del request, idempotency_key
            raise GenerateAndSealError("INVALID_IDEMPOTENCY_KEY")

    client = TestClient(
        create_app(
            Settings(admin_api_key=ADMIN),
            generate_and_seal_service=Service(),  # type: ignore[arg-type]
        )
    )
    response = client.post(
        "/v1/generate-and-seal",
        json={"prompt": "private"},
        headers={"Idempotency-Key": "bad", "Authorization": f"Bearer {ADMIN}"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_IDEMPOTENCY_KEY"
