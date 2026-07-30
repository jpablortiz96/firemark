"""Production composition root for lazy FIREMARK dependencies."""

from __future__ import annotations

from typing import Any

from api.firemark.b2_storage import create_assets_client, create_vault_client
from api.firemark.control_plane.memory_repository import MemoryCertificateRepository
from api.firemark.control_plane.repository import CertificateRepository
from api.firemark.control_plane.service import (
    B2DeliveryStorage,
    CertificateService,
    DeliveryStorage,
)
from api.firemark.control_plane.supabase_repository import SupabaseCertificateRepository
from api.firemark.generate_and_seal import GenerateAndSealService
from api.firemark.generation.openai_provider import OpenAIImageProvider
from api.firemark.runtime import FiremarkRuntime, LazyDeliveryStorage
from api.firemark.settings import Settings
from api.firemark.signer import Ed25519Signer


def _repository(settings: Settings) -> CertificateRepository:
    if settings.repository_backend == "memory":
        return MemoryCertificateRepository()
    return SupabaseCertificateRepository.from_config(settings.require_supabase_config())


def build_runtime(
    settings: Settings,
    *,
    repository: CertificateRepository | None = None,
    storage: DeliveryStorage | None = None,
    generate_and_seal_service: GenerateAndSealService | None = None,
    production_overrides: dict[str, Any] | None = None,
) -> FiremarkRuntime:
    """Compose injected or lazy production dependencies without a network request."""
    selected_repository = repository or _repository(settings)
    complete_b2 = None
    try:
        complete_b2 = settings.require_complete_b2_config()
    except ValueError:
        pass
    selected_storage = storage
    if selected_storage is None and complete_b2 is not None:
        selected_storage = LazyDeliveryStorage(
            lambda: B2DeliveryStorage(create_assets_client(complete_b2.assets))
        )
    certificate_service = CertificateService(
        selected_repository,
        public_base_url=settings.public_base_url or "https://firemark.invalid",
        storage=selected_storage,
        delivery_ttl_seconds=settings.delivery_ttl_seconds,
    )
    generation_service = generate_and_seal_service
    if generation_service is None:
        try:
            config = settings.require_generate_and_seal_config()
        except ValueError:
            config = None
        if config is not None:
            overrides = dict(production_overrides or {})
            generation_service = GenerateAndSealService(
                certificate_service=certificate_service,
                provider_factory=overrides.pop(
                    "provider_factory",
                    lambda: OpenAIImageProvider(
                        api_key=config.openai_api_key.get_secret_value(),
                        timeout_seconds=config.generation_timeout_seconds,
                        max_image_bytes=config.max_generated_image_bytes,
                    ),
                ),
                signer_factory=overrides.pop(
                    "signer_factory",
                    lambda: Ed25519Signer.from_private_key_base64(
                        config.signing_private_key_b64.get_secret_value(),
                        config.signing_public_key_b64,
                    ),
                ),
                assets_client_factory=overrides.pop(
                    "assets_client_factory", lambda: create_assets_client(config.b2.assets)
                ),
                vault_client_factory=overrides.pop(
                    "vault_client_factory", lambda: create_vault_client(config.b2.vault)
                ),
                assets_bucket=config.b2.assets.bucket,
                vault_bucket=config.b2.vault.bucket,
                retention_days=config.b2.vault.retention_days,
                public_base_url=config.public_base_url,
                default_model=config.openai_image_model,
                default_size=config.openai_image_size,
                max_generated_image_bytes=config.max_generated_image_bytes,
                generation_timeout_seconds=config.generation_timeout_seconds,
                **overrides,
            )
    return FiremarkRuntime(
        settings=settings,
        repository=selected_repository,
        certificate_service=certificate_service,
        generate_and_seal_service=generation_service,
    )
