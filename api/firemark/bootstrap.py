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
from api.firemark.generation.elevenlabs_provider import ElevenLabsAudioProvider
from api.firemark.generation.gemini_provider import GeminiImageProvider
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
            openai_secret = (
                config.openai_api_key.get_secret_value()
                if config.openai_api_key is not None
                else None
            )
            gemini_secret = (
                config.gemini_api_key.get_secret_value()
                if config.gemini_api_key is not None
                else None
            )
            elevenlabs_secret = (
                config.elevenlabs_api_key.get_secret_value()
                if config.elevenlabs_api_key is not None
                else None
            )
            openai_factory = (
                None
                if openai_secret is None
                else lambda: OpenAIImageProvider(
                    api_key=openai_secret,
                    timeout_seconds=config.generation_timeout_seconds,
                    max_image_bytes=config.max_generated_image_bytes,
                )
            )
            gemini_factory = (
                None
                if gemini_secret is None
                else lambda: GeminiImageProvider(
                    api_key=gemini_secret,
                    timeout_seconds=config.generation_timeout_seconds,
                    max_image_bytes=config.max_generated_image_bytes,
                )
            )
            audio_factory = (
                None
                if elevenlabs_secret is None
                else lambda: ElevenLabsAudioProvider(
                    api_key=elevenlabs_secret,
                    timeout_seconds=config.generation_timeout_seconds,
                    max_audio_bytes=config.max_generated_audio_bytes,
                )
            )
            generation_service = GenerateAndSealService(
                certificate_service=certificate_service,
                provider_factory=overrides.pop("provider_factory", openai_factory),
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
                max_generated_audio_bytes=config.max_generated_audio_bytes,
                generation_timeout_seconds=config.generation_timeout_seconds,
                gemini_provider_factory=overrides.pop(
                    "gemini_provider_factory", gemini_factory
                ),
                audio_provider_factory=overrides.pop("audio_provider_factory", audio_factory),
                default_gemini_model=config.gemini_image_model,
                default_audio_model=config.elevenlabs_model_id,
                default_audio_voice_id=config.elevenlabs_voice_id,
                **overrides,
            )
    return FiremarkRuntime(
        settings=settings,
        repository=selected_repository,
        certificate_service=certificate_service,
        generate_and_seal_service=generation_service,
    )
