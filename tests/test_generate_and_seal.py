"""Zero-network Generate & Seal orchestration tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from api.firemark.control_plane.memory_repository import MemoryCertificateRepository
from api.firemark.control_plane.repository import RepositoryError
from api.firemark.control_plane.service import CertificateService
from api.firemark.custody import B2CustodyReceipt, LockedObjectReceipt, StoredObjectReceipt
from api.firemark.generate_and_seal import (
    GenerateAndSealError,
    GenerateAndSealRequest,
    GenerateAndSealService,
    IdempotencyConflictError,
)
from api.firemark.generation.fake_provider import _TINY_PNG, FakeGenerationProvider
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.provider import GenerationProviderError
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import extract_public_capsule_png
from api.firemark.seal_envelope import verify_signed_envelope
from api.firemark.signer import Ed25519Signer

NOW = datetime(2026, 7, 30, 15, tzinfo=UTC)
IDEMPOTENCY_KEY = "test-idempotency-key-0001"
PROMPT = "private prompt that must remain inside provenance"


class Harness:
    def __init__(self, repository: MemoryCertificateRepository | None = None) -> None:
        self.repository = repository or MemoryCertificateRepository()
        self.certificate_service = CertificateService(
            self.repository, public_base_url="https://verify.firemark.test"
        )
        self.provider = FakeGenerationProvider()
        self.signer = Ed25519Signer.generate()
        self.events: list[str] = []
        self.manifest_bytes = b""
        self.source_bytes = b""
        self.sealed_bytes = b""
        self.custody_verified = True
        self.custody_version = True
        self.sealed_version = True

    def provider_factory(self) -> FakeGenerationProvider:
        harness = self

        class ObservedFake(FakeGenerationProvider):
            def generate_image(self, request: GenerationRequest) -> GeneratedImage:
                harness.events.append("provider")
                return harness.provider.generate_image(request)

        return ObservedFake()

    def custody(self, **kwargs: Any) -> B2CustodyReceipt:
        self.events.append("custody")
        source_path: Path = kwargs["source_path"]
        self.source_bytes = source_path.read_bytes()
        self.manifest_bytes = kwargs["manifest_bytes"]
        source_hash = kwargs["source_sha256"]
        canonical = kwargs["canonical_hash"]
        retention = kwargs["retention_until"]
        manifest_hash = sha256_bytes(self.manifest_bytes)
        assets_source = StoredObjectReceipt(
            bucket="assets-test",
            key=f"assets/{source_hash}.png",
            sha256=source_hash,
            content_type="image/png",
            size_bytes=len(self.source_bytes),
            version_id="source-version",
            created_at=NOW,
        )
        assets_manifest = StoredObjectReceipt(
            bucket="assets-test",
            key=f"manifests/{canonical}.json",
            sha256=manifest_hash,
            content_type="application/json",
            size_bytes=len(self.manifest_bytes),
            version_id="manifest-version",
            created_at=NOW,
        )
        vault_source = LockedObjectReceipt(
            **assets_source.model_dump(exclude={"bucket", "key", "version_id"}),
            bucket="vault-test",
            key=f"vault/sources/{source_hash}.png",
            version_id="vault-source-version" if self.custody_version else None,
            retention_until=retention,
        )
        vault_manifest = LockedObjectReceipt(
            **assets_manifest.model_dump(exclude={"bucket", "key", "version_id"}),
            bucket="vault-test",
            key=f"vault/manifests/{canonical}.json",
            version_id="vault-manifest-version" if self.custody_version else None,
            retention_until=retention,
        )
        return B2CustodyReceipt(
            source_sha256=source_hash,
            canonical_hash=canonical,
            assets_source=assets_source,
            assets_manifest=assets_manifest,
            vault_source=vault_source,
            vault_manifest=vault_manifest,
            requested_retention_until=retention,
            created_at=NOW,
            custody_verified=self.custody_verified,
        )

    def upload(self, client: object, **kwargs: Any) -> StoredObjectReceipt:
        del client
        self.events.append("sealed_upload")
        self.sealed_bytes = kwargs["data"]
        assert kwargs["expected_sha256"] == sha256_bytes(self.sealed_bytes)
        assert kwargs["metadata"] == {
            "firemark-kind": "sealed",
            "firemark-schema": "1",
            "firemark-cert-id": extract_public_capsule_png(self.sealed_bytes).cert_id,
        }
        return StoredObjectReceipt(
            bucket=kwargs["bucket"],
            key=kwargs["key"],
            sha256=kwargs["expected_sha256"],
            content_type="image/png",
            size_bytes=len(self.sealed_bytes),
            version_id="sealed-version" if self.sealed_version else None,
            created_at=NOW,
        )

    def service(self, **updates: Any) -> GenerateAndSealService:
        values: dict[str, Any] = {
            "certificate_service": self.certificate_service,
            "provider_factory": self.provider_factory,
            "signer_factory": lambda: self.signer,
            "assets_client_factory": lambda: object(),
            "vault_client_factory": lambda: object(),
            "assets_bucket": "assets-test",
            "vault_bucket": "vault-test",
            "retention_days": 90,
            "public_base_url": "https://verify.firemark.test",
            "default_model": "fake-model",
            "default_size": "1024x1024",
            "max_generated_image_bytes": 1024 * 1024,
            "generation_timeout_seconds": 30,
            "allow_local_fixture": True,
            "custody_executor": self.custody,
            "sealed_uploader": self.upload,
            "now": lambda: NOW,
        }
        values.update(updates)
        return GenerateAndSealService(**values)


def test_complete_sequence_hash_order_privacy_signature_and_idempotency() -> None:
    harness = Harness()
    service = harness.service()
    request = GenerateAndSealRequest(prompt=PROMPT)
    first = service.generate_and_seal(request, idempotency_key=IDEMPOTENCY_KEY)
    second = service.generate_and_seal(request, idempotency_key=IDEMPOTENCY_KEY)
    assert first == second
    assert harness.provider.calls == 1
    assert harness.events == ["provider", "custody", "sealed_upload"]
    assert harness.source_bytes == _TINY_PNG
    assert sha256_bytes(harness.source_bytes) == first.source_sha256
    assert harness.sealed_bytes != harness.source_bytes
    assert sha256_bytes(harness.sealed_bytes) == first.sealed_sha256
    assert PROMPT.encode() in harness.manifest_bytes
    assert PROMPT.encode() not in harness.sealed_bytes
    capsule = extract_public_capsule_png(harness.sealed_bytes)
    assert capsule.source_sha256 == first.source_sha256
    assert capsule.canonical_hash == first.canonical_hash
    assert "sealed_sha256" not in capsule.model_dump()
    certificate = harness.repository.get_certificate(first.cert_id)
    assert certificate is not None
    assert certificate.asset is not None
    assert certificate.asset.assets_key.startswith(
        f"sealed/{first.sealed_sha256[:2]}/{first.sealed_sha256[2:4]}/"
    )
    assert certificate.asset.vault_key.startswith("vault/sources/")
    assert verify_signed_envelope(
        certificate.signed_envelope, certificate.signer_public_key_b64
    )
    assert harness.certificate_service.verify(
        __import__(
            "api.firemark.control_plane.models", fromlist=["VerificationRequest"]
        ).VerificationRequest(cert_id=first.cert_id, presented_sha256=first.sealed_sha256),
        now=NOW,
    ).verified


def test_conflicting_idempotency_key_is_rejected_before_another_generation() -> None:
    harness = Harness()
    service = harness.service()
    service.generate_and_seal(
        GenerateAndSealRequest(prompt="first private prompt"),
        idempotency_key=IDEMPOTENCY_KEY,
    )
    with pytest.raises(IdempotencyConflictError):
        service.generate_and_seal(
            GenerateAndSealRequest(prompt="different private prompt"),
            idempotency_key=IDEMPOTENCY_KEY,
        )
    assert harness.provider.calls == 1


def test_invalid_idempotency_fake_production_and_size_fail_before_custody() -> None:
    harness = Harness()
    with pytest.raises(GenerateAndSealError, match="INVALID_IDEMPOTENCY_KEY"):
        harness.service().generate_and_seal(
            GenerateAndSealRequest(prompt=PROMPT), idempotency_key="short"
        )
    with pytest.raises(GenerateAndSealError, match="NON_PRODUCTION_PROVIDER"):
        harness.service(allow_local_fixture=False).generate_and_seal(
            GenerateAndSealRequest(prompt=PROMPT), idempotency_key=IDEMPOTENCY_KEY
        )
    with pytest.raises(GenerateAndSealError, match="TOO_LARGE"):
        harness.service(max_generated_image_bytes=10).generate_and_seal(
            GenerateAndSealRequest(prompt=PROMPT), idempotency_key=IDEMPOTENCY_KEY
        )
    assert "custody" not in harness.events


def test_provider_custody_and_upload_failures_create_no_certificate() -> None:
    class FailedProvider:
        def generate_image(self, request: GenerationRequest) -> GeneratedImage:
            del request
            raise GenerationProviderError("timeout")

    harness = Harness()
    with pytest.raises(GenerationProviderError):
        harness.service(provider_factory=lambda: FailedProvider()).generate_and_seal(
            GenerateAndSealRequest(prompt=PROMPT), idempotency_key=IDEMPOTENCY_KEY
        )
    assert harness.repository.get_certificate("firemark-cert-missing") is None

    def failed_custody(**kwargs: Any) -> B2CustodyReceipt:
        del kwargs
        raise RuntimeError("safe test custody failure")

    with pytest.raises(RuntimeError, match="custody"):
        harness.service(custody_executor=failed_custody).generate_and_seal(
            GenerateAndSealRequest(prompt=PROMPT), idempotency_key=IDEMPOTENCY_KEY
        )

    def failed_upload(client: object, **kwargs: Any) -> StoredObjectReceipt:
        del client, kwargs
        raise RuntimeError("safe test upload failure")

    with pytest.raises(RuntimeError, match="upload"):
        harness.service(sealed_uploader=failed_upload).generate_and_seal(
            GenerateAndSealRequest(prompt=PROMPT), idempotency_key=IDEMPOTENCY_KEY
        )


def test_unverified_or_versionless_custody_and_sealed_upload_fail_closed() -> None:
    harness = Harness()
    harness.custody_verified = False
    with pytest.raises(GenerateAndSealError, match="CUSTODY_NOT_VERIFIED"):
        harness.service().generate_and_seal(
            GenerateAndSealRequest(prompt=PROMPT), idempotency_key=IDEMPOTENCY_KEY
        )
    harness = Harness()
    harness.sealed_version = False
    with pytest.raises(GenerateAndSealError) as caught:
        harness.service().generate_and_seal(
            GenerateAndSealRequest(prompt=PROMPT), idempotency_key=IDEMPOTENCY_KEY
        )
    assert caught.value.code == "SEALED_VERSION_UNAVAILABLE"
    assert caught.value.partial_keys[0].startswith("sealed/")


def test_missing_private_signer_and_registration_failure_are_safe_and_retryable() -> None:
    harness = Harness()
    public_signer = Ed25519Signer.from_public_key_base64(
        harness.signer.export_public_key_base64()
    )
    with pytest.raises(GenerateAndSealError, match="SIGNING_KEY_UNAVAILABLE"):
        harness.service(signer_factory=lambda: public_signer).generate_and_seal(
            GenerateAndSealRequest(prompt=PROMPT), idempotency_key=IDEMPOTENCY_KEY
        )

    class FailingRepository(MemoryCertificateRepository):
        def register_certificate_bundle(self, *args: Any, **kwargs: Any) -> Any:
            del args, kwargs
            raise RepositoryError("test registration failure")

    failed = Harness(FailingRepository())
    with pytest.raises(GenerateAndSealError) as caught:
        failed.service().generate_and_seal(
            GenerateAndSealRequest(prompt=PROMPT), idempotency_key=IDEMPOTENCY_KEY
        )
    assert caught.value.code == "REGISTRATION_FAILED"
    assert len(caught.value.partial_keys) == 3


def test_custom_model_and_size_are_bound_into_private_idempotency_fingerprint() -> None:
    harness = Harness()
    result = harness.service().generate_and_seal(
        GenerateAndSealRequest(prompt=PROMPT, model="fake-custom", size="512x512"),
        idempotency_key=IDEMPOTENCY_KEY,
    )
    certificate = harness.repository.get_certificate(result.cert_id)
    assert certificate is not None
    fingerprint = harness.repository.get_generation_request_fingerprint(result.run_id)
    assert isinstance(fingerprint, str) and len(fingerprint) == 64


def test_http_request_rejects_unsafe_model_size_and_extra_private_parameters() -> None:
    with pytest.raises(ValidationError):
        GenerateAndSealRequest(prompt=PROMPT, model="unsafe model")
    with pytest.raises(ValidationError):
        GenerateAndSealRequest(prompt=PROMPT, size="999x999")
    with pytest.raises(ValidationError):
        GenerateAndSealRequest.model_validate({"prompt": PROMPT, "seed": 123})
