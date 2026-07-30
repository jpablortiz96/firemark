"""Certificate registration, verification, and delivery gate tests."""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest

from api.firemark.b2_storage import RedactedPresignedURL
from api.firemark.control_plane.memory_repository import MemoryCertificateRepository
from api.firemark.control_plane.models import (
    DeliveryAuthorization,
    VerificationRequest,
)
from api.firemark.control_plane.repository import (
    BundleConflictError,
    CertificateNotFoundError,
    DeliveryStorageError,
    RegistrationValidationError,
)
from api.firemark.control_plane.service import (
    AuthorizedDelivery,
    B2DeliveryStorage,
    CertificateService,
)
from tests.control_plane_helpers import (
    CANONICAL,
    NOW,
    SEALED,
    Evidence,
    build_evidence,
    register,
    registered_service,
)


class StorageStub:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, int]] = []

    def issue_download(self, asset: Any, *, ttl_seconds: int) -> RedactedPresignedURL:
        self.calls.append((asset.asset_id, ttl_seconds))
        if self.fail:
            raise RuntimeError("provider response with private details")
        return RedactedPresignedURL(
            "https://s3.example.test/private/file?X-Amz-Signature=raw-secret", ttl_seconds
        )


def _register(evidence: Evidence, **overrides: object) -> tuple[CertificateService, object]:
    repository = MemoryCertificateRepository()
    service = CertificateService(repository)
    values: dict[str, object] = {
        "generation_run": evidence.generation_run,
        "asset": evidence.asset,
        "custody": evidence.custody,
        "envelope": evidence.envelope,
        "signature_b64": evidence.signature_b64,
        "signer_public_key_b64": evidence.signer_public_key_b64,
        "public_manifest": evidence.public_manifest,
        "canonical_hash": CANONICAL,
        "cert_id": evidence.envelope.cert_id,
        "asset_id": evidence.asset.asset_id,
        "run_id": evidence.generation_run.run_id,
    }
    values.update(overrides)
    return service, service.register_certificate(**values)  # type: ignore[arg-type]


def test_valid_registration_and_identical_idempotency() -> None:
    service, repository, evidence = registered_service()
    first = service.get_public_certificate(evidence.envelope.cert_id)
    register(service, evidence)
    second = service.get_public_certificate(evidence.envelope.cert_id)
    assert first == second
    assert repository.get_certificate_by_sealed_sha256(SEALED) is not None
    assert repository.get_certificate_by_sealed_sha256("9" * 64) is None
    assert "private prompt" not in repr(repository)


def test_conflicting_duplicate_is_rejected() -> None:
    service, repository, evidence = registered_service()
    changed = evidence.asset.model_copy(update={"assets_version_id": "different"})
    existing = repository.get_certificate(evidence.envelope.cert_id)
    assert existing is not None
    with pytest.raises(BundleConflictError):
        repository.register_certificate_bundle(
            evidence.generation_run,
            changed,
            evidence.custody,
            existing.model_copy(update={"asset": changed}),
        )
    with pytest.raises(BundleConflictError):
        repository.register_certificate_bundle(
            evidence.generation_run.model_copy(update={"provider": "other"}),
            evidence.asset,
            evidence.custody,
            existing.model_copy(update={"cert_id": "other-certificate"}),
        )


def test_registration_rejects_invalid_signature_and_malformed_key() -> None:
    evidence = build_evidence()
    raw = bytearray(base64.b64decode(evidence.signature_b64))
    raw[0] ^= 1
    with pytest.raises(RegistrationValidationError, match="Signature"):
        _register(evidence, signature_b64=base64.b64encode(raw).decode())
    with pytest.raises(RegistrationValidationError, match="malformed"):
        _register(evidence, signer_public_key_b64="bad")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"canonical_hash": "9" * 64}, "canonical_hash"),
        ({"cert_id": "other-cert"}, "cert_id"),
        ({"asset_id": "other-asset"}, "asset_id"),
        ({"run_id": "other-run"}, "run_id"),
    ],
)
def test_registration_rejects_external_identifier_mismatches(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(RegistrationValidationError, match=message):
        _register(build_evidence(), **overrides)


@pytest.mark.parametrize(
    ("part", "field", "value", "message"),
    [
        ("asset", "source_sha256", "8" * 64, "source_sha256"),
        ("asset", "sealed_sha256", "8" * 64, "sealed_sha256"),
        ("generation_run", "canonical_hash", "8" * 64, "canonical_hash"),
        ("asset", "run_id", "other-run", "run_id"),
        ("custody", "asset_id", "other-asset", "asset_id"),
        ("custody", "custody_verified", False, "Custody is not verified"),
        ("custody", "retention_mode", "GOVERNANCE", "COMPLIANCE"),
        ("asset", "assets_bucket", "other-bucket", "Asset bucket"),
        ("asset", "assets_key", "other-key", "Asset key"),
        ("asset", "vault_bucket", "other-vault", "Vault bucket"),
        ("asset", "vault_key", "other-vault-key", "Vault key"),
        ("asset", "vault_version_id", "other-version", "Vault version"),
    ],
)
def test_registration_rejects_internal_relationship_mismatches(
    part: str, field: str, value: object, message: str
) -> None:
    evidence = build_evidence()
    changed = getattr(evidence, part).model_copy(update={field: value})
    evidence = replace(evidence, **{part: changed})
    with pytest.raises(RegistrationValidationError, match=message):
        _register(evidence)


def test_registration_rejects_custody_hashes_and_private_public_fields() -> None:
    evidence = build_evidence()
    bad_receipt = evidence.custody.custody_receipt.model_copy(
        update={"canonical_hash": "8" * 64}
    )
    with pytest.raises(RegistrationValidationError, match="Custody canonical"):
        _register(evidence, custody=evidence.custody.model_copy(update={"custody_receipt": bad_receipt}))
    with pytest.raises(RegistrationValidationError, match="private generation"):
        _register(evidence, public_manifest={"nested": [{"private_parameters": {"x": 1}}]})


def test_verification_records_success_hash_mismatch_missing_and_revoked() -> None:
    service, repository, evidence = registered_service()
    verified = service.verify(VerificationRequest(cert_id=evidence.envelope.cert_id))
    matched = service.verify(
        VerificationRequest(cert_id=evidence.envelope.cert_id, presented_sha256=SEALED)
    )
    mismatch = service.verify(
        VerificationRequest(cert_id=evidence.envelope.cert_id, presented_sha256="9" * 64)
    )
    missing = service.verify(VerificationRequest(cert_id="missing-cert"))
    assert (verified.status, matched.status, mismatch.status, missing.status) == (
        "verified", "verified", "hash_mismatch", "certificate_not_found"
    )
    assert mismatch.hash_match is False
    assert missing.signature_valid is False
    repository.revoke_certificate(
        evidence.envelope.cert_id, reason="Owner revocation", revoked_at=NOW + timedelta(days=1)
    )
    revoked = service.verify(VerificationRequest(cert_id=evidence.envelope.cert_id))
    assert revoked.status == "certificate_revoked"
    assert len(repository.verification_events) == 5
    with pytest.raises(CertificateNotFoundError):
        repository.revoke_certificate("missing", reason="reason", revoked_at=NOW)


def test_verify_detects_invalid_signature_malformed_envelope_and_invalid_status() -> None:
    service, repository, evidence = registered_service()
    certificate = repository.get_certificate(evidence.envelope.cert_id)
    assert certificate is not None
    raw = bytearray(base64.b64decode(certificate.signature_b64))
    raw[-1] ^= 1
    bad_signature = base64.b64encode(raw).decode()
    bad_signed = certificate.signed_envelope.model_copy(update={"signature": bad_signature})
    repository._certificates[certificate.cert_id] = certificate.model_copy(  # noqa: SLF001
        update={"signature_b64": bad_signature, "signed_envelope": bad_signed}
    )
    assert service.verify(VerificationRequest(cert_id=certificate.cert_id)).status == "signature_invalid"
    repository._certificates[certificate.cert_id] = certificate.model_copy(  # noqa: SLF001
        update={"sealed_sha256": "8" * 64}
    )
    assert service.verify(VerificationRequest(cert_id=certificate.cert_id)).status == "malformed_evidence"
    repository._certificates[certificate.cert_id] = certificate.model_copy(  # noqa: SLF001
        update={"certificate_status": "invalid"}
    )
    assert service.verify(VerificationRequest(cert_id=certificate.cert_id)).safe_reason_code == "CERTIFICATE_INVALID"
    repository._certificates[certificate.cert_id] = certificate.model_copy(  # noqa: SLF001
        update={"custody": None}
    )
    result = service.verify(VerificationRequest(cert_id=certificate.cert_id))
    assert result.safe_reason_code == "CUSTODY_REFERENCE_INVALID"


def test_delivery_issues_only_after_verification_and_redacts_url() -> None:
    _, repository, evidence = registered_service()
    storage = StorageStub()
    service = CertificateService(repository, storage=storage, delivery_ttl_seconds=60)
    grant = service.authorize_delivery(
        evidence.envelope.cert_id, DeliveryAuthorization(presented_sha256=SEALED), now=NOW
    )
    assert isinstance(grant, AuthorizedDelivery)
    assert grant.result.expires_at == NOW + timedelta(seconds=60)
    assert "raw-secret" not in repr(grant)
    assert "raw-secret" not in repr(grant.download)
    assert "download_url" not in repository.delivery_events[-1]
    assert storage.calls == [(evidence.asset.asset_id, 60)]


def test_delivery_blocks_mismatch_revocation_and_missing_storage() -> None:
    service, repository, evidence = registered_service()
    blocked = service.authorize_delivery(
        evidence.envelope.cert_id, DeliveryAuthorization(presented_sha256="9" * 64)
    )
    assert blocked.status == "blocked"  # type: ignore[union-attr]
    assert repository.delivery_events[-1]["delivery_status"] == "blocked"
    service_no_storage = CertificateService(repository)
    unavailable = service_no_storage.authorize_delivery(
        evidence.envelope.cert_id, DeliveryAuthorization(presented_sha256=SEALED)
    )
    assert unavailable.status == "storage_failure"  # type: ignore[union-attr]
    repository.revoke_certificate(evidence.envelope.cert_id, reason="revoked", revoked_at=NOW)
    revoked = service.authorize_delivery(
        evidence.envelope.cert_id, DeliveryAuthorization(presented_sha256=SEALED)
    )
    assert revoked.status == "blocked"  # type: ignore[union-attr]
    missing = service.authorize_delivery(
        "missing-cert", DeliveryAuthorization(presented_sha256=SEALED)
    )
    assert missing.delivery_event_id is None  # type: ignore[union-attr]


def test_delivery_storage_failure_is_safe_and_recorded() -> None:
    _, repository, evidence = registered_service()
    service = CertificateService(repository, storage=StorageStub(fail=True))
    with pytest.raises(DeliveryStorageError) as raised:
        service.authorize_delivery(
            evidence.envelope.cert_id, DeliveryAuthorization(presented_sha256=SEALED)
        )
    assert "provider response" not in str(raised.value)
    assert repository.delivery_events[-1]["delivery_status"] == "storage_failure"


def test_service_rejects_unsafe_ttl_and_missing_public_certificate() -> None:
    repository = MemoryCertificateRepository()
    with pytest.raises(ValueError, match="TTL"):
        CertificateService(repository, delivery_ttl_seconds=59)
    assert CertificateService(repository).get_public_certificate("missing") is None


def test_b2_delivery_adapter_uses_exact_version_and_redacts_client() -> None:
    _, _, evidence = registered_service()

    class Presigner:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def generate_presigned_url(
            self,
            operation: str,
            *,
            Params: dict[str, object],
            ExpiresIn: int,
            HttpMethod: str,
        ) -> str:
            self.calls.append(
                {
                    "operation": operation,
                    "Params": Params,
                    "ExpiresIn": ExpiresIn,
                    "HttpMethod": HttpMethod,
                }
            )
            return "https://s3.example.test/exact?X-Amz-Signature=private"

        def head_object(self, **kwargs: object) -> dict[str, object]:
            self.calls.append({"operation": "head_object", **kwargs})
            return {
                "ContentLength": 100,
                "ContentType": "image/png",
                "Metadata": {"firemark-sha256": evidence.asset.sealed_sha256},
                "VersionId": evidence.asset.assets_version_id,
                "ETag": '"etag"',
                "LastModified": evidence.asset.created_at,
            }

    client = Presigner()
    storage = B2DeliveryStorage(client)
    result = storage.issue_download(evidence.asset, ttl_seconds=60)
    assert client.calls == [
        {
            "operation": "head_object",
            "Bucket": evidence.asset.assets_bucket,
            "Key": evidence.asset.assets_key,
            "VersionId": evidence.asset.assets_version_id,
        },
        {
            "operation": "get_object",
            "Params": {
                "Bucket": evidence.asset.assets_bucket,
                "Key": evidence.asset.assets_key,
                "VersionId": evidence.asset.assets_version_id,
            },
            "ExpiresIn": 60,
            "HttpMethod": "GET",
        },
    ]
    assert "private" not in repr(storage)
    assert "private" not in repr(result)
