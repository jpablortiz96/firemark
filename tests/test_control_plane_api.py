"""Zero-network FastAPI tests for public certificates and the Verify Gate."""

from __future__ import annotations

import logging
from typing import Any

from fastapi.testclient import TestClient

from api.firemark.app import create_app
from api.firemark.b2_storage import RedactedPresignedURL
from api.firemark.control_plane.models import AssetRecord
from api.firemark.control_plane.supabase_repository import SupabaseCertificateRepository
from api.firemark.settings import Settings
from tests.control_plane_helpers import SEALED, registered_service

RAW_URL = "https://s3.example.test/private/file?X-Amz-Signature=raw-secret"
DELIVERY_KEY = "test-only-delivery-api-key"
DELIVERY_HEADERS = {"Authorization": f"Bearer {DELIVERY_KEY}"}


class APIStorage:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def issue_download(self, asset: AssetRecord, *, ttl_seconds: int) -> RedactedPresignedURL:
        del asset
        if self.fail:
            raise RuntimeError(f"storage failed: {RAW_URL}")
        return RedactedPresignedURL(RAW_URL, ttl_seconds)


def _client(*, storage: Any = None) -> tuple[TestClient, Any, Any]:
    _, repository, evidence = registered_service()
    app = create_app(
        Settings(
            public_base_url="https://certs.firemark.test",
            delivery_ttl_seconds=60,
            delivery_api_key=DELIVERY_KEY,
        ),
        repository,
        storage,
    )
    return TestClient(app), repository, evidence


def test_factory_health_dependency_injection_and_openapi_are_zero_network() -> None:
    client, repository, _ = _client()
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "firemark-api",
        "version": "0.1.0",
        "external_dependencies": "not_checked",
    }
    assert response.headers["x-request-id"].startswith("fmreq_")
    app = create_app(repository=repository)
    assert app.title == "FIREMARK Control Plane"
    assert set(app.openapi()["paths"]) == {
        "/healthz", "/v1/certificates/{cert_id}", "/v1/verify",
        "/v1/generate-and-seal", "/v1/delivery/{cert_id}"
    }
    configured = create_app(
        Settings(
            repository_backend="supabase",
            supabase_url="https://project.supabase.co",
            supabase_service_role_key="service-role-secret",
        )
    )
    assert isinstance(
        configured.state.certificate_service.repository, SupabaseCertificateRepository
    )


def test_certificate_api_active_missing_revoked_and_private_fields_absent() -> None:
    client, repository, evidence = _client()
    active = client.get(f"/v1/certificates/{evidence.envelope.cert_id}")
    assert active.status_code == 200
    payload = active.json()
    assert payload["cert_id"] == evidence.envelope.cert_id
    serialized = active.text
    for private in ("private prompt", "prompt_private", "parameters_private", "seed_private"):
        assert private not in serialized
    missing = client.get("/v1/certificates/missing")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "CERTIFICATE_NOT_FOUND"
    assert missing.json()["error"]["request_id"].startswith("fmreq_")
    repository.revoke_certificate(evidence.envelope.cert_id, reason="revoked", revoked_at=evidence.envelope.created_at)
    revoked = client.get(f"/v1/certificates/{evidence.envelope.cert_id}")
    assert revoked.status_code == 410
    assert revoked.json()["error"]["code"] == "CERTIFICATE_REVOKED"


def test_verify_api_all_core_outcomes_and_event_persistence() -> None:
    client, repository, evidence = _client()
    valid = client.post("/v1/verify", json={"cert_id": evidence.envelope.cert_id})
    matching = client.post(
        "/v1/verify", json={"cert_id": evidence.envelope.cert_id, "presented_sha256": SEALED}
    )
    mismatch = client.post(
        "/v1/verify", json={"cert_id": evidence.envelope.cert_id, "presented_sha256": "9" * 64}
    )
    missing = client.post("/v1/verify", json={"cert_id": "missing"})
    malformed = client.post(
        "/v1/verify", json={"cert_id": evidence.envelope.cert_id, "presented_sha256": "bad"}
    )
    assert [item.json()["status"] for item in (valid, matching, mismatch, missing)] == [
        "verified", "verified", "hash_mismatch", "certificate_not_found"
    ]
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "MALFORMED_REQUEST"
    assert len(repository.verification_events) == 4


def test_delivery_success_serializes_url_once_and_never_logs_or_persists_it(
    caplog: Any,
) -> None:
    client, repository, evidence = _client(storage=APIStorage())
    with caplog.at_level(logging.INFO, logger="firemark.api"):
        response = client.post(
            f"/v1/delivery/{evidence.envelope.cert_id}",
            json={"presented_sha256": SEALED},
            headers=DELIVERY_HEADERS,
        )
    assert response.status_code == 200
    assert response.json()["download_url"] == RAW_URL
    assert response.json()["expires_in"] == 60
    assert RAW_URL not in caplog.text
    assert RAW_URL not in repr(repository.delivery_events)
    assert all("url" not in event for event in repository.delivery_events)


def test_delivery_requires_the_distinct_delivery_bearer_key() -> None:
    client, _, evidence = _client(storage=APIStorage())
    path = f"/v1/delivery/{evidence.envelope.cert_id}"
    payload = {"presented_sha256": SEALED}
    missing = client.post(path, json=payload)
    invalid = client.post(path, json=payload, headers={"Authorization": "Bearer wrong"})
    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert missing.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert invalid.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_delivery_failures_have_no_url_and_do_not_call_storage() -> None:
    client, repository, evidence = _client(storage=APIStorage())
    mismatch = client.post(
        f"/v1/delivery/{evidence.envelope.cert_id}",
        json={"presented_sha256": "9" * 64},
        headers=DELIVERY_HEADERS,
    )
    assert mismatch.status_code == 403
    assert "download_url" not in mismatch.text
    assert RAW_URL not in mismatch.text
    repository.revoke_certificate(
        evidence.envelope.cert_id, reason="revoked", revoked_at=evidence.envelope.created_at
    )
    revoked = client.post(
        f"/v1/delivery/{evidence.envelope.cert_id}",
        json={"presented_sha256": SEALED},
        headers=DELIVERY_HEADERS,
    )
    assert revoked.status_code == 403
    assert RAW_URL not in revoked.text


def test_storage_failure_is_safe_and_url_is_absent_from_error_and_logs(caplog: Any) -> None:
    client, _, evidence = _client(storage=APIStorage(fail=True))
    with caplog.at_level(logging.INFO, logger="firemark.api"):
        response = client.post(
            f"/v1/delivery/{evidence.envelope.cert_id}",
            json={"presented_sha256": SEALED},
            headers=DELIVERY_HEADERS,
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "DELIVERY_STORAGE_UNAVAILABLE"
    assert RAW_URL not in response.text
    assert RAW_URL not in caplog.text


def test_default_factory_and_unexpected_errors_are_safe() -> None:
    app = create_app(Settings())
    client = TestClient(app)
    response = client.post(
        "/v1/delivery/missing", json={"presented_sha256": SEALED}
    )
    assert response.status_code == 401
    assert "download_url" not in response.text


def test_unexpected_exception_is_normalized_without_service_details() -> None:
    class FailingRepository:
        def get_certificate(self, cert_id: str) -> Any:
            del cert_id
            raise RuntimeError(f"private service failure {RAW_URL}")

    app = create_app(Settings(), repository=FailingRepository())  # type: ignore[arg-type]
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/v1/certificates/firemark-cert-1")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert RAW_URL not in response.text
