"""Zero-network contract tests for the lazy Supabase repository adapter."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from pydantic import SecretStr

from api.firemark.control_plane.memory_repository import MemoryCertificateRepository
from api.firemark.control_plane.repository import CertificateNotFoundError, RepositoryError
from api.firemark.control_plane.supabase_repository import SupabaseCertificateRepository
from api.firemark.settings import SupabaseConfig
from tests.control_plane_helpers import NOW, SEALED, build_evidence, register

EVENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


class FakeBuilder:
    def __init__(self, client: FakeClient, operation: tuple[Any, ...]) -> None:
        self.client = client
        self.operation = operation

    def select(self, value: str) -> FakeBuilder:
        self.client.calls.append(("select", value))
        return self

    def eq(self, field: str, value: str) -> FakeBuilder:
        self.client.calls.append(("eq", field, value))
        return self

    def maybe_single(self) -> FakeBuilder:
        self.client.calls.append(("maybe_single",))
        return self

    def insert(self, payload: dict[str, Any]) -> FakeBuilder:
        self.client.calls.append(("insert", payload))
        return self

    def update(self, payload: dict[str, Any]) -> FakeBuilder:
        self.client.calls.append(("update", payload))
        return self

    def execute(self) -> Any:
        self.client.calls.append(("execute", *self.operation))
        if self.client.error is not None:
            raise self.client.error
        data = self.client.responses.pop(0) if self.client.responses else None
        return SimpleNamespace(data=data)


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.responses: list[Any] = []
        self.error: Exception | None = None

    def rpc(self, name: str, payload: dict[str, Any]) -> FakeBuilder:
        self.calls.append(("rpc", name, payload))
        return FakeBuilder(self, ("rpc", name))

    def table(self, name: str) -> FakeBuilder:
        self.calls.append(("table", name))
        return FakeBuilder(self, ("table", name))


def _certificate_bundle() -> tuple[Any, Any]:
    evidence = build_evidence()
    memory = MemoryCertificateRepository()
    from api.firemark.control_plane.service import CertificateService

    service = CertificateService(memory)
    register(service, evidence)
    certificate = memory.get_certificate(evidence.envelope.cert_id)
    assert certificate is not None
    return evidence, certificate


def _row(certificate: Any) -> dict[str, Any]:
    values = certificate.model_dump(mode="json", exclude={"asset", "custody"})
    asset = certificate.asset.model_dump(mode="json")
    asset["id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    custody = certificate.custody.model_dump(mode="json")
    custody["id"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    asset["custody_records"] = [custody]
    values["id"] = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    values["assets"] = asset
    return values


def test_constructor_and_repr_are_lazy_and_redacted() -> None:
    calls: list[tuple[str, str]] = []

    def factory(url: str, key: str) -> FakeClient:
        calls.append((url, key))
        return FakeClient()

    config = SupabaseConfig(url="https://project.supabase.co", service_role_key="secret")
    repository = SupabaseCertificateRepository.from_config(config, client_factory=factory)
    assert calls == []
    assert "secret" not in repr(repository)
    repository.get_certificate("missing")
    assert calls == [("https://project.supabase.co", "secret")]


def test_bundle_registration_uses_exactly_one_atomic_rpc() -> None:
    evidence, certificate = _certificate_bundle()
    client = FakeClient()
    client.responses = [evidence.envelope.cert_id]
    repository = SupabaseCertificateRepository(
        "https://project.supabase.co", SecretStr("secret"), client_factory=lambda *_: client
    )
    stored = repository.register_certificate_bundle(
        evidence.generation_run, evidence.asset, evidence.custody, certificate
    )
    rpc_calls = [call for call in client.calls if call[0] == "rpc"]
    assert len(rpc_calls) == 1
    assert rpc_calls[0][1] == "register_firemark_certificate_bundle"
    payload = rpc_calls[0][2]
    assert set(payload) == {"p_generation_run", "p_asset", "p_custody", "p_certificate"}
    assert "asset" not in payload["p_certificate"]
    assert stored.asset == evidence.asset


def test_reads_map_joined_private_aggregate_and_missing() -> None:
    _, certificate = _certificate_bundle()
    client = FakeClient()
    client.responses = [_row(certificate), [_row(certificate)], None]
    repository = SupabaseCertificateRepository(
        "https://project.supabase.co", SecretStr("secret"), client_factory=lambda *_: client
    )
    by_id = repository.get_certificate(certificate.cert_id)
    by_hash = repository.get_certificate_by_sealed_sha256(SEALED)
    missing = repository.get_certificate("missing")
    assert by_id == by_hash == certificate
    assert missing is None
    assert ("eq", "sealed_sha256", SEALED) in client.calls


def test_append_events_and_revoke_use_public_query_apis() -> None:
    _, certificate = _certificate_bundle()
    client = FakeClient()
    revoked_row = _row(
        certificate.model_copy(
            update={
                "certificate_status": "revoked",
                "revoked_at": NOW + timedelta(days=1),
                "revocation_reason": "owner request",
            }
        )
    )
    client.responses = [[{"id": EVENT_ID}], {"id": EVENT_ID}, [revoked_row]]
    repository = SupabaseCertificateRepository(
        "https://project.supabase.co", SecretStr("secret"), client_factory=lambda *_: client
    )
    verification_id = repository.record_verification(
        cert_id=certificate.cert_id,
        presented_sha256=SEALED,
        status="verified",
        signature_valid=True,
        envelope_valid=True,
        hash_match=True,
        custody_reference_valid=True,
        safe_reason_code="VERIFIED",
        created_at=NOW,
    )
    delivery_id = repository.record_delivery(
        cert_id=certificate.cert_id,
        verification_event_id=verification_id,
        status="issued",
        safe_reason_code="DELIVERY_ISSUED",
        expires_at=NOW + timedelta(seconds=60),
        created_at=NOW,
    )
    revoked = repository.revoke_certificate(
        certificate.cert_id, reason="owner request", revoked_at=NOW + timedelta(days=1)
    )
    assert verification_id == delivery_id == UUID(EVENT_ID)
    assert revoked.certificate_status == "revoked"
    assert ("maybe_single",) not in client.calls
    persisted = repr(client.calls)
    assert "download_url" not in persisted and "presigned" not in persisted


def test_service_errors_and_invalid_responses_are_safely_normalized() -> None:
    client = FakeClient()
    client.error = RuntimeError("SQL and service-role details")
    repository = SupabaseCertificateRepository(
        "https://project.supabase.co", SecretStr("secret"), client_factory=lambda *_: client
    )
    with pytest.raises(RepositoryError) as raised:
        repository.get_certificate("firemark-cert-1")
    assert "SQL" not in str(raised.value)
    client.error = None
    client.responses = [[{"id": "not-a-uuid"}], []]
    with pytest.raises(RepositoryError, match="invalid identifier"):
        repository.record_verification(
            cert_id=None,
            presented_sha256=None,
            status="certificate_not_found",
            signature_valid=False,
            envelope_valid=False,
            hash_match=None,
            custody_reference_valid=False,
            safe_reason_code="CERTIFICATE_NOT_FOUND",
            created_at=NOW,
        )
    with pytest.raises(CertificateNotFoundError):
        repository.revoke_certificate("missing", reason="reason", revoked_at=NOW)
