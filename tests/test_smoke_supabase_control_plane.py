"""Zero-network tests for the live Supabase Control Plane checkpoint."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

import scripts.smoke_supabase_control_plane as smoke
from api.firemark.settings import Settings

PUBLISHABLE_KEY = "sb_publishable_zero-network-test"
SECRET_KEY = "sb_secret_zero-network-test"


class FakeServiceError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__("private fake service detail")
        self.code = code


class FakeBackend:
    def __init__(
        self,
        *,
        rls_mode: str = "empty",
        partial_registration: bool = False,
        fail_update: bool = False,
    ) -> None:
        self.rls_mode = rls_mode
        self.partial_registration = partial_registration
        self.fail_update = fail_update
        self.tables: dict[str, list[dict[str, Any]]] = {
            table: [] for table in smoke.PRIVATE_TABLES
        }
        self.client_keys: list[str] = []
        self.operations: list[tuple[Any, ...]] = []

    def client_factory(self, url: str, key: str) -> FakeClient:
        assert url == "https://project.supabase.co"
        self.client_keys.append(key)
        return FakeClient(self, publishable=key == PUBLISHABLE_KEY)

    def register(self, payload: dict[str, Any]) -> str:
        entries = (
            ("generation_runs", "run_id", payload["p_generation_run"]),
            ("assets", "asset_id", payload["p_asset"]),
            ("custody_records", "asset_id", payload["p_custody"]),
            ("certificates", "cert_id", payload["p_certificate"]),
        )
        if self.partial_registration and not self.tables["generation_runs"]:
            row = deepcopy(entries[0][2])
            row["id"] = str(uuid4())
            self.tables["generation_runs"].append(row)
            return str(row["run_id"])
        pending: list[tuple[str, dict[str, Any]]] = []
        for table, identifier, candidate in entries:
            existing = next(
                (row for row in self.tables[table] if row[identifier] == candidate[identifier]),
                None,
            )
            if existing is not None:
                comparable = {key: value for key, value in existing.items() if key != "id"}
                if comparable != candidate:
                    raise FakeServiceError("23505")
            else:
                row = deepcopy(candidate)
                row["id"] = str(uuid4())
                pending.append((table, row))
        for table, row in pending:
            self.tables[table].append(row)
        return str(payload["p_certificate"]["cert_id"])

    def public_certificate(self, cert_id: str) -> list[dict[str, Any]]:
        certificate = next(
            (row for row in self.tables["certificates"] if row["cert_id"] == cert_id), None
        )
        if certificate is None:
            return []
        return [{key: deepcopy(certificate[key]) for key in smoke.PUBLIC_RPC_FIELDS}]


class FakeClient:
    def __init__(self, backend: FakeBackend, *, publishable: bool) -> None:
        self.backend = backend
        self.publishable = publishable

    def table(self, name: str) -> FakeBuilder:
        self.backend.operations.append(("table", name, self.publishable))
        return FakeBuilder(self, "table", name)

    def rpc(self, name: str, payload: dict[str, Any]) -> FakeBuilder:
        self.backend.operations.append(("rpc", name, self.publishable))
        return FakeBuilder(self, "rpc", name, payload=payload)


class FakeBuilder:
    def __init__(
        self,
        client: FakeClient,
        operation: str,
        name: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.client = client
        self.operation = operation
        self.name = name
        self.payload = payload
        self.selection = "*"
        self.filters: list[tuple[str, str]] = []
        self.like_filters: list[tuple[str, str]] = []
        self.insert_value: dict[str, Any] | None = None
        self.update_value: dict[str, Any] | None = None
        self.single = False
        self.limit_value: int | None = None
        self.order_value: tuple[str, bool] | None = None

    def select(self, value: str) -> FakeBuilder:
        self.selection = value
        return self

    def limit(self, value: int) -> FakeBuilder:
        self.limit_value = value
        return self

    def eq(self, field: str, value: str) -> FakeBuilder:
        self.filters.append((field, value))
        return self

    def like(self, field: str, value: str) -> FakeBuilder:
        self.like_filters.append((field, value))
        return self

    def order(self, field: str, *, desc: bool = False) -> FakeBuilder:
        self.order_value = (field, desc)
        return self

    def maybe_single(self) -> FakeBuilder:
        if self.update_value is not None:
            raise AttributeError("mutation builders do not support maybe_single")
        self.single = True
        return self

    def insert(self, payload: dict[str, Any]) -> FakeBuilder:
        self.client.backend.operations.append(("insert", self.name))
        self.insert_value = payload
        return self

    def update(self, payload: dict[str, Any]) -> FakeBuilder:
        self.client.backend.operations.append(("update", self.name))
        self.update_value = payload
        return self

    def execute(self) -> Any:
        if self.operation == "rpc":
            assert self.payload is not None
            if self.name == "register_firemark_certificate_bundle":
                if self.client.publishable:
                    raise FakeServiceError("42501")
                return SimpleNamespace(data=self.client.backend.register(self.payload))
            if self.name == smoke.PUBLIC_RPC_NAME:
                return SimpleNamespace(
                    data=self.client.backend.public_certificate(str(self.payload["p_cert_id"]))
                )
            raise AssertionError("unexpected RPC")
        if self.client.publishable:
            if self.client.backend.rls_mode == "denied":
                raise FakeServiceError("42501")
            if self.client.backend.rls_mode == "leak":
                return SimpleNamespace(data=[{"id": "private-row"}])
            return SimpleNamespace(data=[])
        rows = self.client.backend.tables[self.name]
        if self.insert_value is not None:
            row = deepcopy(self.insert_value)
            row["id"] = str(uuid4())
            rows.append(row)
            return SimpleNamespace(data=[deepcopy(row)])
        selected = [
            row
            for row in rows
            if all(str(row.get(field)) == str(value) for field, value in self.filters)
        ]
        for field, pattern in self.like_filters:
            prefix = pattern.removesuffix("%")
            selected = [row for row in selected if str(row.get(field, "")).startswith(prefix)]
        if self.order_value is not None:
            field, desc = self.order_value
            selected.sort(key=lambda row: str(row.get(field, "")), reverse=desc)
        if self.limit_value is not None:
            selected = selected[: self.limit_value]
        if self.update_value is not None:
            if self.client.backend.fail_update:
                raise FakeServiceError("PGRST_TEST")
            for row in selected:
                row.update(deepcopy(self.update_value))
        result = [self._joined_certificate(row) for row in selected]
        if self.single:
            return SimpleNamespace(data=result[0] if result else None)
        return SimpleNamespace(data=result)

    def _joined_certificate(self, row: dict[str, Any]) -> dict[str, Any]:
        result = deepcopy(row)
        if self.name != "certificates" or "assets(" not in self.selection:
            return result
        asset = next(
            item
            for item in self.client.backend.tables["assets"]
            if item["asset_id"] == row["asset_id"]
        )
        custody = next(
            item
            for item in self.client.backend.tables["custody_records"]
            if item["asset_id"] == row["asset_id"]
        )
        result["assets"] = {**deepcopy(asset), "custody_records": [deepcopy(custody)]}
        return result


def live_settings(**updates: Any) -> Settings:
    values: dict[str, Any] = {
        "supabase_url": "https://project.supabase.co",
        "supabase_publishable_key": PUBLISHABLE_KEY,
        "supabase_service_role_key": SECRET_KEY,
        "public_base_url": "https://verify.firemark.test",
        "delivery_ttl_seconds": 300,
    }
    values.update(updates)
    return Settings.model_validate(values)


def test_no_live_constructs_no_client_and_returns_informational_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        smoke,
        "_default_client_factory",
        lambda *_: pytest.fail("no-live must not construct a client"),
    )
    assert smoke.main([]) == 2
    output = capsys.readouterr().out
    assert "network disabled" in output
    assert "No Supabase client was constructed" in output


def test_live_configuration_rejects_partial_http_and_identical_keys() -> None:
    partial = Settings(
        supabase_url="https://project.supabase.co",
        supabase_service_role_key=SECRET_KEY,
        delivery_ttl_seconds=300,
    )
    with pytest.raises(smoke.LiveCheckpointError, match="INVALID_LIVE_CONFIGURATION"):
        smoke.run_checkpoint(partial, client_factory=lambda *_: object())
    with pytest.raises(ValidationError, match="HTTPS"):
        live_settings(supabase_url="http://project.supabase.co")
    identical = live_settings(
        supabase_publishable_key="same-value",
        supabase_service_role_key="same-value",
    )
    with pytest.raises(smoke.LiveCheckpointError, match="INVALID_LIVE_CONFIGURATION"):
        smoke.run_checkpoint(identical, client_factory=lambda *_: object())


def test_cli_loads_dotenv_before_live_settings_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    order: list[str] = []

    def fake_load_dotenv(*, dotenv_path: Path, override: bool) -> bool:
        assert dotenv_path == env_file
        assert override is False
        order.append("dotenv")
        return True

    def fake_load_settings() -> Settings:
        order.append("settings")
        assert order == ["dotenv", "settings"]
        return live_settings()

    def fake_run_checkpoint(settings: Settings, **kwargs: Any) -> dict[str, Any]:
        assert settings.require_live_supabase_control_plane_config()
        assert kwargs["output_report"] is None
        order.append("checkpoint")
        return {"project_hostname": "project.supabase.co"}

    monkeypatch.setattr(smoke, "DEFAULT_ENV_FILE", env_file)
    monkeypatch.setattr(smoke, "load_dotenv", fake_load_dotenv)
    monkeypatch.setattr(smoke, "load_settings", fake_load_settings)
    monkeypatch.setattr(smoke, "run_checkpoint", fake_run_checkpoint)
    assert smoke.main(["--live"]) == 0
    assert order == ["dotenv", "settings", "checkpoint"]


def test_safe_configuration_diagnostic_prints_only_status_and_key_families(
    capsys: pytest.CaptureFixture[str],
) -> None:
    publishable = "sb_publishable_must-never-print"
    secret = "sb_secret_must-never-print"
    query_token = "must-never-print-query-token"
    values = {
        "SUPABASE_URL": f"https://project.supabase.co?token={query_token}",
        "SUPABASE_PUBLISHABLE_KEY": publishable,
        "SUPABASE_SERVICE_ROLE_KEY": secret,
        "FIREMARK_PUBLIC_BASE_URL": "https://firemark.local/",
        "FIREMARK_DELIVERY_TTL_SECONDS": "300",
    }
    smoke.print_safe_configuration_diagnostic(values)
    output = capsys.readouterr().out
    assert "FIELD=SUPABASE_PUBLISHABLE_KEY PRESENT VALID" in output
    assert "FAMILY=SB_PUBLISHABLE" in output
    assert "FIELD=SUPABASE_SERVICE_ROLE_KEY PRESENT VALID" in output
    assert "FAMILY=SB_SECRET" in output
    assert "HOST=project.supabase.co" in output
    assert "FIELD=FIREMARK_PUBLIC_BASE_URL PRESENT VALID" in output
    assert publishable not in output
    assert secret not in output
    assert query_token not in output


def test_safe_configuration_diagnostic_rejects_unknown_key_family() -> None:
    lines = smoke.safe_configuration_diagnostic(
        {
            "SUPABASE_URL": "https://project.supabase.co",
            "SUPABASE_PUBLISHABLE_KEY": "unknown-public-key",
            "SUPABASE_SERVICE_ROLE_KEY": SECRET_KEY,
            "FIREMARK_PUBLIC_BASE_URL": "https://firemark.local",
            "FIREMARK_DELIVERY_TTL_SECONDS": "300",
        }
    )
    assert any(
        "FIELD=SUPABASE_PUBLISHABLE_KEY PRESENT INVALID "
        "REASON=UNSUPPORTED_KEY_FAMILY FAMILY=UNKNOWN" == line
        for line in lines
    )


def test_rls_classification_accepts_empty_or_denied_and_rejects_leaks() -> None:
    assert smoke.classify_rls_probe(SimpleNamespace(data=[])) == "empty_rls_result"
    assert smoke.classify_rls_probe(error=FakeServiceError("42501")) == (
        "authorization_denied"
    )
    with pytest.raises(smoke.LiveCheckpointError, match="PRIVATE_ROWS_EXPOSED"):
        smoke.classify_rls_probe(SimpleNamespace(data=[{"id": "leak"}]))
    with pytest.raises(smoke.LiveCheckpointError, match="UNSAFE_RLS_PROBE_FAILURE"):
        smoke.classify_rls_probe(error=RuntimeError("unknown"))


def test_nonexistent_public_certificate_is_an_empty_safe_result() -> None:
    backend = FakeBackend()
    client = FakeClient(backend, publishable=True)
    assert smoke._public_rpc_rows(client, "missing", "public_certificate_rpc_probe") == []


@pytest.mark.parametrize("rls_mode", ["empty", "denied"])
def test_complete_checkpoint_proves_registration_events_revocation_and_safe_report(
    rls_mode: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    backend = FakeBackend(rls_mode=rls_mode)
    report_path = tmp_path / "safe-report.json"
    report = smoke.run_checkpoint(
        live_settings(),
        client_factory=backend.client_factory,
        output_report=report_path,
        identifier=f"test-{rls_mode}",
    )
    assert [stage["name"] for stage in report["stages"]] == list(smoke.STAGES)
    assert all(stage["result"] == "PASS" for stage in report["stages"])
    assert report["table_row_counts"] == {
        "generation_runs": 1,
        "assets": 1,
        "custody_records": 1,
        "certificates": 1,
        "verification_events": 1,
        "delivery_events": 1,
    }
    assert report["idempotent_registration"] is True
    assert report["conflicting_duplicate_rejected"] is True
    assert report["public_rpc_exact_allowlist"] is True
    assert report["revocation"] == {
        "public_status": "revoked",
        "verification_authorized": False,
    }
    assert backend.tables["certificates"][0]["certificate_status"] == "revoked"
    assert len(backend.tables["verification_events"]) == 1
    assert len(backend.tables["delivery_events"]) == 1
    assert not any("url" in key.lower() for key in backend.tables["delivery_events"][0])
    persisted = report_path.read_text(encoding="utf-8")
    output = capsys.readouterr().out
    for credential in (PUBLISHABLE_KEY, SECRET_KEY):
        assert credential not in persisted
        assert credential not in output
    assert json.loads(persisted) == report
    assert backend.client_keys == [SECRET_KEY, PUBLISHABLE_KEY]


def test_partial_atomic_result_is_rejected() -> None:
    backend = FakeBackend(partial_registration=True)
    with pytest.raises(smoke.LiveCheckpointError, match="PARTIAL_OR_DUPLICATE_BUNDLE"):
        smoke.run_checkpoint(
            live_settings(), client_factory=backend.client_factory, identifier="partial"
        )
    assert len(backend.tables["generation_runs"]) == 1
    assert all(
        not backend.tables[table]
        for table in ("assets", "custody_records", "certificates")
    )


def test_failure_after_delivery_is_normalized_to_certificate_revocation_stage(
    capsys: pytest.CaptureFixture[str],
) -> None:
    backend = FakeBackend(fail_update=True)
    with pytest.raises(smoke.LiveCheckpointError) as raised:
        smoke.run_checkpoint(
            live_settings(),
            client_factory=backend.client_factory,
            identifier="revocation-failure",
        )
    assert raised.value.stage == "certificate_revocation"
    assert raised.value.reason_code == "REPOSITORY_OPERATION_FAILED"
    output = capsys.readouterr().out
    assert "delivery_event_append: PASS" in output
    assert "checkpoint_internal" not in output


def test_public_projection_requires_exact_allowlist_and_rejects_private_leaks() -> None:
    evidence = smoke._build_evidence("projection", smoke.datetime(2026, 7, 29, tzinfo=smoke.UTC))
    row = {
        "cert_id": evidence.envelope.cert_id,
        "asset_id": evidence.asset.asset_id,
        "run_id": evidence.generation_run.run_id,
        "sealed_sha256": smoke.SEALED_SHA256,
        "canonical_hash": smoke.CANONICAL_HASH,
        "signer_key_id": evidence.envelope.signer_key_id,
        "signer_public_key_b64": evidence.signer_public_key_b64,
        "signature_b64": evidence.signature_b64,
        "public_manifest": evidence.public_manifest,
        "certificate_status": "active",
        "issued_at": "2026-07-29T00:00:00Z",
    }
    smoke.require_public_projection(row, evidence)
    with pytest.raises(smoke.LiveCheckpointError, match="PUBLIC_ALLOWLIST_MISMATCH"):
        smoke.require_public_projection({**row, "prompt_private": "leak"}, evidence)
    leaked = {**row, "public_manifest": {"nested": {"authorization": "leak"}}}
    with pytest.raises(smoke.LiveCheckpointError, match="PRIVATE_FIELD_LEAK"):
        smoke.require_public_projection(leaked, evidence)


def test_service_failures_are_normalized_without_credentials(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class ExplodingBuilder:
        def execute(self) -> Any:
            raise RuntimeError(f"database detail {SECRET_KEY}")

    with pytest.raises(smoke.LiveCheckpointError) as raised:
        smoke._execute(ExplodingBuilder(), "public_certificate_rpc_probe", "PUBLIC_RPC_FAILED")
    assert str(raised.value) == "public_certificate_rpc_probe:PUBLIC_RPC_FAILED"
    assert SECRET_KEY not in str(raised.value)
    assert SECRET_KEY not in capsys.readouterr().out


def test_database_secret_scan_rejects_names_markers_and_exact_credentials() -> None:
    with pytest.raises(smoke.LiveCheckpointError, match="SENSITIVE_COLUMN_NAME"):
        smoke.require_safe_database_rows(
            {"certificates": [{"private_key": "hidden"}]}, credentials=()
        )
    with pytest.raises(smoke.LiveCheckpointError, match="SENSITIVE_VALUE_MARKER"):
        smoke.require_safe_database_rows(
            {"certificates": [{"safe": "authorization: bearer redacted"}]}, credentials=()
        )
    with pytest.raises(smoke.LiveCheckpointError, match="CREDENTIAL_VALUE_PRESENT"):
        smoke.require_safe_database_rows(
            {"certificates": [{"safe": PUBLISHABLE_KEY}]}, credentials=(PUBLISHABLE_KEY,)
        )
