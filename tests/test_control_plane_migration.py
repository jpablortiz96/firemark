"""Static production-schema safety contracts."""

from __future__ import annotations

import re
from pathlib import Path

MIGRATION = Path("supabase/migrations/20260729000100_firemark_control_plane.sql")
MULTIMEDIA_MIGRATION = Path("supabase/migrations/20260730000100_firemark_multimedia.sql")


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8").lower()


def test_migration_creates_required_tables_constraints_indexes_and_rls() -> None:
    sql = _sql()
    tables = {
        "generation_runs", "assets", "custody_records", "certificates",
        "verification_events", "delivery_events",
    }
    for table in tables:
        assert f"create table public.{table}" in sql
        assert f"alter table public.{table} enable row level security" in sql
    assert sql.count("gen_random_uuid()") == 6
    assert "^[0-9a-f]{64}$" in sql
    assert "verified_custody_requires_compliance" in sql
    assert "certificate_status in ('active', 'revoked', 'invalid')" in sql
    assert "certificate_public_manifest_redacted" in sql
    for indexed in (
        "run_id_idx", "asset_id_idx", "cert_id_idx", "source_sha256_idx",
        "sealed_sha256_idx", "canonical_hash_idx", "issued_at_idx",
        "verification_events_created_at_idx", "delivery_events_created_at_idx",
    ):
        assert indexed in sql


def test_public_rpc_exposes_only_allowlisted_certificate_fields() -> None:
    sql = _sql()
    match = re.search(
        r"create or replace function public\.get_firemark_public_certificate.*?returns table \((.*?)\)\s*language",
        sql,
        re.DOTALL,
    )
    assert match is not None
    public_signature = match.group(1)
    expected = {
        "cert_id", "asset_id", "run_id", "sealed_sha256", "canonical_hash", "signer_key_id",
        "signer_public_key_b64", "signature_b64", "public_manifest", "certificate_status",
        "issued_at",
    }
    actual = {line.strip().split()[0].rstrip(",") for line in public_signature.splitlines() if line.strip()}
    assert actual == expected
    for private in (
        "prompt_private", "parameters_private", "seed_private", "vault_key",
        "vault_version_id", "custody_receipt", "source_sha256",
    ):
        assert private not in public_signature


def test_schema_has_no_credentials_authorization_or_persisted_urls() -> None:
    sql = _sql()
    for forbidden in (
        "service_role_key text", "app_key text", "authorization_header", "presigned_url",
        "download_url", "provider_credentials", "vault_credentials",
    ):
        assert forbidden not in sql
    delivery = sql.split("create table public.delivery_events", 1)[1].split(");", 1)[0]
    assert "url" not in delivery
    assert "verification_event_id uuid not null references" in delivery


def test_atomic_registration_rpc_is_service_role_only() -> None:
    sql = _sql()
    assert "function public.register_firemark_certificate_bundle" in sql
    assert "language plpgsql" in sql
    assert "security definer" in sql
    assert "immutable certificate conflict" in sql
    assert "from public, anon, authenticated" in sql
    assert "to service_role" in sql


def test_multimedia_migration_extends_immutable_bundle_and_public_allowlist() -> None:
    sql = MULTIMEDIA_MIGRATION.read_text(encoding="utf-8").lower()
    for field in (
        "asset_type", "media_type", "mime_type", "byte_size", "ai_generated",
        "width", "height", "duration_ms", "provider", "model", "source_sha256",
    ):
        assert field in sql
    assert "asset_type in ('image', 'audio')" in sql
    assert "assets_image_hashes_distinct" in sql
    assert "asset_type <> 'image' or source_sha256 <> sealed_sha256" in sql
    assert "firemark.public-audio-reference" not in sql
    assert "create or replace function public.register_firemark_certificate_bundle" in sql
    assert "to anon, authenticated, service_role" in sql
    assert "prompt_private" not in sql.split(
        "returns table (", 1
    )[1].split(")\nlanguage sql", 1)[0]
