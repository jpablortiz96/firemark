-- FIREMARK Control Plane: private evidence, public certificates, and append-only decisions.
create extension if not exists pgcrypto with schema extensions;

create table public.generation_runs (
    id uuid primary key default extensions.gen_random_uuid(),
    run_id text not null unique,
    provider text not null,
    model text not null,
    prompt_private text not null,
    parameters_private jsonb not null,
    seed_private text,
    canonical_hash text not null check (canonical_hash ~ '^[0-9a-f]{64}$'),
    manifest_storage_key text not null,
    manifest_version_id text,
    created_at timestamptz not null
);

create table public.assets (
    id uuid primary key default extensions.gen_random_uuid(),
    asset_id text not null unique,
    run_id text not null references public.generation_runs(run_id),
    media_type text not null,
    file_extension text not null,
    source_sha256 text not null check (source_sha256 ~ '^[0-9a-f]{64}$'),
    sealed_sha256 text not null unique check (sealed_sha256 ~ '^[0-9a-f]{64}$'),
    assets_bucket text not null,
    assets_key text not null,
    assets_version_id text not null,
    vault_bucket text not null,
    vault_key text not null,
    vault_version_id text not null,
    created_at timestamptz not null,
    constraint assets_distinct_hashes check (source_sha256 <> sealed_sha256)
);

create table public.custody_records (
    id uuid primary key default extensions.gen_random_uuid(),
    asset_id text not null unique references public.assets(asset_id),
    custody_receipt jsonb not null,
    retention_mode text not null check (retention_mode in ('COMPLIANCE')),
    retention_until timestamptz not null,
    custody_verified boolean not null default false,
    created_at timestamptz not null,
    constraint verified_custody_requires_compliance
        check (not custody_verified or retention_mode = 'COMPLIANCE')
);

create table public.certificates (
    id uuid primary key default extensions.gen_random_uuid(),
    cert_id text not null unique,
    asset_id text not null unique references public.assets(asset_id),
    run_id text not null references public.generation_runs(run_id),
    source_sha256 text not null check (source_sha256 ~ '^[0-9a-f]{64}$'),
    sealed_sha256 text not null unique check (sealed_sha256 ~ '^[0-9a-f]{64}$'),
    canonical_hash text not null check (canonical_hash ~ '^[0-9a-f]{64}$'),
    signer_key_id text not null,
    signer_public_key_b64 text not null,
    signature_b64 text not null,
    signed_envelope jsonb not null,
    public_manifest jsonb not null,
    certificate_status text not null default 'active'
        check (certificate_status in ('active', 'revoked', 'invalid')),
    issued_at timestamptz not null,
    revoked_at timestamptz,
    revocation_reason text,
    constraint certificate_public_manifest_redacted check (
        public_manifest::text !~*
        '"[^"]*(prompt|parameter|seed|credential|authorization|app[_-]?key|presigned)[^"]*"[[:space:]]*:'
    ),
    constraint certificate_revocation_state check (
        (certificate_status = 'revoked' and revoked_at is not null and revocation_reason is not null)
        or (certificate_status <> 'revoked' and revoked_at is null and revocation_reason is null)
    )
);

create table public.verification_events (
    id uuid primary key default extensions.gen_random_uuid(),
    cert_id text references public.certificates(cert_id),
    presented_sha256 text check (
        presented_sha256 is null or presented_sha256 ~ '^[0-9a-f]{64}$'
    ),
    verification_status text not null check (verification_status in (
        'verified', 'hash_mismatch', 'signature_invalid', 'certificate_revoked',
        'certificate_not_found', 'malformed_evidence'
    )),
    signature_valid boolean not null,
    envelope_valid boolean not null,
    hash_match boolean,
    custody_reference_valid boolean not null,
    safe_reason_code text not null,
    created_at timestamptz not null
);

create table public.delivery_events (
    id uuid primary key default extensions.gen_random_uuid(),
    cert_id text not null references public.certificates(cert_id),
    verification_event_id uuid not null references public.verification_events(id),
    delivery_status text not null check (delivery_status in ('issued', 'blocked', 'storage_failure')),
    safe_reason_code text not null,
    expires_at timestamptz,
    created_at timestamptz not null
);

create index generation_runs_run_id_idx on public.generation_runs(run_id);
create index generation_runs_canonical_hash_idx on public.generation_runs(canonical_hash);
create index assets_asset_id_idx on public.assets(asset_id);
create index assets_run_id_idx on public.assets(run_id);
create index assets_source_sha256_idx on public.assets(source_sha256);
create index assets_sealed_sha256_idx on public.assets(sealed_sha256);
create index certificates_cert_id_idx on public.certificates(cert_id);
create index certificates_canonical_hash_idx on public.certificates(canonical_hash);
create index certificates_issued_at_idx on public.certificates(issued_at);
create index verification_events_created_at_idx on public.verification_events(created_at);
create index delivery_events_created_at_idx on public.delivery_events(created_at);

alter table public.generation_runs enable row level security;
alter table public.assets enable row level security;
alter table public.custody_records enable row level security;
alter table public.certificates enable row level security;
alter table public.verification_events enable row level security;
alter table public.delivery_events enable row level security;

revoke all on table public.generation_runs from anon, authenticated;
revoke all on table public.assets from anon, authenticated;
revoke all on table public.custody_records from anon, authenticated;
revoke all on table public.certificates from anon, authenticated;
revoke all on table public.verification_events from anon, authenticated;
revoke all on table public.delivery_events from anon, authenticated;
grant all on table public.generation_runs to service_role;
grant all on table public.assets to service_role;
grant all on table public.custody_records to service_role;
grant all on table public.certificates to service_role;
grant all on table public.verification_events to service_role;
grant all on table public.delivery_events to service_role;

create or replace function public.get_firemark_public_certificate(p_cert_id text)
returns table (
    cert_id text,
    asset_id text,
    run_id text,
    sealed_sha256 text,
    canonical_hash text,
    signer_key_id text,
    signer_public_key_b64 text,
    signature_b64 text,
    public_manifest jsonb,
    certificate_status text,
    issued_at timestamptz
)
language sql
stable
security definer
set search_path = ''
as $$
    select c.cert_id, c.asset_id, c.run_id, c.sealed_sha256, c.canonical_hash,
           c.signer_key_id, c.signer_public_key_b64, c.signature_b64,
           c.public_manifest, c.certificate_status, c.issued_at
      from public.certificates as c
     where c.cert_id = p_cert_id;
$$;

revoke all on function public.get_firemark_public_certificate(text) from public;
grant execute on function public.get_firemark_public_certificate(text) to anon, authenticated, service_role;

create or replace function public.register_firemark_certificate_bundle(
    p_generation_run jsonb,
    p_asset jsonb,
    p_custody jsonb,
    p_certificate jsonb
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_run_id text := p_generation_run->>'run_id';
    v_asset_id text := p_asset->>'asset_id';
    v_cert_id text := p_certificate->>'cert_id';
begin
    if v_run_id is distinct from p_asset->>'run_id'
       or v_run_id is distinct from p_certificate->>'run_id'
       or v_asset_id is distinct from p_custody->>'asset_id'
       or v_asset_id is distinct from p_certificate->>'asset_id' then
        raise exception using errcode = '23514', message = 'FIREMARK bundle relationship mismatch';
    end if;

    insert into public.generation_runs (
        run_id, provider, model, prompt_private, parameters_private, seed_private,
        canonical_hash, manifest_storage_key, manifest_version_id, created_at
    ) values (
        v_run_id, p_generation_run->>'provider', p_generation_run->>'model',
        p_generation_run->>'prompt_private', p_generation_run->'parameters_private',
        p_generation_run->>'seed_private', p_generation_run->>'canonical_hash',
        p_generation_run->>'manifest_storage_key', p_generation_run->>'manifest_version_id',
        (p_generation_run->>'created_at')::timestamptz
    ) on conflict (run_id) do nothing;

    if not exists (
        select 1 from public.generation_runs r
         where r.run_id = v_run_id
           and to_jsonb(r) - 'id' =
               to_jsonb(jsonb_populate_record(null::public.generation_runs, p_generation_run)) - 'id'
    ) then
        raise exception using errcode = '23505', message = 'FIREMARK immutable run conflict';
    end if;

    insert into public.assets (
        asset_id, run_id, media_type, file_extension, source_sha256, sealed_sha256,
        assets_bucket, assets_key, assets_version_id, vault_bucket, vault_key,
        vault_version_id, created_at
    ) values (
        v_asset_id, v_run_id, p_asset->>'media_type', p_asset->>'file_extension',
        p_asset->>'source_sha256', p_asset->>'sealed_sha256', p_asset->>'assets_bucket',
        p_asset->>'assets_key', p_asset->>'assets_version_id', p_asset->>'vault_bucket',
        p_asset->>'vault_key', p_asset->>'vault_version_id', (p_asset->>'created_at')::timestamptz
    ) on conflict (asset_id) do nothing;

    if not exists (
        select 1 from public.assets a where a.asset_id = v_asset_id
          and to_jsonb(a) - 'id' =
              to_jsonb(jsonb_populate_record(null::public.assets, p_asset)) - 'id'
    ) then
        raise exception using errcode = '23505', message = 'FIREMARK immutable asset conflict';
    end if;

    insert into public.custody_records (
        asset_id, custody_receipt, retention_mode, retention_until, custody_verified, created_at
    ) values (
        v_asset_id, p_custody->'custody_receipt', p_custody->>'retention_mode',
        (p_custody->>'retention_until')::timestamptz,
        (p_custody->>'custody_verified')::boolean, (p_custody->>'created_at')::timestamptz
    ) on conflict (asset_id) do nothing;

    if not exists (
        select 1 from public.custody_records cr where cr.asset_id = v_asset_id
          and to_jsonb(cr) - 'id' =
              to_jsonb(jsonb_populate_record(null::public.custody_records, p_custody)) - 'id'
    ) then
        raise exception using errcode = '23505', message = 'FIREMARK immutable custody conflict';
    end if;

    insert into public.certificates (
        cert_id, asset_id, run_id, source_sha256, sealed_sha256, canonical_hash,
        signer_key_id, signer_public_key_b64, signature_b64, signed_envelope,
        public_manifest, certificate_status, issued_at, revoked_at, revocation_reason
    ) values (
        v_cert_id, v_asset_id, v_run_id, p_certificate->>'source_sha256',
        p_certificate->>'sealed_sha256', p_certificate->>'canonical_hash',
        p_certificate->>'signer_key_id', p_certificate->>'signer_public_key_b64',
        p_certificate->>'signature_b64', p_certificate->'signed_envelope',
        p_certificate->'public_manifest', p_certificate->>'certificate_status',
        (p_certificate->>'issued_at')::timestamptz,
        (p_certificate->>'revoked_at')::timestamptz, p_certificate->>'revocation_reason'
    ) on conflict (cert_id) do nothing;

    if not exists (
        select 1 from public.certificates c where c.cert_id = v_cert_id
          and to_jsonb(c) - 'id' =
              to_jsonb(jsonb_populate_record(null::public.certificates, p_certificate)) - 'id'
    ) then
        raise exception using errcode = '23505', message = 'FIREMARK immutable certificate conflict';
    end if;
    return v_cert_id;
end;
$$;

revoke all on function public.register_firemark_certificate_bundle(jsonb, jsonb, jsonb, jsonb)
    from public, anon, authenticated;
grant execute on function public.register_firemark_certificate_bundle(jsonb, jsonb, jsonb, jsonb)
    to service_role;
