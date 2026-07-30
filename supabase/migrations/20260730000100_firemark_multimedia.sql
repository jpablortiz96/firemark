-- FIREMARK multimedia: immutable public-safe media facts and byte-preserving audio sealing.
alter table public.generation_runs
    add column ai_generated boolean not null default true;

alter table public.assets
    add column asset_type text not null default 'image'
        check (asset_type in ('image', 'audio')),
    add column byte_size bigint,
    add column width integer check (width is null or width > 0),
    add column height integer check (height is null or height > 0),
    add column duration_ms bigint check (duration_ms is null or duration_ms > 0);

update public.assets as a
   set byte_size = (cr.custody_receipt->'assets_source'->>'size_bytes')::bigint
  from public.custody_records as cr
 where cr.asset_id = a.asset_id;

alter table public.assets
    alter column byte_size set not null,
    add constraint assets_positive_byte_size check (byte_size > 0),
    drop constraint assets_distinct_hashes,
    add constraint assets_image_hashes_distinct
        check (asset_type <> 'image' or source_sha256 <> sealed_sha256),
    add constraint assets_media_dimensions check (
        (asset_type = 'image' and duration_ms is null and ((width is null) = (height is null)))
        or (asset_type = 'audio' and width is null and height is null)
    );

alter table public.certificates
    add column provider text,
    add column model text,
    add column media_type text check (media_type in ('image', 'audio')),
    add column mime_type text,
    add column byte_size bigint check (byte_size > 0),
    add column ai_generated boolean,
    add column width integer check (width is null or width > 0),
    add column height integer check (height is null or height > 0),
    add column duration_ms bigint check (duration_ms is null or duration_ms > 0);

update public.certificates as c
   set provider = r.provider,
       model = r.model,
       media_type = a.asset_type,
       mime_type = a.media_type,
       byte_size = a.byte_size,
       ai_generated = r.ai_generated,
       width = a.width,
       height = a.height,
       duration_ms = a.duration_ms
  from public.generation_runs as r, public.assets as a
 where r.run_id = c.run_id and a.asset_id = c.asset_id;

alter table public.certificates
    alter column provider set not null,
    alter column model set not null,
    alter column media_type set not null,
    alter column mime_type set not null,
    alter column byte_size set not null,
    alter column ai_generated set not null;

drop function public.get_firemark_public_certificate(text);
create function public.get_firemark_public_certificate(p_cert_id text)
returns table (
    cert_id text,
    asset_id text,
    run_id text,
    provider text,
    model text,
    media_type text,
    mime_type text,
    byte_size bigint,
    ai_generated boolean,
    width integer,
    height integer,
    duration_ms bigint,
    source_sha256 text,
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
    select c.cert_id, c.asset_id, c.run_id, c.provider, c.model, c.media_type,
           c.mime_type, c.byte_size, c.ai_generated, c.width, c.height, c.duration_ms,
           c.source_sha256, c.sealed_sha256, c.canonical_hash, c.signer_key_id,
           c.signer_public_key_b64, c.signature_b64, c.public_manifest,
           c.certificate_status, c.issued_at
      from public.certificates as c
     where c.cert_id = p_cert_id;
$$;

revoke all on function public.get_firemark_public_certificate(text) from public;
grant execute on function public.get_firemark_public_certificate(text)
    to anon, authenticated, service_role;

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
        run_id, provider, model, ai_generated, prompt_private, parameters_private, seed_private,
        canonical_hash, manifest_storage_key, manifest_version_id, created_at
    ) values (
        v_run_id, p_generation_run->>'provider', p_generation_run->>'model',
        (p_generation_run->>'ai_generated')::boolean, p_generation_run->>'prompt_private',
        p_generation_run->'parameters_private', p_generation_run->>'seed_private',
        p_generation_run->>'canonical_hash', p_generation_run->>'manifest_storage_key',
        p_generation_run->>'manifest_version_id', (p_generation_run->>'created_at')::timestamptz
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
        asset_id, run_id, asset_type, media_type, file_extension, byte_size, width, height,
        duration_ms, source_sha256, sealed_sha256, assets_bucket, assets_key, assets_version_id,
        vault_bucket, vault_key, vault_version_id, created_at
    ) values (
        v_asset_id, v_run_id, p_asset->>'asset_type', p_asset->>'media_type',
        p_asset->>'file_extension', (p_asset->>'byte_size')::bigint,
        (p_asset->>'width')::integer, (p_asset->>'height')::integer,
        (p_asset->>'duration_ms')::bigint, p_asset->>'source_sha256',
        p_asset->>'sealed_sha256', p_asset->>'assets_bucket', p_asset->>'assets_key',
        p_asset->>'assets_version_id', p_asset->>'vault_bucket', p_asset->>'vault_key',
        p_asset->>'vault_version_id', (p_asset->>'created_at')::timestamptz
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
        cert_id, asset_id, run_id, provider, model, media_type, mime_type, byte_size,
        ai_generated, width, height, duration_ms, source_sha256, sealed_sha256, canonical_hash,
        signer_key_id, signer_public_key_b64, signature_b64, signed_envelope, public_manifest,
        certificate_status, issued_at, revoked_at, revocation_reason
    ) values (
        v_cert_id, v_asset_id, v_run_id, p_certificate->>'provider', p_certificate->>'model',
        p_certificate->>'media_type', p_certificate->>'mime_type',
        (p_certificate->>'byte_size')::bigint, (p_certificate->>'ai_generated')::boolean,
        (p_certificate->>'width')::integer, (p_certificate->>'height')::integer,
        (p_certificate->>'duration_ms')::bigint, p_certificate->>'source_sha256',
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
