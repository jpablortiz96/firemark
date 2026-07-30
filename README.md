# FIREMARK

FIREMARK is a production-oriented application for creating an auditable chain between generated
media, its provenance, its sealed representation, and the decision to release it.

## Product thesis

Generated media should not be delivered on trust alone. FIREMARK is intended to preserve evidence
from generation through sealing and to make successful verification a prerequisite for delivery.

## Problem statement

Media generation systems can produce provenance, but that evidence can become detached from the
asset as it moves through storage and delivery. A recipient needs a clear way to determine what was
generated, what was sealed, who signed the evidence, and whether the delivered artifact still
matches that evidence.

## Locked product scope

FIREMARK has exactly three product capabilities:

1. **Generate & Seal** — orchestrate generation, preserve provenance, and create a sealed artifact.
2. **Public Birth Certificate** — expose a redacted, public record for a sealed artifact.
3. **Verify Gate** — block delivery unless verification succeeds.

## Trust model

The planned trust model preserves Genblaze provenance, embeds a redacted manifest in supported
media, signs a FIREMARK Seal Envelope with Ed25519, and retains original evidence in immutable
object storage. Public verification is intended to connect those records without exposing private
evidence or credentials.

`source_sha256` and `sealed_sha256` are deliberately distinct and must never be treated as
interchangeable:

- `source_sha256` identifies the generated provider output before media embedding.
- `sealed_sha256` identifies the final distributed file after the Genblaze manifest has been
  embedded.

The local Trust Kernel signs the complete canonical FIREMARK Seal Envelope with Ed25519. A valid
signature proves that the envelope bytes have not changed since a holder of the corresponding
private key signed them. It also binds the envelope to the expected public-key fingerprint and
`signer_key_id`.

The signature does not prove that generation occurred, that a provider's provenance claims are
true, that an asset was stored immutably, or that the named signer was authorized. Those assurances
require the provider, custody, identity, and operational controls that are outside this milestone.
The detached signature is not embedded into media because that would create a circular dependency
with `sealed_sha256`.

## Repository status

The repository contains the local Trust Kernel, the Genblaze Local Provenance Roundtrip, the B2
Custody Kernel, and the FIREMARK Control Plane. The Control Plane exposes redacted Birth
Certificates, reconstructs and verifies signed evidence, records append-oriented decisions, and
requires verification before private delivery. A production-oriented Supabase migration, lazy
service-role adapter, and bounded live verification checkpoint are included. Ordinary tests remain
zero-network; external Supabase evidence exists only after an owner explicitly runs the live
checkpoint successfully against a disposable project.

## Control Plane

The FastAPI application is built by `api.firemark.app.create_app()`. Construction creates no
external clients and accepts injected repository and delivery-storage implementations. Local and
test use can rely on the deterministic in-memory repository. The Supabase adapter is constructed
explicitly from complete server-side settings and creates its client only on its first operation.

The HTTP surface is intentionally small:

| Method | Path | Contract |
| --- | --- | --- |
| `GET` | `/healthz` | Local process health; external dependencies are not contacted. |
| `GET` | `/v1/certificates/{cert_id}` | Redacted public Birth Certificate. |
| `POST` | `/v1/verify` | Signature, envelope, custody-reference, status, and optional hash verification. |
| `POST` | `/v1/delivery/{cert_id}` | Verify Gate requiring the exact `sealed_sha256`. |

The public certificate includes only public identifiers, `sealed_sha256`, `canonical_hash`, signer
material, the redacted public manifest, status, issuance time, and its verification URL. Prompts,
parameters, seeds, `source_sha256`, storage locations, VersionIds, and custody receipt internals
remain on the private service-role path.

The Verify Gate records verification before making a delivery decision. It asks the injected B2
delivery adapter for an exact-version, short-lived private download only after status, signature,
envelope, custody references, and presented `sealed_sha256` all pass. The raw URL exists only in the
successful HTTP serializer; the domain result, event repository, logs, exceptions, and failure
responses contain no URL.

The migration at `supabase/migrations/20260729000100_firemark_control_plane.sql` creates six RLS
tables. Anonymous and authenticated roles receive no direct table access. A safe public certificate
RPC exposes an allowlist, while a service-role-only PostgreSQL RPC atomically and idempotently
registers the run, asset, custody record, and certificate.

## Genblaze local provenance roundtrip

The roundtrip creates a deterministic local PNG fixture. The fixture is not AI-generated, is not
provider-generated, and is never production evidence. It builds a real Genblaze Run and Manifest
through the installed public builders, embeds the complete Manifest into a PNG, extracts and
verifies it, and binds its hashes into a signed FIREMARK Seal Envelope.

The Genblaze asset digest and FIREMARK container digest cover different bytes:

- The Genblaze output `Asset.sha256` equals `source_sha256`, the digest of the PNG before embedding.
- `sealed_sha256` is the digest of the final full-manifest PNG after Genblaze adds its iTXt chunk.
- `Manifest.verify()` verifies the canonical Manifest and declared digest coverage. It does not
  re-hash the post-embedding PNG container.
- FIREMARK binds the final distributed container through `sealed_sha256` in its signed envelope.

Genblaze 0.3.8 supports two materially different payloads. Full mode embeds the complete,
independently verifiable Manifest inline in PNG metadata. Privacy redaction cannot remain a full
Manifest because removing prompt, parameters, or seed would invalidate its canonical hash. The
installed `EmbedPolicy` therefore requires pointer mode, which emits only `schema_version`,
`canonical_hash`, and a local fixture `manifest_uri`. In 0.3.8, `SmartEmbedder` stores that pointer
as a `.genblaze.json` sidecar and leaves the corresponding public PNG bytes unchanged. Durable
pointer resolution is provided by the B2 Custody Kernel, while public capsule publication remains
deferred.

## B2 Custody Kernel

FIREMARK uses two separately credentialed private buckets:

- The assets bucket contains normal source objects and full private manifests. These objects can be
  downloaded through short-lived presigned GET URLs and cleaned up deliberately.
- The vault bucket contains the same source evidence and full manifests under COMPLIANCE Object
  Lock. Vault objects are never sent through generic cleanup paths.

The deterministic key layout is:

```text
assets/{sha256[0:2]}/{sha256[2:4]}/{sha256}.{extension}
manifests/{run_id}/{canonical_hash}.json
public/{cert_id}/pointer.json
public/{cert_id}/signed-envelope.json
public/{cert_id}/custody-receipt.json
vault/sources/{sha256[0:2]}/{sha256[2:4]}/{sha256}.{extension}
vault/manifests/{run_id}/{canonical_hash}.json
```

The Genblaze `canonical_hash` identifies the canonical manifest contract. FIREMARK separately
hashes the complete serialized manifest bytes for storage integrity; these digests have different
coverage and must not be conflated.

Object Lock enabled on a bucket only means the bucket can accept retention parameters. FIREMARK
claims active custody only after reading both object retentions back from B2, confirming
`COMPLIANCE`, confirming a sufficient retain-until date, and re-downloading the exact bytes.
COMPLIANCE retention cannot be shortened or bypassed by FIREMARK. A retained smoke object remains
stored and billable until its retention expires.

Assets and vault application keys must be different and scoped to their respective private
buckets. The vault key must be able to write retained versions, read retention, head and download
objects, and attempt normal deletion without a governance-bypass capability. The assets key needs
normal private read, write, head, and delete capabilities. Never make either bucket public.

### Accepted Genblaze version matrix

The authorized matrix is `genblaze-core==0.3.8`, `genblaze-cli==0.3.6`, and
`genblaze-s3==0.3.6`. Adapter metadata declares `genblaze-core>=0.3.4,<0.4`; public protocol tests
pin this relationship. The upstream adapter internally imports `genblaze_core._version`. FIREMARK
accepts that upstream implementation risk only with exact pins and contract tests, and FIREMARK
source never imports underscore-prefixed Genblaze modules itself.

FIREMARK uses public `S3StorageBackend` and `ObjectStorageSink` integration for normal Genblaze
pipeline compatibility. Direct boto3 calls implement custody controls because genblaze-s3 0.3.6
does not expose sufficient retention inspection, exact VersionId proof, or corroborated delete
denial. FIREMARK also uses boto3 presigning because genblaze-s3 `presigned_get()` performs a remote
preflight even when constructed with `preflight=False`.

## Local setup

Use Python 3.12 from Windows PowerShell:

```powershell
cd D:\firemark
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
python -m pytest
python -m pytest --cov=api.firemark --cov-report=term-missing --cov-fail-under=95
python -m ruff check .
python -m mypy api scripts
python scripts\smoke_trust.py
python scripts\smoke_genblaze_roundtrip.py
python scripts\smoke_b2_custody.py --help
python scripts\smoke_b2_custody.py
```

Start the local API with the injected in-memory repository and no external checks:

```powershell
D:\firemark\.venv\Scripts\python.exe -m uvicorn api.firemark.app:create_app `
  --factory --host 127.0.0.1 --port 8000
```

OpenAPI is available locally at `http://127.0.0.1:8000/docs`. The default in-memory process starts
empty; certificate registration is an internal service operation, not a public endpoint.

For the Supabase checkpoint, create a disposable project manually, review and apply the migration
through the Supabase CLI, then configure these ignored local values:

```text
SUPABASE_URL=
SUPABASE_PUBLISHABLE_KEY=
SUPABASE_SERVICE_ROLE_KEY=
FIREMARK_PUBLIC_BASE_URL=
FIREMARK_DELIVERY_TTL_SECONDS=
```

The publishable key must be an `sb_publishable_` key and the backend key must be a distinct
`sb_secret_` key. Do not place the backend key in a browser, public certificate, log, fixture, or
committed file.

Review the zero-network behavior first, then let a single owner run the live checkpoint:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\smoke_supabase_control_plane.py
D:\firemark\.venv\Scripts\python.exe scripts\smoke_supabase_control_plane.py --live `
  --output-report .artifacts\supabase-control-plane-report.json --force
```

Without `--live`, the command constructs no Supabase client, performs no network request, and exits
with informational code 2. The live run creates uniquely named synthetic local-fixture rows, proves
private-table RLS and the public RPC allowlist, exercises atomic and idempotent registration,
rejects a conflicting duplicate, appends one verification event and one URL-free blocked delivery
event, and revokes the smoke certificate. It makes no provider or B2 request. The safe report omits
credentials, private evidence, signed envelopes, prompts, parameters, manifests, authorization
headers, and URLs.

The `.env` file is optional for ordinary tests. If used, populate it locally and never commit it.
The settings loader reads process environment variables explicitly; it does not automatically load
the `.env` file. Only the explicitly live B2 smoke command loads the ignored repository `.env`.

Configure two private buckets locally by copying `.env.example` to `.env`. The vault bucket must
have Object Lock enabled when it is created. Use one-day retention only for a deliberate
development smoke run; the current production target is 90 days and must be selected explicitly.

Run real B2 verification only after reviewing costs and capabilities:

```powershell
python scripts\smoke_b2_custody.py --live `
  --output-report .artifacts\b2-custody-report.json `
  --force
python -m pytest -m live_b2 --run-live-b2
```

The smoke uses a deterministic local PNG, not AI-generated or provider-generated content. It
creates two persistent COMPLIANCE-retained vault versions and intentionally leaves them in place.
The report contains safe keys, hashes, versions, and retention timestamps, but never credentials or
the presigned URL. The default command without `--live` exits with code 2 and makes no network call.

After a failed live smoke, use the separate read-only access diagnostic before authorizing another
custody attempt. Its default command exits with informational code 2 and performs no network call:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\diagnose_b2_access.py
D:\firemark\.venv\Scripts\python.exe scripts\diagnose_b2_access.py --live
```

The live diagnostic is checkpoint-specific and contacts only the configured Backblaze endpoint. It
uses `head_bucket`, `list_objects_v2` with `MaxKeys=1`, and the vault Object Lock configuration
read. It never prints object names or credentials and never uploads, deletes, presigns, changes
retention, writes a report, or repeats the custody smoke.

After read-only access passes, inspect objects persisted by an interrupted custody smoke without
repeating or mutating the smoke workflow. The default command exits with informational code 2 and
makes no network call; the explicitly live command lists current FIREMARK keys, streams at most 10
MiB per object for in-memory integrity checks, and reads vault retention without changing it:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\inspect_b2_smoke_state.py
D:\firemark\.venv\Scripts\python.exe scripts\inspect_b2_smoke_state.py --live
```

The inspector prints only allowlisted metadata and normalized safe errors. It never prints object
bodies or complete manifests, persists downloaded bytes, uploads, deletes, copies, presigns, or
changes bucket or Object Lock settings.

When that inspector confirms one valid source pair, one valid manifest pair, and active
`COMPLIANCE` retention, resume only the interrupted post-persistence checkpoint:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\resume_b2_custody_checkpoint.py
D:\firemark\.venv\Scripts\python.exe scripts\resume_b2_custody_checkpoint.py --live `
  --output-report .artifacts\b2-custody-resume-report.json `
  --force
```

The default recovery command exits with informational code 2 and performs no network call. The
explicitly live recovery discovers VersionIds, counts relevant delete markers, verifies the
private presigned source download, challenges the exact retained vault-manifest version, and only
then deletes and verifies absence of the two exact unlocked assets versions. It never uploads,
copies, changes retention, removes vault objects or delete markers, or persists the presigned URL.
The safe report is written only after every mandatory stage passes.

## Security

Credentials, private signing keys, raw evidence, generated media, and local databases must remain
outside version control. The example environment file contains variable names only. Never place
production secrets in source files, logs, fixtures, or issue reports.

Generate local provisioning files only when needed:

```powershell
python scripts\keygen.py
```

The private Base64 file is written under `.secrets/` and must never be copied into `evidence/` or
committed. The script attempts restrictive file permissions, but it cannot guarantee Windows ACL
policy. Apply an appropriate ACL, restrict account access, maintain a secure backup, and use managed
key custody before production deployment. Never print the private value.

Run the local trust smoke test independently with:

```powershell
python scripts\smoke_trust.py
```

Its PASS output demonstrates local cryptographic behavior with ephemeral keys and deterministic
test bytes only. It is not production evidence.

Run the zero-network Genblaze contract smoke test with temporary artifacts:

```powershell
python scripts\smoke_genblaze_roundtrip.py
```

Persist ignored local fixtures for manual CLI inspection:

```powershell
python scripts\smoke_genblaze_roundtrip.py `
  --output-dir .artifacts\genblaze-roundtrip `
  --force
genblaze verify .artifacts\genblaze-roundtrip\full_embedded.png
genblaze extract .artifacts\genblaze-roundtrip\full_embedded.png --format summary
```

Do not use `genblaze verify --fetch` against `full_embedded.png`: its embedded Manifest declares
the pre-embedding source digest, while `--fetch` would hash the post-embedding container.

The following command documents a known 0.3.8 limitation:

```powershell
genblaze extract .artifacts\genblaze-roundtrip\public_redacted.png
```

It reports `PointerSidecarError` because the public privacy payload is a pointer sidecar rather
than a complete Manifest. Inspect the safe pointer JSON in
`.artifacts\genblaze-roundtrip\public_embedded_payload.json`; it intentionally cannot reconstruct
or verify a complete Manifest without resolving `manifest_uri`.

## Honest limitations

The B2 Custody Kernel does not prove provider generation; its smoke content is a local fixture. The
Control Plane migration, Supabase adapter, and live-checkpoint implementation have comprehensive
zero-network contract tests, but live Supabase evidence exists only after the owner runs the explicit
command successfully. Real provider generation, the frontend, authentication/authorization
policy for delivery callers, public inline capsules, and deployment remain unimplemented. The B2
live proof is environment-specific, creates non-atomic state across four objects, and cannot make
the complete application production-ready.
