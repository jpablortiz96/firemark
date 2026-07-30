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

The trust model preserves complete Genblaze provenance privately, embeds a closed redacted
FIREMARK public capsule in supported media, signs a FIREMARK Seal Envelope with Ed25519, and
retains original evidence in immutable object storage. Public verification connects those records
without exposing private evidence or credentials.

`source_sha256` and `sealed_sha256` are deliberately distinct and must never be treated as
interchangeable:

- `source_sha256` identifies the generated provider output before media embedding.
- `sealed_sha256` identifies the final distributed file after the FIREMARK public capsule has been
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

The repository contains the local Trust Kernel, Genblaze provenance integration, B2 Custody
Kernel, Control Plane, and production Generate & Seal path for PNG images. The live B2 checkpoint
has proved COMPLIANCE retention and the live Supabase checkpoint has proved RLS, atomic
registration, public projection, events, and revocation. Generate & Seal now wires the official
OpenAI SDK, private canonical provenance, capsule embedding, custody, sealed storage, signing,
atomic registration, and authenticated delivery. Its live evidence remains pending the explicit
owner-run checkpoint; ordinary tests remain zero-network.

## Roadmap

Completed milestones are repository foundation, Trust Kernel, SealEnvelopeV1, Genblaze
provenance, B2 Custody and live COMPLIANCE proof, FastAPI Control Plane, Supabase schema and live
verification, and the local production wiring for Generate & Seal. Remaining work is the public
Birth Certificate frontend, Verify Gate user experience, deployment, one real demo generation,
and hackathon submission.

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
| `POST` | `/v1/generate-and-seal` | Admin-authenticated, idempotent PNG generation and sealing. |
| `POST` | `/v1/delivery/{cert_id}` | Delivery-authenticated Verify Gate requiring the exact `sealed_sha256`. |

The public certificate includes public identifiers, `sealed_sha256`, `canonical_hash`, signer
material, status, issuance time, verification URL, and the redacted capsule projection (which binds
`source_sha256`). Prompts, parameters, seeds, storage locations, VersionIds, and custody receipt
internals remain on the private service-role path.

The Verify Gate records verification before making a delivery decision. It asks the injected B2
delivery adapter to confirm the recorded exact VersionId and then issue a short-lived private
download only after status, signature, envelope, custody references, and presented
`sealed_sha256` all pass. The raw URL exists only in the successful HTTP serializer; the domain
result, event repository, logs, exceptions, and failure responses contain no URL.

The migration at `supabase/migrations/20260729000100_firemark_control_plane.sql` creates six RLS
tables. Anonymous and authenticated roles receive no direct table access. A safe public certificate
RPC exposes an allowlist, while a service-role-only PostgreSQL RPC atomically and idempotently
registers the run, asset, custody record, and certificate.

## Generate & Seal architecture

`api.firemark.bootstrap.build_runtime()` is the explicit production composition root. Repository
selection is controlled by `FIREMARK_REPOSITORY_BACKEND`; `memory` remains available for ordinary
tests and `supabase` selects the lazy service-role adapter. Application construction performs no
network request. OpenAI, B2, signing, and delivery dependencies are constructed only when their
operation is requested, and each boundary remains injectable.

`POST /v1/generate-and-seal` requires `Authorization: Bearer <FIREMARK_ADMIN_API_KEY>` and a safe
`Idempotency-Key`. The request follows this order:

1. Generate one PNG through the injected provider and hash the untouched bytes as
   `source_sha256`.
2. Build and verify the complete private canonical Genblaze Manifest and obtain its
   `canonical_hash`.
3. Embed `FiremarkPublicCapsuleV1` into a deterministic PNG `tEXt` chunk and hash the resulting
   distributable bytes as `sealed_sha256`.
4. Retain the raw source and full Manifest in the B2 vault under COMPLIANCE retention, verifying
   bytes and exact VersionIds.
5. Upload and re-download the sealed PNG at
   `sealed/{sha256[0:2]}/{sha256[2:4]}/{sha256}.png` using allowlisted metadata only.
6. Construct and sign `SealEnvelopeV1`, then atomically register the complete certificate bundle
   in Supabase. No successful API response is returned before verified custody and registration.

The idempotency key deterministically names the private run, asset, and certificate. A private
request fingerprint stored inside `parameters_private` returns the same completed result for an
identical retry and rejects a conflicting retry with HTTP 409. Failed pre-registration work can be
retried safely; persisted partial locations are carried only by internal safe errors and never
returned as credentials or URLs.

The public capsule contains only its fixed schema version, certificate/run/asset identifiers,
`canonical_hash`, `source_sha256`, signer key ID, verification URL, and issuance time. It excludes
`sealed_sha256` because embedding that value would create a circular hash. It also excludes prompts,
parameters, seeds, provider responses and credentials, full manifests, signatures, private keys,
B2 VersionIds, and presigned URLs. Re-embedding an identical capsule is byte-deterministic;
conflicting, duplicate, malformed, oversized, or non-canonical capsules fail closed. PNG pixel data
is preserved.

The official `openai` SDK is pinned exactly. GPT Image requests select PNG output and consume the
documented base64 result; DALL-E requests use their documented response-format option. The adapter
also supports the official URL response shape through an HTTPS-only, hostname-allowlisted, bounded,
non-redirecting download. Authentication, rate-limit, invalid-request, safety, timeout,
unavailable, and malformed-response failures become safe normalized codes. Provider bytes,
response bodies, URLs, and credentials are never logged or persisted. The deterministic fake
provider is test-only, reports `ai_generated=false`, and cannot silently run in production.

Generation and delivery use distinct `SecretStr` bearer credentials and constant-time comparison.
Missing or invalid bearer credentials return 401; public health, Birth Certificate, and Verify
routes remain anonymous. The prompt is sent only to the selected provider and retained only in the
private generation run.

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
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
python -m pytest
python -m pytest --cov=api.firemark --cov-report=term-missing --cov-fail-under=95
python -m ruff check .
python -m mypy api scripts
python scripts\smoke_trust.py
python scripts\smoke_genblaze_roundtrip.py
python scripts\smoke_b2_custody.py --help
python scripts\smoke_b2_custody.py
python scripts\smoke_generate_and_seal.py --help
python scripts\smoke_generate_and_seal.py
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
FIREMARK_REPOSITORY_BACKEND=
FIREMARK_ADMIN_API_KEY=
FIREMARK_DELIVERY_API_KEY=
FIREMARK_SIGNING_PRIVATE_KEY_B64=
FIREMARK_SIGNING_PUBLIC_KEY_B64=
OPENAI_API_KEY=
OPENAI_IMAGE_MODEL=
OPENAI_IMAGE_SIZE=
FIREMARK_GENERATION_TIMEOUT_SECONDS=
FIREMARK_MAX_GENERATED_IMAGE_BYTES=
```

Prefer a current `sb_publishable_` public key and a distinct current `sb_secret_` backend key.
Legacy Supabase JWT keys remain compatible only when their embedded role is respectively `anon` or
`service_role`; role-mismatched and unknown key families fail closed. Do not place the backend key
in a browser, public certificate, log, fixture, or committed file.
Configuration failures print only field status, safe reason codes, URL hostnames, and key-family
labels; they never print credential values, JWT claims, or complete URLs.

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

If that live checkpoint has already persisted its atomic bundle and event rows but stops before
revocation, do not repeat the original smoke. Resume only the existing unambiguous bundle:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\resume_supabase_control_plane_checkpoint.py
D:\firemark\.venv\Scripts\python.exe scripts\resume_supabase_control_plane_checkpoint.py --live `
  --output-report .artifacts\supabase-control-plane-report.json --force
```

The resume command performs no registration RPC and inserts no verification or delivery event. It
validates existing row counts and the public allowlist, revokes through the service-role repository,
proves the revoked Verify Gate result locally, scans only the smoke rows for secret material, and
writes the final safe report. An identical prior checkpoint revocation is accepted idempotently;
missing, ambiguous, or differently revoked bundles fail closed.

The `.env` file is optional for ordinary tests. If used, populate it locally and never commit it.
The settings loader reads process environment variables explicitly; it does not automatically load
the `.env` file. Only explicitly live CLI checkpoints load the ignored repository `.env`.

Review the non-live Generate & Seal command first. It constructs no provider, B2, or Supabase
client and exits with informational code 2. The explicitly live command makes exactly one real
OpenAI image request and may incur provider and storage cost:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\smoke_generate_and_seal.py
D:\firemark\.venv\Scripts\python.exe scripts\smoke_generate_and_seal.py --live `
  --output-report .artifacts\generate-and-seal-report.json --force
```

The live checkpoint verifies source, canonical, sealed, signature, custody, registration, public
projection, Verify Gate, authenticated delivery, delivered bytes, embedded capsule, and a bounded
database credential scan. Its safe report includes evidence identifiers, hashes, safe object keys,
VersionIds, retention timestamps, package versions, and stage results. It excludes the prompt,
all credentials and bearer headers, signing private material, full private Manifest, provider
response, and raw delivery URL.

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

The historical B2 Custody smoke uses a local fixture and therefore does not prove provider
generation. The B2 and Supabase live checkpoints are environment-specific evidence, not a claim
that the complete application is deployed. Generate & Seal has comprehensive zero-network contract
tests, but no real OpenAI generation evidence exists until the owner runs its explicit live command.
The public frontend, Birth Certificate experience, Verify Gate user experience, deployment, real
demo generation, and hackathon submission remain pending. B2 custody spans multiple objects and is
not cross-object atomic; a registration failure can leave safe, billable partial storage that must
be inspected before operational cleanup.
