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

`source_sha256` and `sealed_sha256` retain distinct roles and must never be treated as
interchangeable labels:

- `source_sha256` identifies the generated provider output before media embedding.
- `sealed_sha256` identifies the final distributed file after the media-specific sealing strategy.

For PNG images those values must differ because capsule embedding changes the container. MP3 audio
uses an explicitly byte-preserving sealing strategy, so both roles intentionally contain the same
digest. Audio is verified by `cert_id` plus the locally calculated hash; FIREMARK does not claim an
embedded audio capsule.

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
Kernel, Control Plane, and production Generate & Seal path for PNG images and MP3 audio. The live B2 checkpoint
has proved COMPLIANCE retention and the live Supabase checkpoint has proved RLS, atomic
registration, public projection, events, and revocation. Generate & Seal now wires the official
OpenAI SDK, private canonical provenance, capsule embedding, custody, sealed storage, signing,
atomic registration, and authenticated delivery. The completed live Generate & Seal checkpoint
proved that entire path against real OpenAI, B2, and Supabase services. Ordinary tests remain
zero-network.

## Roadmap

Completed milestones are repository foundation, Trust Kernel, SealEnvelopeV1, Genblaze
provenance, B2 Custody and live COMPLIANCE proof, FastAPI Control Plane, Supabase schema and live
verification, live Generate & Seal, the local public web experience, FIREMARK Lens, and Public
Proof Pack export. Remaining work is owner-operated deployment, demo recording, and hackathon
submission.

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
| `POST` | `/v1/generate-and-seal` | Admin-authenticated, idempotent image or audio generation and sealing. |
| `POST` | `/v1/delivery/{cert_id}` | Delivery-authenticated Verify Gate requiring the exact `sealed_sha256`. |

The public certificate includes public identifiers, provider/model, categorical and MIME media
types, byte size, safe dimensions/duration, both asset hashes, `canonical_hash`, signer material,
status, issuance time, verification URL, and a redacted media projection. Prompts, parameters,
seeds, storage locations, VersionIds, and custody receipt internals remain private.

The Verify Gate records verification before making a delivery decision. It asks the injected B2
delivery adapter to confirm the recorded exact VersionId and then issue a short-lived private
download only after status, signature, envelope, custody references, and presented
`sealed_sha256` all pass. The raw URL exists only in the successful HTTP serializer; the domain
result, event repository, logs, exceptions, and failure responses contain no URL.

The migration at `supabase/migrations/20260729000100_firemark_control_plane.sql` creates six RLS
tables. Anonymous and authenticated roles receive no direct table access. A safe public certificate
RPC exposes an allowlist, while a service-role-only PostgreSQL RPC atomically and idempotently
registers the run, asset, custody record, and certificate.
`20260730000100_firemark_multimedia.sql` adds public-safe multimedia facts, conditional image hash
constraints, and the expanded atomic/public projections without exposing private evidence.

## Generate & Seal architecture

`api.firemark.bootstrap.build_runtime()` is the explicit production composition root. Repository
selection is controlled by `FIREMARK_REPOSITORY_BACKEND`; `memory` remains available for ordinary
tests and `supabase` selects the lazy service-role adapter. Application construction performs no
network request. Provider, B2, signing, and delivery dependencies are constructed only when their
operation is requested, and each boundary remains injectable.

`POST /v1/generate-and-seal` requires `Authorization: Bearer <FIREMARK_ADMIN_API_KEY>` and a safe
`Idempotency-Key`. The request follows this order:

1. Generate one PNG through OpenAI/Google Gemini or one MP3 through ElevenLabs and hash the
   untouched bytes as `source_sha256`.
2. Build and verify the complete private canonical Genblaze Manifest and obtain its
   `canonical_hash`.
3. For PNG, embed `FiremarkPublicCapsuleV1` into a deterministic `tEXt` chunk. For MP3, create a
   closed `FiremarkPublicAudioReferenceV1` without changing or pretending to embed audio bytes.
4. Retain the raw source and full Manifest in the B2 vault under COMPLIANCE retention, verifying
   bytes and exact VersionIds.
5. Upload and re-download sealed media at a content-addressed `.png` or `.mp3` key using
   allowlisted metadata only.
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

Google Gemini and ElevenLabs use bounded, non-redirecting HTTPS adapters against their documented
REST endpoints. Gemini accepts exactly one PNG. ElevenLabs requests `mp3_44100_128` and accepts
only bounded `audio/mpeg` bytes. Their errors use the same safe normalized categories; credentials,
prompts/text, response bodies, and URLs are excluded from logs and public records.

### Google Gemini image generation

FIREMARK calls the Google Gemini API directly with a Google AI Studio key. The generation contract
is the official Interactions API:

```text
POST https://generativelanguage.googleapis.com/v1beta/interactions
x-goog-api-key: <GEMINI_API_KEY>
Content-Type: application/json
Accept: application/json

{"model": "gemini-3.1-flash-image",
 "input": [{"type": "text", "text": "<prompt>"}],
 "response_format": {"type": "image", "mime_type": "image/jpeg",
                     "aspect_ratio": "1:1", "image_size": "1K",
                     "delivery": "uri"},
 "stream": false, "background": false, "store": false}
```

The request is unary and synchronous: `stream`, `background` and `store` are all explicitly false.
The API key travels only in `x-goog-api-key`; no `Authorization: Bearer` header is ever sent, the
model field never carries a duplicate `models/` prefix, and GMI Cloud is never contacted.

The Interactions `ImageResponseFormat` accepts `image/jpeg` for URI delivery. `image/png` is not a
valid value there and is rejected with HTTP 400 `INVALID_REQUEST`, so FIREMARK asks for the accurate
JPEG source and produces the PNG carrier itself.

#### Why URI delivery

`delivery: "uri"` keeps the interaction response small. A large inline Base64 image forces a
multi-megabyte body through the same connection that carries the interaction metadata; a failure
while receiving or decoding it cannot be distinguished from an unfinished generation, which makes
the whole operation ambiguous and unrecoverable without a new billable request.

With URI delivery the flow splits into two independently bounded operations:

1. A normal non-streamed `POST` reads the small interaction metadata and requires
   `status: completed` with exactly one final image reference — read from `output_image.uri`, or
   from an `image` content block inside `steps`. Inline Base64 remains a defensive parser path but
   is not the requested delivery mode.
2. A separate client downloads the bytes with bounded connect, read, write and pool timeouts, a
   hard byte ceiling, an enforced content type, PNG magic-byte validation, and an immediate
   SHA-256.

The provider URI is transient private provider data. It is never printed, logged, persisted,
checkpointed, reported, attached to an exception, returned in public certificate data, or written
to Supabase or B2 metadata. Before any download FIREMARK requires HTTPS, no credentials in the URL,
no fragment, a bounded length, and a Google-hosted allowlisted host; it rejects `localhost`,
loopback, private, link-local, reserved and multicast addresses. Redirects are rejected by default;
at most one is followed and only after the destination passes the same validation. The API key is
presented only to `generativelanguage.googleapis.com` — a signed Google storage or user-content URL
carries its own authorization and receives no credential.

A download whose content type is not the requested `image/jpeg` is rejected with
`PROVIDER_SOURCE_MIME_UNSUPPORTED` before the body is read. FIREMARK never relabels bytes it did
not request.

#### Source versus sealed media

The provider source and the distributable sealed asset are different artifacts with different
formats, different hashes and different storage:

| | Source | Sealed |
| --- | --- | --- |
| Format | `image/jpeg` (exact provider bytes) | `image/png` |
| Hash | `source_sha256` | `sealed_sha256` |
| Storage | private assets + COMPLIANCE vault, `.jpg` | content-addressed assets key, `.png` |
| Capsule | none | `FiremarkPublicCapsuleV1` in a `tEXt` chunk |

`source_sha256` is always the SHA-256 of the untouched provider JPEG. It is never computed from the
normalized PNG, and the two digests always differ. The public certificate describes the sealed PNG:
`media_type: image`, `mime_type: image/png`, `sealed_sha256` of the capsule-bearing file, alongside
the source digest that was already public by contract. `provider_source_mime_type` stays in private
generation metadata, so representing a JPEG source needs no database migration.

#### Deterministic PNG normalization

`api/firemark/generation/normalization.py` decodes the validated JPEG source and re-encodes it as a
PNG before capsule embedding. It runs entirely offline through pinned Pillow:

```text
Google JPEG source bytes → structural decode → deterministic PNG → capsule embedding → sealed PNG
```

It rejects malformed images, decompression bombs, excessive dimensions (>16384 px) and excessive
pixel counts (>50 MP). Orientation is applied deterministically from EXIF, the pixel buffer is
copied into a fresh image so no EXIF, comment, ICC profile or provider metadata survives, alpha is
preserved only when the source genuinely carries it, and the PNG encoder uses fixed options so
identical input always produces identical output. The only lossy step is decoding the JPEG the
provider produced; FIREMARK adds none of its own.

A PNG source — for example OpenAI GPT Image — is carried through untouched, so existing evidence
stays byte identical and no normalization step is recorded for it.

The private Genblaze manifest records the transformation on the generation step:

```json
{"operation": "normalize_image",
 "input_mime_type": "image/jpeg",
 "output_mime_type": "image/png",
 "purpose": "firemark_public_capsule_embedding"}
```

That record and `provider_source_mime_type` stay private. The prompt and other private
transformation metadata are never exposed publicly.

The certificate identity is exact:

| Field | Value |
| --- | --- |
| `provider` | `google_gemini` |
| `model` | `gemini-3.1-flash-image` |
| `provider_model_name` | `Nano Banana 2` |
| `media_type` | `image` |
| `mime_type` | `image/png` |
| `ai_generated` | `true` |

A read-only model preflight is **diagnostic-only** and is not part of the generation path. A model
listing can behave differently from the Interactions endpoint, so it must never block a valid
generation. Read-only diagnostics live in a separate command that generates nothing and therefore
costs nothing:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\diagnose_gemini_access.py
D:\firemark\.venv\Scripts\python.exe scripts\diagnose_gemini_access.py --live
```

The live diagnostic reads `v1beta/models` and `v1beta/models/{model}`. It prints HTTP status, the
normalized safe category, a safe reason code, a transport-versus-endpoint failure domain, the
configured model, whether that model appears in the listing, and bounded supported method names.
It never prints the API key, a prompt, a raw response, a provider message, an authorization header,
a request identifier, quota metadata, or account metadata.

Transport problems are never collapsed into a single category. Each relevant `httpx` failure class
carries its own safe reason code, and an HTTP 5xx carries its real status instead:

| Failure class | Normalized code | Safe reason code |
| --- | --- | --- |
| `ConnectTimeout` | `timeout` | `TRANSPORT_CONNECT_TIMEOUT` |
| `ReadTimeout` | `timeout` | `TRANSPORT_READ_TIMEOUT` |
| `WriteTimeout` | `timeout` | `TRANSPORT_WRITE_TIMEOUT` |
| `PoolTimeout` | `timeout` | `TRANSPORT_POOL_TIMEOUT` |
| `ProxyError` | `unavailable` | `TRANSPORT_PROXY_FAILURE` |
| `ConnectError` | `unavailable` | `DNS_RESOLUTION_FAILURE` or `TRANSPORT_CONNECT_FAILURE` |
| `ReadError` | `unavailable` | `TRANSPORT_READ_FAILURE` |
| `WriteError` | `unavailable` | `TRANSPORT_WRITE_FAILURE` |
| `RemoteProtocolError` | `unavailable` | `TRANSPORT_REMOTE_PROTOCOL_FAILURE` |
| `LocalProtocolError` | `unavailable` | `TRANSPORT_LOCAL_PROTOCOL_FAILURE` |
| `DecodingError` | `unavailable` | `TRANSPORT_DECODING_FAILURE` |
| any other `TransportError` | `unavailable` | `TRANSPORT_FAILURE` |

Only the normalized code, HTTP status when available, safe reason code, and the exception class
name from a strict allowlist are persisted. Exception messages, `repr`, requests, responses,
headers, prompts, API keys and URIs are never stored.

The isolated smoke submits at most one generation request only when `--live` is explicitly supplied:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\smoke_gemini_image_provider.py
D:\firemark\.venv\Scripts\python.exe scripts\smoke_gemini_image_provider.py --live
```

It writes `.artifacts/gemini-image-provider-checkpoint.json` atomically before submission, after a
definitive provider rejection, and immediately after valid source bytes are received. The exact
provider JPEG is stored as `source.jpg` under the ignored
`.artifacts/gemini-image-provider-private/` tree. Once bytes exist, recovery reuses them and Gemini
is never called again.

The stage table reports thirteen safe stages:

```text
configuration_validation        interaction_metadata_validation   deterministic_png_normalization
request_construction            image_uri_validation              normalized_png_validation
prior_checkpoint_classification jpeg_download                     checkpoint_completion
checkpoint_before_submission    jpeg_validation
interaction_submission          source_hash
```

Safe output includes the provider, configured model, provider model name, operation ID, HTTP status,
normalized category, safe reason code, source MIME, sealed MIME, source byte size, normalized PNG
byte size, source hash and whether URI delivery was used. It never includes the URI, prompt, API
key, raw response or exception message.

#### Retrying an operation versus starting a new one

These are different decisions and FIREMARK keeps them separate.

| Situation | Meaning | Command |
| --- | --- | --- |
| Definitive rejection, no bytes | The provider refused the request. Nothing was produced. | `--allow-definitive-retry` |
| Ambiguous outcome | A timeout, a lost connection after submission, or an uncaptured result. Generation may or may not have happened and may already be billed. | blocked; requires `--start-new-operation-after-ambiguous` |

An ambiguous checkpoint fails closed with `AMBIGUOUS_PRIOR_SUBMISSION` and is **never** retried and
never rewritten — the run does not even update its stage rows. `--allow-definitive-retry` cannot
unblock it.

To move forward, an operator explicitly starts a *new* operation. This is a new billable
generation, not a retry:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\smoke_gemini_image_provider.py --live `
  --start-new-operation-after-ambiguous
```

The option requires `--live`. It atomically moves the preserved record, byte for byte, to
`.artifacts/gemini-image-provider-checkpoints/gemini-image-provider-ambiguous-<UTC>.json`, mints a
new operation ID, and allows exactly one new submission. The archive is never edited, never marked
retryable, and never discarded; it stays inside the ignored `.artifacts/` tree. If the new operation
is also ambiguous, it fails closed again and needs fresh authorization.

Generation and delivery use distinct `SecretStr` bearer credentials and constant-time comparison.
Missing or invalid bearer credentials return 401; public health, Birth Certificate, and Verify
routes remain anonymous. The prompt is sent only to the selected provider and retained only in the
private generation run.

## Public web experience

The Next.js App Router application lives in `web/`. It uses React Server Components for the
landing and certificate routes, a focused Client Component for Verify Gate interaction, and one
server-side route handler for authenticated delivery. The browser calls only the public
certificate and verification endpoints. It never receives `FIREMARK_DELIVERY_API_KEY`; the route
handler exchanges that server-only bearer for a short-lived URL after FastAPI independently
repeats verification.

| Surface | Route | Purpose |
| --- | --- | --- |
| Landing | `/` | Product thesis, Generate & Seal, Birth Certificate, and Verify Gate. |
| Certificate | `/certificate/[certId]` | Redacted public certificate with trust summary and technical details. |
| Verify Gate | `/verify` | Certificate and optional sealed-hash verification. |
| Delivery proxy | `POST /api/delivery/[certId]` | Server-only authenticated delivery exchange. |
| Proof Pack | `GET /api/proof-pack/[certId]` | Ephemeral ZIP containing public verification evidence. |

The typed frontend client validates certificate IDs, SHA-256 digests, safe response shapes, public
manifest fields, and URL schemes. Requests have bounded timeouts and normalized errors; raw
backend exceptions are not shown. Short-lived delivery URLs remain only in the successful browser
response and component memory. They are not logged or written to storage.

### FIREMARK Lens and Public Proof Packs

FIREMARK Lens makes file verification the primary `/verify` experience. The browser accepts only
PNG files up to 25 MiB, reads PNG chunks and CRCs locally, extracts the exact
`FiremarkPublicCapsuleV1` canonical `tEXt` payload, and calculates the complete file SHA-256 through
Web Crypto. A Web Worker performs hashing when available, with a main-thread Web Crypto fallback.
The selected bytes, filename, local path, and calculated evidence are never uploaded, logged, or
persisted. Only `{cert_id, presented_sha256}` is sent to the existing public Verify API.

Lens reports eight independent layers: file format, embedded capsule, sealed hash, certificate
presence, Ed25519 signature, certificate status, B2 custody reference, and delivery eligibility.
Local parsing never claims to prove remote custody; the final decision comes from Verify Gate.
Missing or malformed capsules stop before any API call, while modified, revoked, and unregistered
assets remain blocked.

The audio mode accepts bounded MP3 files, validates and hashes them locally, and requires the user
to supply the public `cert_id`. It transmits only `{cert_id, presented_sha256}` and marks the
embedded-capsule layer `NOT CHECKED`. After a successful Verify Gate decision, the short-lived
delivery URL may feed an in-memory browser audio player and is never persisted.

An active Birth Certificate offers `Download Proof Pack`. Its server-side route fetches only the
public certificate projection and creates an in-memory ZIP containing `certificate.json`, a text
summary, Ed25519 public key, locally generated SVG QR code, and verification instructions. It
fetches no media, uses no backend bearer, creates no presigned URL, and persists nothing.

Three-minute demo flow:

1. Open a public Birth Certificate and download its Proof Pack.
2. Open `/verify`, show the local-processing privacy badge, and drop the valid sealed PNG.
3. Show the automatically discovered certificate, local hash, eight PASS layers, and enabled delivery.
4. Select the one-byte-modified demo fixture and show hash mismatch with delivery blocked.
5. Select the no-capsule PNG and show that Lens stops locally without calling Verify Gate.
6. Open the Proof Pack and show its five public-only entries and offline QR code.

FastAPI CORS is driven by `FIREMARK_ALLOWED_ORIGINS`, a strict JSON list. HTTPS origins are
required except for explicit `localhost`, `127.0.0.1`, or `::1` development origins. Wildcards,
credentials in origins, paths, queries, fragments, and credentialed CORS are rejected. The default
allows only `http://localhost:3000` and `http://127.0.0.1:3000`. Application construction remains
zero-network.

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
GEMINI_API_KEY=
GEMINI_IMAGE_MODEL=
ELEVENLABS_API_KEY=
ELEVENLABS_VOICE_ID=
ELEVENLABS_MODEL_ID=
FIREMARK_GENERATION_TIMEOUT_SECONDS=
FIREMARK_MAX_GENERATED_IMAGE_BYTES=
FIREMARK_MAX_GENERATED_AUDIO_BYTES=
FIREMARK_ALLOWED_ORIGINS=
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

Configure the local web application separately in ignored `web/.env.local`:

```text
NEXT_PUBLIC_FIREMARK_API_BASE_URL=http://127.0.0.1:8000
FIREMARK_DELIVERY_API_KEY=
FIREMARK_PUBLIC_SITE_URL=http://localhost:3000
```

Only `NEXT_PUBLIC_FIREMARK_API_BASE_URL` is browser-visible. The delivery bearer and public site
configuration stay server-side. Start both local processes in separate PowerShell terminals:

```powershell
D:\firemark\.venv\Scripts\python.exe -m uvicorn api.firemark.app:create_app `
  --factory --host 127.0.0.1 --port 8000
```

```powershell
cd D:\firemark\web
npm install
npm run dev
```

Run the frontend quality gate with:

```powershell
cd D:\firemark\web
npm run lint
npm run typecheck
npm run test
npm run build
```

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

The multimodal checkpoint proves one Google Gemini PNG and one ElevenLabs MP3 without using OpenAI or an
alternate provider. Its non-live mode constructs no external client and exits with informational
code 2. Live mode uses separate atomic checkpoints, persists generated bytes before B2 or Supabase,
and resumes each modality independently without issuing a second provider request:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\smoke_multimodal_generate_and_seal.py
D:\firemark\.venv\Scripts\python.exe scripts\smoke_multimodal_generate_and_seal.py --live `
  --output-report .artifacts\multimodal-generate-and-seal-report.json --force
```

The Google Gemini checkpoint verifies its embedded public PNG capsule. The ElevenLabs checkpoint confirms
the byte-preserving MP3 strategy and the detached `cert_id + sha256` verification contract. Both
paths validate exact B2 VersionIds, COMPLIANCE retention, Supabase registration, public projection,
Verify Gate, authenticated delivery, and delivered-byte integrity. If a provider call starts but
its outcome cannot be durably captured, recovery fails closed instead of risking a duplicate call.

The full live smoke writes `.artifacts/generate-and-seal-checkpoint.json` atomically before its
first remote write and updates it after custody, sealed-asset persistence, registration, and final
verification. Raw source and private Manifest working files are stored separately under the
ignored `.artifacts/generate-and-seal-private/` tree; the safe checkpoint contains only recovery
identifiers, hashes, exact object versions, retention timestamps, and local paths. It never stores
the prompt, credentials, private key, provider response, object bytes, or a transient URL.

If a production Generate & Seal operation stops after provider generation, do not repeat the live
smoke and do not make another provider request. Review the provider-free command first, then let a
single owner explicitly resume the checkpoint:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\resume_generate_and_seal_checkpoint.py
D:\firemark\.venv\Scripts\python.exe scripts\resume_generate_and_seal_checkpoint.py --live `
  --output-report .artifacts\generate-and-seal-report.json --force
```

Non-live recovery exits with informational code 2 and constructs no OpenAI, B2, or Supabase
client. Live recovery never constructs or calls OpenAI. It reads the safe checkpoint first,
validates bounded exact vault versions and their active COMPLIANCE retention, reconstructs the
same capsule and sealed bytes, reuses an identical sealed version when present, registers the
certificate atomically and idempotently, and completes verification and delivery. It never creates
a new vault source or Manifest version, changes retention, deletes a vault object, or persists a
delivery URL. A pre-checkpoint legacy bundle can be discovered through B2, but recovery returns
`INCOMPLETE_EVIDENCE` without writes when exact capsule IDs or timestamps cannot be recovered.

Exact-version read-after-write verification uses one shared bounded retry budget: at most five
attempts and ten seconds total with short backoff. Only temporary `NoSuchKey`, `NoSuchVersion`,
`NotFound`, absent immediate retention, and retryable transport failures are retried. Permission,
credential, bucket, Object Lock mode, expired retention, wrong VersionId, malformed response, and
hash failures fail immediately. Every head, download, and retention request includes the exact
VersionId, and retention timestamps are normalized to UTC with safe sub-second service
normalization.

When Generate & Seal reaches B2 but fails before registration, isolate custody without repeating
the provider request or contacting Supabase:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\smoke_generate_and_seal_b2.py
D:\firemark\.venv\Scripts\python.exe scripts\smoke_generate_and_seal_b2.py --live `
  --output-report .artifacts\generate-and-seal-b2-report.json --force
```

The live B2-only checkpoint uses deterministic local fixture provenance, retains only its source
and private Manifest versions under COMPLIANCE, verifies every exact version, and deletes the
temporary sealed assets version by exact VersionId. It makes no OpenAI or Supabase request and
never deletes a vault version.

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
generation by itself. The completed Generate & Seal checkpoint provides separate live evidence for
the combined path, but neither that checkpoint nor the local web build claims that the complete
application is deployed. The responsive public frontend, Birth Certificate experience, Verify Gate,
and secure delivery proxy are implemented and tested locally. The deployment layer is ready, but
the remote Railway and Vercel deployments, demo recording, and hackathon submission remain pending.
B2 custody spans multiple objects and is not cross-object atomic; a registration failure can leave
safe, billable partial storage that must be inspected before operational cleanup.

## Production deployment readiness

The repository includes a non-root Python 3.12 Docker image and supported Railway configuration for
the FastAPI backend, security headers for the Next.js frontend, zero-network CI gates, a safe
environment inventory, and a read-only deployed-stack smoke that reuses the completed certificate.
No production service has been deployed by this repository checkpoint.

Follow [the production deployment runbook](docs/deployment.md) for the exact Railway-first then
Vercel sequence, required variables, CORS update, rollback, and safe smoke procedure. The Vercel
project root is `web/`; the Railway health check is `/healthz`. Review readiness and non-live smoke
locally with:

```powershell
D:\firemark\.venv\Scripts\python.exe scripts\check_production_readiness.py
D:\firemark\.venv\Scripts\python.exe scripts\smoke_deployed_stack.py
```

The second command constructs no HTTP or external-service client and exits with informational code
2. Live deployed verification must be run only after both final HTTPS domains are configured. Demo
recording and hackathon submission remain pending.
