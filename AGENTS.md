# FIREMARK — engineering context

Durable project context, conventions, and quality gates. Read this before editing.

## Product

FIREMARK gives AI-generated assets a cryptographically verifiable **Birth Certificate**.

> Every AI asset ships with a Birth Certificate — or it does not ship at all.

Exactly three product capabilities, and no others:

1. **Generate & Seal** — orchestrate generation, preserve provenance, create a sealed artifact.
2. **Public Birth Certificate** — expose a redacted public record for a sealed artifact.
3. **Verify Gate** — block delivery unless verification succeeds.

## Architecture

| Layer | Implementation |
| --- | --- |
| Backend | FastAPI, built by `api.firemark.app.create_app()` (zero-network construction) |
| Composition root | `api.firemark.bootstrap.build_runtime()` — every external client is lazy and injectable |
| Frontend | Next.js App Router in `web/` (Vercel project root is `web/`) |
| Control Plane | Supabase, six RLS tables + service-role-only atomic registration RPC |
| Custody | Backblaze B2, two separately credentialed private buckets |
| Immutability | B2 Object Lock `COMPLIANCE` retention on the vault bucket |
| Provenance | Genblaze private canonical manifests (`genblaze-core==0.3.8`) |
| Signing | Ed25519 `SealEnvelopeV1`, detached signature |
| Public capsule | `FiremarkPublicCapsuleV1` in a deterministic PNG `tEXt` chunk |
| Verification | Verify Gate, FIREMARK Lens (zero-upload PNG), local MP3 hash |
| Hosting | Railway (backend, health check `/healthz`), Vercel (frontend) |

`source_sha256` and `sealed_sha256` are never interchangeable. `source_sha256` is the provider
output before embedding; `sealed_sha256` is the distributed file after the media-specific sealing
strategy. PNG values must differ. MP3 sealing is byte-preserving, so both intentionally match, and
audio is verified with `cert_id` + locally computed SHA-256 (no embedded audio capsule is claimed).

## Providers

| Media | Provider | Model source of truth |
| --- | --- | --- |
| Image | OpenAI | `OPENAI_IMAGE_MODEL` |
| Image | Google Gemini | `GEMINI_IMAGE_MODEL` |
| Audio | ElevenLabs | `ELEVENLABS_MODEL_ID` |

**Do not implement Replicate. Do not implement GMI Cloud. GMI Cloud is not Google Gemini.**
`GMI_API_KEY` and `REPLICATE_API_TOKEN` exist in settings only as unused reserved names.

### Google Gemini contract

Google AI Studio keys authenticate directly with the Gemini API through `x-goog-api-key`.
Generation uses the official **Interactions API**:

```text
POST https://generativelanguage.googleapis.com/v1beta/interactions
{"model": "<GEMINI_IMAGE_MODEL>",
 "input": [{"type": "text", "text": "<prompt>"}],
 "response_format": {"type": "image", "mime_type": "image/jpeg",
                     "aspect_ratio": "1:1", "image_size": "1K"}}
```

Headers: `x-goog-api-key`, `Content-Type: application/json`, `Accept: application/json`,
`Accept-Encoding: identity`. Keys are snake_case; this is the Interactions REST schema, not
`generateContent`. Never send `Authorization: Bearer`. Never prefix the model with `models/`.

**Send only fields the model's own examples document.** The generic Interactions OpenAPI schema
advertises capabilities no single model necessarily implements. `delivery` is valid in that generic
schema but absent from the `gemini-3.1-flash-image` examples, and sending it produced HTTP 400
`INVALID_REQUEST`. `image/png` is likewise not a valid `ImageResponseFormat` MIME value.
`FORBIDDEN_REQUEST_FIELDS` names every field that must never be emitted — `delivery`, `stream`,
`background`, `store`, `response_modalities`, `generationConfig`, `tools`,
`previous_interaction_id`, `contents` — and the smoke asserts their absence before submitting.

The image arrives **inline** as Base64 in `output_image.data` or an `image` content block inside
`steps`. Never require a URI and never download a second resource; the API key is only ever
presented to `generativelanguage.googleapis.com`. Read the JSON body as a bounded HTTP/1.1 stream
with redirects disabled and `Accept-Encoding: identity`, and fail closed on truncated or malformed
JSON.

### Safe Google error details

A bare `HTTP_400` cannot be diagnosed. For non-2xx responses extract exactly two structured facts:
`error.status` (`[A-Z0-9_]{1,64}`) and `google.rpc.BadRequest` → `fieldViolations[].field`
(`[A-Za-z0-9_.\[\]-]{1,160}`, at most 16). Surface them as `PROVIDER_ERROR_STATUS=` and
`PROVIDER_INVALID_FIELDS=`. Never persist or print `error.message`, the violation description, raw
details, the raw response, the request body, the prompt, the API key, the interaction ID or headers.
Never invent a field name Google did not supply.

### Source versus sealed media

They are different artifacts. Never conflate them:

| | Source | Sealed |
| --- | --- | --- |
| Format | `image/jpeg` (exact provider bytes) | `image/png` |
| Hash | `source_sha256` | `sealed_sha256` |
| Storage | assets + COMPLIANCE vault, `.jpg` | content-addressed assets key, `.png` |

`source_sha256` is the SHA-256 of the untouched provider bytes and is **never** computed from the
normalized PNG. `GeneratedImage` carries `source_mime_type`, `source_extension`, `width` and
`height`; it does not assume PNG. `provider_source_mime_type` lives in private generation metadata,
so a JPEG source needs no migration.

### Deterministic PNG normalization

`api/firemark/generation/normalization.py` is the only place a source format is converted. It is
offline, uses pinned Pillow, and must stay deterministic: fixed PNG options, EXIF orientation
applied, pixel buffer copied into a fresh image so no EXIF/comment/ICC/provider metadata survives,
alpha kept only when genuinely present, and bounds on dimensions (16384 px) and pixels (50 MP).
Malformed images and decompression bombs fail closed. The only lossy step is decoding the provider's
JPEG — never add another.

A PNG source is carried through untouched so existing evidence stays byte identical. The private
manifest records `{"operation": "normalize_image", "input_mime_type": ..., "output_mime_type":
"image/png", "purpose": "firemark_public_capsule_embedding"}` on the generation step, and it stays
private.

Certificate identity for the current image model must be exactly:

```text
provider:            google_gemini
model:               gemini-3.1-flash-image
provider_model_name: Nano Banana 2
media_type:          image
mime_type:           image/png
ai_generated:        true
```

Marketing names live only in `api/firemark/generation/provider_identity.py` and never replace the
real provider or model ID. `provider_model_name` is derived at projection time — it is not a
database column, so adding a model needs no migration.

### Preflight policy

A read-only model preflight is **diagnostic-only** and is not on the generation path. A model
listing endpoint can behave differently from the generation endpoint, so it must never block a
valid generation. Read-only probes live in `scripts/diagnose_gemini_access.py`.

Never collapse failures into one broad category. These stay distinguishable:

```text
AUTHENTICATION_FAILURE  PERMISSION_DENIED  QUOTA_OR_BILLING_FAILURE  RATE_LIMIT
MODEL_UNSUPPORTED       INVALID_REQUEST    TIMEOUT                   PROVIDER_UNAVAILABLE
MALFORMED_RESPONSE      NON_PNG_RESPONSE   RESPONSE_TOO_LARGE        SAFE_UNEXPECTED_FAILURE
```

Every relevant `httpx` failure class carries its own safe reason code so a DNS problem, a read
timeout, a truncated body and an HTTP 5xx are never confused: `TRANSPORT_CONNECT_TIMEOUT`,
`TRANSPORT_READ_TIMEOUT`, `TRANSPORT_WRITE_TIMEOUT`, `TRANSPORT_POOL_TIMEOUT`,
`TRANSPORT_PROXY_FAILURE`, `DNS_RESOLUTION_FAILURE`, `TRANSPORT_CONNECT_FAILURE`,
`TRANSPORT_READ_FAILURE`, `TRANSPORT_WRITE_FAILURE`, `TRANSPORT_REMOTE_PROTOCOL_FAILURE`,
`TRANSPORT_LOCAL_PROTOCOL_FAILURE`, `TRANSPORT_DECODING_FAILURE`, `TRANSPORT_FAILURE`.

Persist only the normalized code, the HTTP status when available, the safe reason code, the
exception class name from `SAFE_EXCEPTION_TOKENS`, and allowlisted structured field paths. Never
persist an exception message, `repr`, request, response, headers, prompt or API key.

## Security rules

Never expose, log, persist, or print:

- prompts and TTS text (private to the generation run only)
- API keys, bearer credentials, authorization headers
- signing private keys, Supabase service credentials, B2 application keys
- private manifest contents, raw provider responses
- presigned URLs, transient delivery URLs, temporary provider media URLs

Additional rules:

- **Never print the contents of `.env`.** Settings load from the process environment; only
  explicitly `--live` CLI checkpoints call `load_dotenv` on the ignored repository `.env`.
- Ordinary tests must be **zero-network**. Mock all transport.
- Delivery URLs exist only transiently in a successful response and component memory.
- Do not use `localStorage` or `sessionStorage` for sensitive information.
- Configuration errors print only field status, safe reason codes, URL hostnames, and key-family
  labels — never credential values, JWT claims, or complete URLs.

## Live checkpoint discipline

Live commands cost money and touch irreversible storage. Rules:

- Every live command is gated behind an explicit `--live`. Without it, no client is constructed and
  the command exits with informational code **2**.
- Persist safe atomic state before submission, after a definitive provider rejection, immediately
  after valid generated bytes, and before/after each irreversible B2/Supabase stage.
- Once generated bytes are stored locally, recovery **reuses them**; the provider is never called
  again. B2, Supabase, certificate, verification, and delivery may resume.
- An ambiguous outcome (timeout, connection lost after submission, uncaptured result) **fails
  closed**. Never auto-resubmit and never silently switch provider or model.
- A definitive rejection with no captured bytes may be retried only with explicit operator
  authorization (`--allow-definitive-retry`).

**Retrying an operation is not the same as starting a new one.** A blocked checkpoint is preserved
verbatim: never edited, never marked retryable, never discarded, and never rewritten — not even its
stage rows. `--allow-definitive-retry` covers only the *first* definitive rejection of an operation.
Beyond that an operator passes one of the new-operation options (both require `--live`), which
atomically archive the record to
`.artifacts/gemini-image-provider-checkpoints/gemini-image-provider-{definitive,ambiguous}-<UTC>.json`,
mint a new operation ID, and authorize exactly one new submission:

| Prior class | Option |
| --- | --- |
| `definitive_rejection` (one retry left) | `--allow-definitive-retry` |
| `definitive_rejection_exhausted` | `--start-new-operation-after-definitive` |
| `ambiguous` | `--start-new-operation-after-ambiguous` |

Each option refuses every state it was not designed for. Starting a new operation is a new billable
generation, and the CLI says so before it runs. A second failure fails closed again.
- ElevenLabs starts only after the Gemini image flow completes.

Safe checkpoints live under the ignored `.artifacts/` tree; private bytes go in a separate
`*-private/` subtree and are referenced only by local path.

## Quality gates

Run from `D:\firemark` in PowerShell:

```powershell
D:\firemark\.venv\Scripts\python.exe -m pip check
D:\firemark\.venv\Scripts\python.exe -m pytest
D:\firemark\.venv\Scripts\python.exe -m pytest --cov=api.firemark --cov-report=term-missing --cov-fail-under=95
D:\firemark\.venv\Scripts\python.exe -m ruff check .
D:\firemark\.venv\Scripts\python.exe -m mypy api scripts
D:\firemark\.venv\Scripts\python.exe scripts\smoke_gemini_image_provider.py
D:\firemark\.venv\Scripts\python.exe scripts\diagnose_gemini_access.py
D:\firemark\.venv\Scripts\python.exe scripts\smoke_multimodal_generate_and_seal.py
```

```powershell
cd D:\firemark\web
npm test
npm run lint
npm run typecheck
npm run build
```

Coverage must stay at or above **95%** for `api.firemark`. mypy runs in `strict` mode over
`api` and `scripts`. Ruff uses `line-length = 100` with rules `B, E4, E7, E9, F, I, UP`.

## Conventions

- Python 3.12 only; the interpreter is `D:\firemark\.venv\Scripts\python.exe`.
- Pydantic models are `extra="forbid"` and `frozen=True`; secrets use `SecretStr`.
- Provider adapters are bounded, non-redirecting HTTPS clients with explicit byte limits, and
  normalize every failure into a safe code. They never leak a raw body into an exception.
- Application construction performs no network request. External clients are built only when their
  operation runs, and every boundary is injectable for tests.
- `genblaze-core==0.3.8`, `genblaze-cli==0.3.6`, `genblaze-s3==0.3.6` are exact pins. FIREMARK
  source never imports underscore-prefixed Genblaze modules.

## Do not

- Run any `--live` command on the user's behalf.
- Commit, push, or apply migrations automatically.
- Deploy Railway or Vercel.
- Rewrite unrelated working code.
