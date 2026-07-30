# FIREMARK frontend architecture

## Scope

The `web/` application is the public interface for FIREMARK's three locked capabilities. It
explains Generate & Seal, renders public Birth Certificates, runs Verify Gate, and requests secure
delivery after a verified result. It does not implement dashboards, accounts, galleries, billing,
administration, or generation controls.

The stack is Next.js App Router, TypeScript, React, and Tailwind CSS. Pages are Server Components
unless browser interaction is required. Native `fetch` is the only HTTP client, and local component
state is sufficient for the verification workflow. FIREMARK Lens adds a browser-local PNG parser,
Web Crypto hashing, and an optional dedicated Worker without introducing an upload service.

## Public and private boundary

The browser may receive:

- the configured public FastAPI base URL;
- the redacted `PublicCertificate` projection;
- a `VerificationResult` containing safe status fields;
- a short-lived delivery URL, but only in one successful delivery response.
- user-selected PNG or MP3 bytes held transiently in local component execution;
- the extracted closed public capsule and locally calculated sealed SHA-256.

The browser must never receive:

- `FIREMARK_DELIVERY_API_KEY` or another bearer credential;
- prompts, generation parameters, or seeds;
- the private canonical manifest;
- vault keys, B2 VersionIds, or custody receipt internals;
- service-role or OpenAI credentials.

Selected file bytes never cross an HTTP boundary. Lens sends only `cert_id` and
`presented_sha256`; it does not send a filename, path, Blob, ArrayBuffer, EXIF, or other PNG chunks.
No browser storage or console logging participates in this path.

The frontend parser projects backend responses onto explicit public fields. It rejects malformed
responses, unsafe URL schemes, and public manifests containing private-field markers. Components
render only that projection.

## Delivery secret boundary

Delivery crosses a dedicated server-only boundary:

```text
Browser
  POST /api/delivery/[certId]
    { cert_id, presented_sha256 }
        |
        v
Next.js route handler
  validates ID + digest
  reads FIREMARK_DELIVERY_API_KEY
  sends Authorization only to FastAPI
        |
        v
FastAPI POST /v1/delivery/{cert_id}
  repeats Verify Gate
  verifies exact stored asset version
  returns short-lived URL only on success
        |
        v
Browser memory (successful response only)
```

The route handler does not log the bearer or URL, does not persist either value, returns
`Cache-Control: private, no-store`, and normalizes all failure responses without copying backend
details. A failed verification never contains a URL.

## Page architecture

| Route | Rendering | Main responsibility |
| --- | --- | --- |
| `/` | Server Component | Product thesis, trust model, capabilities, process, and final CTA. |
| `/certificate/[certId]` | Dynamic Server Component | Fetch and render one allowlisted public certificate. |
| `/verify` | Server shell + Client Component | Validate input, call Verify Gate, and render deterministic outcomes. |
| `/api/delivery/[certId]` | Route handler | Protect the delivery bearer and validate delivery responses. |
| `/api/proof-pack/[certId]` | Route handler | Build a public-only ZIP in memory with no secret or media fetch. |
| `not-found.tsx` | Server Component | Safe unknown-route state. |
| `error.tsx` | Client error boundary | Safe retry without exposing exception details. |
| `loading.tsx` | Server loading UI | Accessible loading skeleton. |

Certificate metadata is descriptive only for valid public records. Invalid, missing, revoked, or
unavailable certificate pages receive `noindex`. The root layout defines canonical, Open Graph, and
Twitter metadata; the landing page includes `SoftwareApplication` structured data.

## API flow and error handling

`src/lib/api.ts` owns public FastAPI calls. It validates certificate IDs and lowercase SHA-256
digests before requests, applies an eight-second `AbortController` timeout, requests JSON, and
parses responses into closed TypeScript contracts. Network, timeout, configuration, malformed
response, and backend failures become `SafeApiError` values with fixed user messages.

The verification UI supports every backend state:

- `verified`
- `hash_mismatch`
- `signature_invalid`
- `certificate_revoked`
- `certificate_not_found`
- `malformed_evidence`

Every result combines text, status iconography, an exact safe reason code, and a recommended next
action. Color is never the sole status signal. Delivery is rendered only for a verified result with
a presented sealed SHA-256.

## FIREMARK Lens

`/verify` offers three modes: local PNG Lens, local MP3 hash verification, and certificate-ID
verification.
Lens accepts only an `image/png` file with a `.png` extension and a maximum size of 25 MiB. Its
dedicated parser validates PNG magic, bounded chunk lengths, per-chunk CRC, one terminal IEND, the
reserved `firemark.public-capsule` key, `tEXt` encoding, the 8 KiB capsule limit, duplicate entries,
closed fields, safe identifiers, HTTPS verification URL, and canonical sorted-key ASCII JSON.

The TypeScript capsule contract is locked to Python `FiremarkPublicCapsuleV1` through a committed
Python-generated fixture asserted by both test suites. `sealed_sha256` is intentionally absent from
the capsule and is calculated over the whole selected file with
`crypto.subtle.digest("SHA-256", fileBytes)`. A module Worker is preferred; unsupported or failed
Worker construction falls back to the same Web Crypto operation on the main thread. Selecting or
resetting a file aborts the Worker/fetch signal and prevents stale state from rendering.

The result separates eight layers: local format and capsule checks; file-hash agreement;
certificate presence; Ed25519 signature; certificate status; B2 custody reference; and delivery
eligibility. B2 and delivery layers are never inferred from browser parsing and are populated only
from `POST /v1/verify`.

Audio verification accepts a bounded `audio/mpeg` `.mp3`, requires an explicit public certificate
ID, validates MP3 magic, and hashes the bytes through the same Web Crypto/Worker boundary. It sends
only `{cert_id, presented_sha256}`. The embedded-capsule layer is explicitly `NOT CHECKED` because
FIREMARK neither alters MP3 bytes nor claims a nonexistent embedded capsule. Successful secure
delivery may be played from the short-lived URL held only in component memory.

Demo fixtures cover one valid sealed PNG, a one-byte-modified structurally valid PNG, and a PNG
without a capsule. They exist only in tests and never provide a control that alters a user's file.

## Public Proof Pack

The certificate page links to `GET /api/proof-pack/[certId]`. This server-side Next.js handler uses
the anonymous public certificate lookup, reprojects the allowlist, and creates a no-store ZIP in
memory. Exact server dependencies are `fflate@0.8.3` for ZIP serialization and
`qrcode-svg@1.1.0` for dependency-free local SVG QR generation.

The pack contains exactly `certificate.json`, `verification-summary.txt`, `public-key.txt`,
`qr-code.svg`, and `README.txt`. It includes no media, private provenance, custody internals,
VersionIds, credential, authorization header, presigned URL, or delivery URL. QR generation makes
no network request and encodes the certificate's public verification URL directly.

## CORS

FastAPI reads `FIREMARK_ALLOWED_ORIGINS` as a strict JSON array. Production origins must use HTTPS;
HTTP is accepted only for `localhost`, `127.0.0.1`, and `::1`. Values must be origins without user
information, paths, queries, or fragments. Wildcards are rejected. The middleware does not enable
credentials and allows only `GET`, `POST`, and `OPTIONS` with `Accept` and `Content-Type` request
headers. App construction and middleware registration perform no network calls.

## Accessibility and motion

The application uses semantic landmarks and headings, labeled inputs, native form submission,
keyboard-operable controls, visible focus states, live regions for loading and results, text plus
icon status communication, and a skip link. Layout is mobile-first and collapses certificate,
verification, and trust grids on narrow screens. `prefers-reduced-motion` disables nonessential
motion.

## Environment and deployment assumptions

`web/.env.example` contains empty placeholders only:

```text
NEXT_PUBLIC_FIREMARK_API_BASE_URL=
FIREMARK_DELIVERY_API_KEY=
FIREMARK_PUBLIC_SITE_URL=
```

`NEXT_PUBLIC_FIREMARK_API_BASE_URL` is intentionally browser-visible. The other values are
server-only. Local secrets belong in ignored `web/.env.local`. Deployment must place the Next.js
server behind HTTPS, configure the exact deployed frontend origin in FastAPI, and provide the
delivery bearer only to the Next.js server runtime.

No deployment has been performed. Demo recording and hackathon submission remain pending.
