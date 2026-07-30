# FIREMARK frontend architecture

## Scope

The `web/` application is the public interface for FIREMARK's three locked capabilities. It
explains Generate & Seal, renders public Birth Certificates, runs Verify Gate, and requests secure
delivery after a verified result. It does not implement dashboards, accounts, galleries, billing,
administration, or generation controls.

The stack is Next.js App Router, TypeScript, React, and Tailwind CSS. Pages are Server Components
unless browser interaction is required. Native `fetch` is the only HTTP client, and local component
state is sufficient for the verification workflow.

## Public and private boundary

The browser may receive:

- the configured public FastAPI base URL;
- the redacted `PublicCertificate` projection;
- a `VerificationResult` containing safe status fields;
- a short-lived delivery URL, but only in one successful delivery response.

The browser must never receive:

- `FIREMARK_DELIVERY_API_KEY` or another bearer credential;
- prompts, generation parameters, or seeds;
- the private canonical manifest;
- vault keys, B2 VersionIds, or custody receipt internals;
- service-role or OpenAI credentials.

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
