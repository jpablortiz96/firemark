# FIREMARK trust model

What a FIREMARK certificate proves, what it deliberately does not, and how the boundaries are
enforced.

> Precision matters more than reassurance here. Every claim below maps to code, a migration, a test
> or a safe report.

---

## What FIREMARK proves

For an active certificate and a file you hold:

1. **Byte identity.** The file hashes to the `sealed_sha256` recorded in the certificate. Not
   "looks similar" — the exact bytes.
2. **Signature integrity.** The `SealEnvelopeV1` was signed by a holder of a specific Ed25519
   private key. A valid signature proves the envelope bytes have not changed since signing, and
   binds the envelope to the expected public-key fingerprint and `signer_key_id`.
3. **Provenance commitment.** The envelope commits to exactly one canonical Genblaze manifest via
   `canonical_hash`. The manifest cannot be swapped without breaking the signature.
4. **Custody references.** The source and manifest exist in the Backblaze B2 vault at exact
   `VersionId`s, under active Object Lock COMPLIANCE retention with a sufficient retain-until date —
   verified by reading retention *back from B2*, not by assuming it.
5. **Live status.** The certificate is not revoked at the moment of verification.
6. **Delivery integrity.** Bytes released through the Verify Gate come from the exact recorded
   object version, and can be re-hashed by the recipient against the certificate.

---

## What FIREMARK does not claim

Being explicit here is a feature.

| Not claimed | Why |
| --- | --- |
| That a provider's own provenance claims are true | FIREMARK records what the provider returned. It cannot audit the provider's internals. |
| That the named signer was **authorized** | The signature proves key possession, not authority. Identity and operational controls are outside this milestone. |
| That generation occurred as described | It proves the evidence chain is intact, not that the world matched the record. |
| That an asset is "real", "safe", "true" or "not a deepfake" | FIREMARK makes origin and integrity of *registered* assets verifiable. It is not a detector. |
| That all media carries embedded proof | Only sealed PNG carries a capsule. MP3 verification uses `cert_id` + local SHA-256. |
| **Tamper-proof** | FIREMARK is **tamper-evident**. It cannot prevent modification; it makes modification detectable. |
| That custody is cross-object atomic | It is not. See [limitations](#known-limitations). |

---

## Threat model

### Adversary: someone modifies the delivered file

**Detected.** Any byte change alters `sealed_sha256`. The Verify Gate requires the exact digest and
delivery is blocked. FIREMARK Lens detects this locally, before any network call.

### Adversary: someone edits the certificate database

**Detected.** Certificate fields are covered by the Ed25519-signed envelope. Editing a row without
the private key produces a signature that does not verify. The envelope also references immutable
B2 objects whose retention cannot be shortened.

### Adversary: someone swaps the retained source or manifest

**Prevented for the retention window.** Vault objects are written under Object Lock **COMPLIANCE**.
FIREMARK itself cannot shorten or bypass that retention, and neither can an operator holding
FIREMARK's own credentials. The vault key deliberately lacks a governance-bypass capability, and
vault objects never enter a cleanup path.

### Adversary: someone substitutes a different object version at the same key

**Detected.** Every head, download and retention request carries the exact `VersionId`, and those
versions are bound into the signed envelope. A certificate points at a specific immutable object
generation, not at a mutable key.

### Adversary: someone re-signs a modified envelope

**Requires the private signing key.** That key never leaves the server, is never logged, never
enters a report or checkpoint, and never appears in an exception. Compromising it is the explicit
single point of failure and is why managed key custody is listed as production work.

### Adversary: someone tries to read prompts or private provenance from the public record

**Prevented at the database boundary.** Anonymous and authenticated Postgres roles have **no direct
table access**. The public projection is a service-defined RPC exposing an allowlist. Prompts, TTS
text, parameters, seeds, storage locations, `VersionId`s and custody internals are never included.

### Adversary: someone replays a delivery URL

**Bounded.** Delivery URLs are short-lived, issued only after a passing Verify Gate, and exist only
in the successful HTTP serializer. They are never logged, persisted, checkpointed, reported or
attached to an exception.

### Failure mode: a provider call outcome is unknown

**Fails closed.** An ambiguous result — a timeout, a lost connection after submission, an uncaptured
response — never triggers an automatic retry. The checkpoint is preserved verbatim and an operator
must explicitly authorize a new, clearly-labelled billable operation.

---

## Evidence zones

<img src="assets/diagrams/trust-boundaries.svg" alt="Four trust zones: public, private, secret and immutable" width="100%">

| Zone | Contents | Enforcement |
| --- | --- | --- |
| **Public** | Identifiers, provider/model, media and MIME types, byte size, both hashes, `canonical_hash`, signer key ID and public key, signature, status, issuance time, verification URL, redacted media projection | Allowlisted projection RPC |
| **Private** | Prompt/TTS text, provider parameters, seed, complete manifest, buckets, object keys, `VersionId`s, custody receipt internals, request fingerprint | RLS; service role only |
| **Secret** | Ed25519 private key, provider API keys, Supabase service-role key, B2 application keys, admin and delivery bearers, presigned and transient URLs | Never serialized anywhere |
| **Immutable** | Retained provider source, retained canonical manifest, at exact `VersionId`s | B2 Object Lock COMPLIANCE |

Only two things cross outward: a **signature** from the secret zone, and a **`canonical_hash`** from
the private zone.

---

## Local verification behaviour

FIREMARK Lens runs entirely in the browser for both supported media. The selected bytes, filename,
local path and computed evidence are never uploaded, logged or persisted. Exactly two values leave
the browser: the public **certificate ID** and the locally computed **SHA-256**. No file bytes,
Base64, `ArrayBuffer`, `Blob`, `File`, `FormData` or multipart body is ever constructed, and an
optional MP3 preview uses a local object URL that is revoked when the file changes and on unmount.

A `sha256` query parameter is never treated as verification evidence — the local file is the only
source of truth.

Lens reports eight independent layers: file format, embedded capsule, sealed hash, certificate
presence, Ed25519 signature, certificate status, B2 custody reference and delivery eligibility.

- **PNG.** Accepts files up to 25 MiB, parses chunks and CRCs locally, extracts the exact
  `FiremarkPublicCapsuleV1` canonical `tEXt` payload and computes the full-file SHA-256 through Web
  Crypto (Web Worker where available, main-thread fallback). A missing or malformed capsule stops
  the flow **before any API call**.
- **MP3.** Accepts bounded MP3 files up to 50 MiB. The MP3 structure is proved from the bytes
  themselves — an ID3 tag or a valid MPEG frame sync — never from the browser-supplied MIME type,
  which is only used to reject an obviously wrong selection early. The browser computes the
  SHA-256, retrieves the public certificate by `cert_id`, and requires `media_type: audio`,
  `mime_type: audio/mpeg`, two well-formed digests and `source_sha256 == sealed_sha256` before the
  local hash is compared. Only then is the Verify Gate consulted.

  Audio reports its own seven layers — local processing, MP3 format, public certificate, media
  contract, byte-preserving seal, local file hash, cryptographic verification — because there is no
  embedded capsule to check. Lens does not imply a proof that does not exist, and a hash mismatch is
  decided locally without contacting the Verify Gate at all.

Local parsing never claims to prove remote custody. The final decision always comes from the Verify
Gate.

---

## Key material

The local Trust Kernel signs the complete canonical `SealEnvelopeV1` with Ed25519. The detached
signature is **not** embedded into media, because doing so would create a circular dependency with
`sealed_sha256`.

Private key material is generated locally via `scripts/keygen.py` and written under `.secrets/`,
which is git-ignored. The script attempts restrictive file permissions but cannot guarantee Windows
ACL policy: apply an appropriate ACL, restrict account access, maintain a secure backup and move to
managed key custody before scaling production. The private value is never printed.

---

## Responsible-technology posture

- **Privacy by construction.** The prompt is sent only to the selected provider and retained only in
  the private generation run. It cannot appear in a public certificate, a report or a log — the
  report writer refuses to serialize a payload containing forbidden markers.
- **Fail-closed by default.** Every ambiguous state blocks rather than guesses.
- **Honest verification language.** Where a proof does not exist for a medium, the UI says
  `NOT CHECKED` instead of implying success.
- **No detection theatre.** FIREMARK does not claim to identify AI media in the wild. It proves the
  lifecycle of assets that were registered.
- **Zero-network tests.** The ordinary test suite contacts no provider, database or object store, so
  running it can never incur cost or emit data.

---

## Known limitations

- **Custody is not cross-object atomic.** B2 custody spans multiple objects; a registration failure
  can leave safe, billable partial storage. The repository ships read-only inspectors
  (`scripts/inspect_b2_smoke_state.py`, `scripts/diagnose_b2_access.py`) to examine that state before
  any cleanup decision.
- **Authorization is out of scope.** The signature proves key possession, not that the signer was
  entitled to sign for a given organization.
- **Retention is finite.** COMPLIANCE retention has a configured window (production target: 90 days).
  Evidence beyond that window requires an extended retention tier.
- **`Manifest.verify()` scope.** It verifies the canonical manifest and declared digest coverage; it
  does not re-hash the post-embedding container. FIREMARK binds the distributed container separately
  through `sealed_sha256`.
- **Genblaze 0.3.8 pointer payloads** are stored as a `.genblaze.json` sidecar rather than inside PNG
  bytes, so FIREMARK publishes its own public capsule and resolves pointers through B2 custody.

---

## Reporting a concern

Please open an issue at
[github.com/jpablortiz96/firemark/issues](https://github.com/jpablortiz96/firemark/issues). Do not
include credentials, private manifests, presigned URLs or prompts in a report.
