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

The repository now contains the local Trust Kernel milestone: streaming SHA-256 hashing, raw
Ed25519 key handling, canonical Seal Envelope serialization, detached signing and verification,
and a zero-network local smoke test. This is a cryptographic foundation, not a complete production
system.

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
```

The `.env` file is optional for the current tests. If used, populate it locally and never commit it.
The settings loader reads process environment variables explicitly; it does not automatically load
the `.env` file.

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

## Honest limitations

No external provider or cloud integration is present. Genblaze manifest creation and media
embedding, Backblaze B2 custody, API endpoints, database persistence, Supabase, provider generation,
public certificate publication, and the delivery verification gate are not implemented. Local
envelope signing does not make these absent components production-ready.
