"""Run a zero-network local smoke test of the FIREMARK trust kernel."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from api.firemark.hashing import sha256_bytes, sha256_file
from api.firemark.seal_envelope import (
    SealEnvelopeV1,
    sign_envelope,
    verify_signed_envelope,
)
from api.firemark.signer import Ed25519Signer


def _run_checks() -> list[tuple[str, bool]]:
    checks: list[tuple[str, bool]] = []
    with TemporaryDirectory(prefix="firemark-trust-smoke-") as temporary_directory:
        root = Path(temporary_directory)
        source_path = root / "local-test-source.bin"
        sealed_path = root / "local-test-sealed.bin"
        source_path.write_bytes(b"FIREMARK local test source bytes v1")
        sealed_path.write_bytes(b"FIREMARK local test sealed bytes v1\nembedded-manifest-marker")

        source_sha256 = sha256_file(source_path)
        sealed_sha256 = sha256_file(sealed_path)
        checks.append(("source and sealed hashes differ", source_sha256 != sealed_sha256))

        signer = Ed25519Signer.generate()
        created_at = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
        envelope = SealEnvelopeV1(
            cert_id="local-test-certificate",
            run_id="local-test-run",
            canonical_hash=sha256_bytes(b"local-test-canonical-provenance"),
            source_sha256=source_sha256,
            sealed_sha256=sealed_sha256,
            sealed_asset_bucket="local-test-assets",
            sealed_asset_key="local-test/sealed.bin",
            public_manifest_bucket="local-test-public-manifests",
            public_manifest_key="local-test/manifest.json",
            vault_bucket="local-test-vault",
            vault_source_key="local-test/source.bin",
            vault_source_version_id="local-test-source-version",
            vault_manifest_key="local-test/private-manifest.json",
            vault_manifest_version_id="local-test-manifest-version",
            retention_until=created_at + timedelta(days=30),
            signer_key_id=signer.signer_key_id,
            created_at=created_at,
        )
        signed = sign_envelope(envelope, signer)
        public_key = signer.export_public_key_base64()
        checks.append(
            ("original envelope signature verifies", verify_signed_envelope(signed, public_key))
        )

        modified_envelope = envelope.model_copy(
            update={"sealed_asset_key": "local-test/tampered-sealed.bin"}
        )
        modified_signed = signed.model_copy(update={"envelope": modified_envelope})
        checks.append(
            (
                "modified envelope signature is rejected",
                not verify_signed_envelope(modified_signed, public_key),
            )
        )

        sealed_bytes = bytearray(sealed_path.read_bytes())
        sealed_bytes[0] ^= 1
        sealed_path.write_bytes(sealed_bytes)
        checks.append(
            ("modified sealed file hash is rejected", sha256_file(sealed_path) != sealed_sha256)
        )

    return checks


def main() -> int:
    """Print local trust checks and return zero only when all checks pass."""
    checks = _run_checks()
    print("FIREMARK local trust smoke test - local cryptographic verification only")
    print("This output is not production evidence.")
    print(f"{'Check':44} Result")
    print(f"{'-' * 44} ------")
    for label, passed in checks:
        print(f"{label:44} {'PASS' if passed else 'FAIL'}")
    return 0 if all(passed for _, passed in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
