"""Provision local FIREMARK Ed25519 key files without exposing private material."""

from __future__ import annotations

import argparse
import os
import stat
import tempfile
from collections.abc import Sequence
from pathlib import Path

from api.firemark.signer import Ed25519Signer, KeyMaterialError

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIRECTORY = REPOSITORY_ROOT / ".secrets"
DEFAULT_EVIDENCE_FILE = REPOSITORY_ROOT / "evidence" / "pubkey.txt"


def _atomic_write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary.write(value)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    except OSError:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate local FIREMARK Ed25519 provisioning files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIRECTORY,
        help="Directory for private and public Base64 key files.",
    )
    parser.add_argument(
        "--evidence-file",
        type=Path,
        default=DEFAULT_EVIDENCE_FILE,
        help="Path for the public key evidence summary.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing key and public evidence files.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Generate key files and return a process-compatible exit code."""
    args = _build_parser().parse_args(argv)
    output_directory: Path = args.output_dir.resolve()
    evidence_file: Path = args.evidence_file.resolve()
    private_file = output_directory / "firemark_ed25519_private.b64"
    public_file = output_directory / "firemark_ed25519_public.b64"
    targets = (private_file, public_file, evidence_file)

    existing = next((path for path in targets if path.exists()), None)
    if existing is not None and not args.force:
        print(f"ERROR: Refusing to overwrite existing path: {existing}")
        print("Next: review the existing files or rerun with --force for deliberate rotation.")
        return 2

    try:
        signer = Ed25519Signer.generate()
        private_value = signer.export_private_key_base64_for_provisioning()
        public_value = signer.export_public_key_base64()
        evidence_value = "\n".join(
            (
                "algorithm=Ed25519",
                f"public_key={public_value}",
                f"fingerprint={signer.fingerprint}",
                f"signer_key_id={signer.signer_key_id}",
                "",
            )
        )

        _atomic_write(private_file, private_value)
        os.chmod(private_file, stat.S_IRUSR | stat.S_IWUSR)
        _atomic_write(public_file, public_value)
        _atomic_write(evidence_file, evidence_value)
    except (KeyMaterialError, OSError) as exc:
        print(f"ERROR: Key provisioning failed: {exc}")
        return 1

    print(f"Created: {private_file}")
    print(f"Created: {public_file}")
    print(f"Created: {evidence_file}")
    print(f"Public fingerprint: {signer.fingerprint}")
    print(f"Signer key ID: {signer.signer_key_id}")
    print("Next: protect the private file with an appropriate Windows ACL and secure backup.")
    print("Next: configure exactly one FIREMARK private-key source before production startup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
