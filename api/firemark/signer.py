"""Ed25519 key handling and signing for the FIREMARK trust kernel."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PRIVATE_KEY_LENGTH = 32
PUBLIC_KEY_LENGTH = 32
SIGNATURE_LENGTH = 64


class KeyMaterialError(ValueError):
    """Raised when Ed25519 key material is missing, malformed, or inconsistent."""


def _decode_standard_base64(value: str, *, expected_length: int, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise KeyMaterialError(f"{label} must be a non-empty standard Base64 string")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise KeyMaterialError(f"{label} is not valid standard Base64") from exc
    if len(decoded) != expected_length:
        raise KeyMaterialError(f"{label} must decode to exactly {expected_length} bytes")
    if base64.b64encode(decoded) != encoded:
        raise KeyMaterialError(f"{label} is not canonical standard Base64")
    return decoded


def decode_signature_base64(value: str) -> bytes:
    """Decode and validate a canonical FIREMARK Ed25519 signature."""
    return _decode_standard_base64(value, expected_length=SIGNATURE_LENGTH, label="Signature")


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Return the canonical FIREMARK fingerprint for an Ed25519 public key."""
    digest = hashlib.sha256(_public_key_bytes(public_key)).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{encoded}"


def public_key_signer_id(public_key: Ed25519PublicKey) -> str:
    """Return the deterministic FIREMARK signer key identifier."""
    digest = hashlib.sha256(_public_key_bytes(public_key)).hexdigest()
    return f"firemark-ed25519-{digest[:16]}"


def _read_key_file(path: Path, label: str) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise KeyMaterialError(f"Unable to read {label} file: {path}") from exc
    if not value:
        raise KeyMaterialError(f"{label} file is empty: {path}")
    return value


@dataclass(frozen=True, repr=False)
class Ed25519KeyPair:
    """Validated Ed25519 key material with an optional private key."""

    public_key: Ed25519PublicKey
    private_key: Ed25519PrivateKey | None = None

    def __post_init__(self) -> None:
        if self.private_key is None:
            return
        derived = _public_key_bytes(self.private_key.public_key())
        supplied = _public_key_bytes(self.public_key)
        if not hmac.compare_digest(derived, supplied):
            raise KeyMaterialError("Private and public Ed25519 keys do not match")

    def __repr__(self) -> str:
        return (
            "Ed25519KeyPair("
            f"public_key_fingerprint='{self.fingerprint}', "
            f"has_private_key={self.private_key is not None})"
        )

    @classmethod
    def generate(cls) -> Ed25519KeyPair:
        """Generate a new Ed25519 private and public key pair."""
        private_key = Ed25519PrivateKey.generate()
        return cls(public_key=private_key.public_key(), private_key=private_key)

    @classmethod
    def from_private_base64(
        cls,
        private_key_base64: str,
        public_key_base64: str | None = None,
    ) -> Ed25519KeyPair:
        """Load raw private key material and optionally verify its public key."""
        raw_private = _decode_standard_base64(
            private_key_base64,
            expected_length=PRIVATE_KEY_LENGTH,
            label="Private key",
        )
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(raw_private)
        except ValueError as exc:
            raise KeyMaterialError("Private key is not valid Ed25519 material") from exc

        public_key = private_key.public_key()
        if public_key_base64 is not None:
            supplied = cls.from_public_base64(public_key_base64).public_key
            public_key = supplied
        return cls(public_key=public_key, private_key=private_key)

    @classmethod
    def from_public_base64(cls, public_key_base64: str) -> Ed25519KeyPair:
        """Load raw public key material for verification-only use."""
        raw_public = _decode_standard_base64(
            public_key_base64,
            expected_length=PUBLIC_KEY_LENGTH,
            label="Public key",
        )
        try:
            public_key = Ed25519PublicKey.from_public_bytes(raw_public)
        except ValueError as exc:
            raise KeyMaterialError("Public key is not valid Ed25519 material") from exc
        return cls(public_key=public_key)

    @classmethod
    def from_files(
        cls,
        *,
        private_key_path: Path | None = None,
        public_key_path: Path | None = None,
    ) -> Ed25519KeyPair:
        """Load a private key, a public key, or a matched pair from UTF-8 files."""
        if private_key_path is None and public_key_path is None:
            raise KeyMaterialError("At least one key file path is required")
        private_value = (
            _read_key_file(private_key_path, "private key")
            if private_key_path is not None
            else None
        )
        public_value = (
            _read_key_file(public_key_path, "public key")
            if public_key_path is not None
            else None
        )
        if private_value is not None:
            return cls.from_private_base64(private_value, public_value)
        if public_value is None:
            raise KeyMaterialError("A public key file path is required")
        return cls.from_public_base64(public_value)

    @property
    def fingerprint(self) -> str:
        """Return the public-key fingerprint."""
        return public_key_fingerprint(self.public_key)

    @property
    def signer_key_id(self) -> str:
        """Return the deterministic signer key identifier."""
        return public_key_signer_id(self.public_key)

    def export_public_base64(self) -> str:
        """Export the raw public key using standard Base64."""
        return base64.b64encode(_public_key_bytes(self.public_key)).decode("ascii")

    def export_private_base64_for_provisioning(self) -> str:
        """Explicitly export raw private key material for secure provisioning."""
        if self.private_key is None:
            raise KeyMaterialError("Private key material is not available")
        raw_private = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return base64.b64encode(raw_private).decode("ascii")


class Ed25519Signer:
    """Sign and verify bytes with validated Ed25519 key material."""

    __slots__ = ("_key_pair",)

    def __init__(self, key_pair: Ed25519KeyPair) -> None:
        self._key_pair = key_pair

    def __repr__(self) -> str:
        return (
            "Ed25519Signer("
            f"public_key_fingerprint='{self.fingerprint}', "
            f"can_sign={self.can_sign})"
        )

    @classmethod
    def generate(cls) -> Ed25519Signer:
        """Generate an ephemeral signer with a new Ed25519 key pair."""
        return cls(Ed25519KeyPair.generate())

    @classmethod
    def from_private_key_base64(
        cls,
        private_key_base64: str,
        public_key_base64: str | None = None,
    ) -> Ed25519Signer:
        """Create a signer from Base64 private key material."""
        return cls(Ed25519KeyPair.from_private_base64(private_key_base64, public_key_base64))

    @classmethod
    def from_public_key_base64(cls, public_key_base64: str) -> Ed25519Signer:
        """Create a verification-only signer from a Base64 public key."""
        return cls(Ed25519KeyPair.from_public_base64(public_key_base64))

    @classmethod
    def from_key_files(
        cls,
        *,
        private_key_path: Path | None = None,
        public_key_path: Path | None = None,
    ) -> Ed25519Signer:
        """Create a signer from one or two UTF-8 Base64 key files."""
        return cls(
            Ed25519KeyPair.from_files(
                private_key_path=private_key_path,
                public_key_path=public_key_path,
            )
        )

    @property
    def public_key(self) -> Ed25519PublicKey:
        """Expose the non-secret public key object."""
        return self._key_pair.public_key

    @property
    def fingerprint(self) -> str:
        """Return the public-key fingerprint."""
        return self._key_pair.fingerprint

    @property
    def signer_key_id(self) -> str:
        """Return the deterministic signer key identifier."""
        return self._key_pair.signer_key_id

    @property
    def can_sign(self) -> bool:
        """Report whether private key material is available."""
        return self._key_pair.private_key is not None

    def export_public_key_base64(self) -> str:
        """Export the public key using standard Base64."""
        return self._key_pair.export_public_base64()

    def export_private_key_base64_for_provisioning(self) -> str:
        """Explicitly export private key material for secure provisioning."""
        return self._key_pair.export_private_base64_for_provisioning()

    def sign(self, payload: bytes) -> str:
        """Sign arbitrary bytes and return a standard Base64 signature."""
        if self._key_pair.private_key is None:
            raise KeyMaterialError("Private key material is required for signing")
        signature = self._key_pair.private_key.sign(payload)
        return base64.b64encode(signature).decode("ascii")

    def verify(self, payload: bytes, signature_base64: str) -> bool:
        """Return whether a standard Base64 Ed25519 signature is valid."""
        try:
            signature = decode_signature_base64(signature_base64)
            self.public_key.verify(signature, payload)
        except (InvalidSignature, KeyMaterialError, ValueError, TypeError):
            return False
        return True
