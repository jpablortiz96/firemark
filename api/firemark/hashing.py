"""Streaming and in-memory SHA-256 helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path

DEFAULT_CHUNK_SIZE = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    """Return the lowercase SHA-256 hexadecimal digest for bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Return a file's SHA-256 digest while reading it incrementally."""
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")
    if not path.exists():
        raise FileNotFoundError(f"File does not exist: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"Expected a file but received a directory: {path}")

    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()
