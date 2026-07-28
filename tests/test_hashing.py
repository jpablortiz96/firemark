"""Tests for FIREMARK SHA-256 helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from api.firemark.hashing import sha256_bytes, sha256_file


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ],
)
def test_sha256_bytes_known_vectors(payload: bytes, expected: str) -> None:
    assert sha256_bytes(payload) == expected


def test_sha256_file_streams_in_small_chunks(tmp_path: Path) -> None:
    payload = bytes(range(256)) * 100
    path = tmp_path / "streaming-test.bin"
    path.write_bytes(payload)

    assert sha256_file(path, chunk_size=17) == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("chunk_size", [0, -1, 1.5, True])
def test_sha256_file_rejects_invalid_chunk_size(tmp_path: Path, chunk_size: object) -> None:
    path = tmp_path / "data.bin"
    path.write_bytes(b"data")

    with pytest.raises(ValueError, match="positive integer"):
        sha256_file(path, chunk_size=chunk_size)  # type: ignore[arg-type]


def test_sha256_file_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="File does not exist"):
        sha256_file(tmp_path / "missing.bin")


def test_sha256_file_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(IsADirectoryError, match="Expected a file"):
        sha256_file(tmp_path)


def test_one_byte_mutation_changes_digest(tmp_path: Path) -> None:
    path = tmp_path / "mutable.bin"
    path.write_bytes(b"stable payload")
    original_digest = sha256_file(path)

    path.write_bytes(b"Stable payload")

    assert sha256_file(path) != original_digest
