"""Safe local boundaries around public Genblaze provenance APIs."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from genblaze_core import EmbedPolicy, GenblazeError, Manifest, parse_manifest
from genblaze_core.media import SmartEmbedder, get_handler, guess_mime

from api.firemark.hashing import sha256_file

MAX_JSON_PAYLOAD_BYTES = 16 * 1024 * 1024


class GenblazeProvenanceError(RuntimeError):
    """Raised when a Genblaze provenance operation fails closed."""


@dataclass(frozen=True)
class ProvenanceEmbedResult:
    """Immutable hashes and media metadata from a successful inline embed."""

    source_path: Path
    sealed_path: Path
    source_sha256: str
    sealed_sha256: str
    canonical_hash: str
    embed_method: str
    sidecar_path: Path | None
    mime_type: str


def _require_regular_file(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} does not exist: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"{label} must be a file: {path}")


def _load_json_object(payload: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise GenblazeProvenanceError("Genblaze payload is not valid JSON") from exc
    if not isinstance(value, dict):
        raise GenblazeProvenanceError("Genblaze payload must be a JSON object")
    return cast(dict[str, Any], value)


def render_policy_payload(manifest: Manifest, policy: EmbedPolicy) -> bytes:
    """Render a verified Manifest through the installed public EmbedPolicy API."""
    if not manifest.verify():
        raise GenblazeProvenanceError("Refusing to render an unverified Genblaze Manifest")
    try:
        payload = cast(str, manifest.to_embed_json(policy))
    except GenblazeError as exc:
        raise GenblazeProvenanceError("Genblaze rejected the requested embed policy") from exc
    _load_json_object(payload)
    return payload.encode("utf-8")


def read_json_payload(path: Path, *, max_bytes: int = MAX_JSON_PAYLOAD_BYTES) -> dict[str, Any]:
    """Read a bounded UTF-8 JSON object without interpreting it as a full Manifest."""
    _require_regular_file(path, "Payload")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    size = path.stat().st_size
    if size > max_bytes:
        raise GenblazeProvenanceError(
            f"Genblaze payload exceeds the FIREMARK size limit ({size} > {max_bytes} bytes)"
        )
    try:
        payload = path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise GenblazeProvenanceError("Genblaze payload is not valid UTF-8") from exc
    return _load_json_object(payload)


def parse_complete_manifest_payload(payload: bytes | str) -> Manifest:
    """Parse and verify a complete extracted Manifest using the public parser."""
    try:
        text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    except UnicodeError as exc:
        raise GenblazeProvenanceError("Genblaze payload is not valid UTF-8") from exc
    data = _load_json_object(text)
    if "run" not in data:
        raise GenblazeProvenanceError("Payload is not a complete Genblaze Manifest")
    if not isinstance(data["run"], dict):
        raise GenblazeProvenanceError("Complete Genblaze Manifest parsing failed")
    try:
        manifest = parse_manifest(data)
    except (GenblazeError, ValueError, TypeError) as exc:
        raise GenblazeProvenanceError("Complete Genblaze Manifest parsing failed") from exc
    if not manifest.verify():
        raise GenblazeProvenanceError("Extracted Genblaze Manifest did not verify")
    return manifest


def extract_complete_manifest(media_path: Path) -> Manifest:
    """Extract and verify a complete Manifest through a public media handler."""
    _require_regular_file(media_path, "Media source")
    mime_type = guess_mime(media_path)
    handler = get_handler(mime_type)
    if handler is None:
        raise GenblazeProvenanceError(f"Unsupported media type: {mime_type}")
    try:
        manifest = handler.extract(media_path)
    except GenblazeError as exc:
        raise GenblazeProvenanceError("Genblaze manifest extraction failed") from exc
    if not manifest.verify():
        raise GenblazeProvenanceError("Extracted Genblaze Manifest did not verify")
    return manifest


def embed_manifest_copy(
    source_path: Path,
    sealed_path: Path,
    manifest: Manifest,
    *,
    overwrite: bool = False,
) -> ProvenanceEmbedResult:
    """Embed a verified full Manifest inline without modifying the source file."""
    _require_regular_file(source_path, "Source asset")
    source = source_path.resolve()
    destination = sealed_path.resolve()
    if source == destination:
        raise GenblazeProvenanceError("Source and destination paths must be different")
    if destination.exists() and destination.is_dir():
        raise IsADirectoryError(f"Destination must be a file: {destination}")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Destination already exists: {destination}")
    if not manifest.verify():
        raise GenblazeProvenanceError("Refusing to embed an unverified Genblaze Manifest")

    mime_type = guess_mime(source)
    if get_handler(mime_type) is None:
        raise GenblazeProvenanceError(f"Unsupported media type: {mime_type}")

    source_sha256 = sha256_file(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=destination.suffix,
        dir=destination.parent,
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    temporary_sidecar = temporary_path.with_suffix(temporary_path.suffix + ".genblaze.json")

    try:
        try:
            embed_result = SmartEmbedder().embed(
                source,
                manifest,
                temporary_path,
                mime_type=mime_type,
            )
        except GenblazeError as exc:
            raise GenblazeProvenanceError("Genblaze inline embedding failed") from exc

        if embed_result.method != "inline" or embed_result.sidecar_path is not None:
            raise GenblazeProvenanceError(
                "Genblaze did not use the required inline embedding method"
            )
        if not temporary_path.is_file():
            raise GenblazeProvenanceError("Genblaze did not produce the sealed media file")
        if sha256_file(source) != source_sha256:
            raise GenblazeProvenanceError("Source asset changed during embedding")

        sealed_sha256 = sha256_file(temporary_path)
        if sealed_sha256 == source_sha256:
            raise GenblazeProvenanceError("Inline embedding did not change the sealed asset hash")

        extracted = extract_complete_manifest(temporary_path)
        if extracted.canonical_hash != manifest.canonical_hash:
            raise GenblazeProvenanceError("Embedded canonical_hash does not match the source Manifest")

        os.replace(temporary_path, destination)
    except OSError as exc:
        raise GenblazeProvenanceError("Local file operation failed during embedding") from exc
    finally:
        temporary_path.unlink(missing_ok=True)
        temporary_sidecar.unlink(missing_ok=True)

    return ProvenanceEmbedResult(
        source_path=source,
        sealed_path=destination,
        source_sha256=source_sha256,
        sealed_sha256=sealed_sha256,
        canonical_hash=manifest.canonical_hash,
        embed_method=embed_result.method,
        sidecar_path=embed_result.sidecar_path,
        mime_type=mime_type,
    )
