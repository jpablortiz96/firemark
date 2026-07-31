"""Deterministic, offline image normalization to the FIREMARK PNG carrier.

A provider may only be able to deliver a source format FIREMARK cannot embed a
public capsule into. Google's Interactions ``ImageResponseFormat`` accepts
``image/jpeg`` for URI delivery, so the Gemini source arrives as JPEG while the
FIREMARK public capsule requires a PNG container.

This boundary decodes the exact provider source and re-encodes it as a
deterministic PNG. It performs no network access, adds no lossy transformation
beyond decoding the source, and strips EXIF, comments, ICC profiles and any
other provider metadata so the sealed carrier reveals nothing the certificate
does not already state.

The source bytes are never modified. ``source_sha256`` is always computed from
the untouched provider bytes; only the sealed carrier is normalized.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Final, Literal

from PIL import Image, ImageOps, UnidentifiedImageError

from api.firemark.generation.models import JPEG_MAGIC, PNG_MAGIC

SourceImageMimeType = Literal["image/jpeg", "image/png"]

#: Pillow format names accepted for each supported source MIME type.
_PILLOW_FORMATS: Final[dict[str, str]] = {"image/jpeg": "JPEG", "image/png": "PNG"}
_SOURCE_MAGIC: Final[dict[str, bytes]] = {"image/jpeg": JPEG_MAGIC, "image/png": PNG_MAGIC}

MAX_IMAGE_DIMENSION: Final = 16384
MAX_IMAGE_PIXELS: Final = 50_000_000
#: Fixed zlib level so repeated normalization of identical bytes is identical.
PNG_COMPRESS_LEVEL: Final = 6

NormalizationFailureCode = Literal[
    "unsupported_source_mime",
    "non_jpeg_source",
    "malformed_image",
    "image_dimensions_exceeded",
    "image_pixels_exceeded",
    "image_decoding_failure",
    "png_normalization_failure",
    "non_png_normalized_output",
]


class ImageNormalizationError(RuntimeError):
    """Safe normalization failure that carries no image or provider material."""

    def __init__(self, code: NormalizationFailureCode) -> None:
        super().__init__(f"Image normalization failed: {code}")
        self.code = code


@dataclass(frozen=True)
class NormalizedImage:
    """A deterministic PNG carrier derived from validated source bytes."""

    data: bytes
    width: int
    height: int
    mime_type: Literal["image/png"] = "image/png"
    file_extension: Literal["png"] = "png"


@dataclass(frozen=True)
class ImageSourceFacts:
    """Structural facts proved by decoding the untouched provider source."""

    mime_type: SourceImageMimeType
    width: int
    height: int
    byte_size: int


def _open(data: bytes, mime_type: str) -> Image.Image:
    expected_format = _PILLOW_FORMATS.get(mime_type)
    if expected_format is None:
        raise ImageNormalizationError("unsupported_source_mime")
    magic = _SOURCE_MAGIC[mime_type]
    if not data.startswith(magic):
        raise ImageNormalizationError(
            "non_jpeg_source" if mime_type == "image/jpeg" else "malformed_image"
        )
    try:
        image = Image.open(io.BytesIO(data))
    except Image.DecompressionBombError:
        raise ImageNormalizationError("image_pixels_exceeded") from None
    except (UnidentifiedImageError, OSError, ValueError):
        raise ImageNormalizationError("malformed_image") from None
    if image.format != expected_format:
        image.close()
        raise ImageNormalizationError(
            "non_jpeg_source" if mime_type == "image/jpeg" else "malformed_image"
        )
    return image


def _enforce_bounds(image: Image.Image) -> tuple[int, int]:
    width, height = image.size
    if width < 1 or height < 1:
        raise ImageNormalizationError("malformed_image")
    if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        raise ImageNormalizationError("image_dimensions_exceeded")
    if width * height > MAX_IMAGE_PIXELS:
        raise ImageNormalizationError("image_pixels_exceeded")
    return width, height


def inspect_image_source(data: bytes, *, mime_type: str) -> ImageSourceFacts:
    """Prove the source decodes structurally without re-encoding it.

    Truncated and malformed payloads fail here, before any byte is treated as a
    usable generation result.
    """
    with _open(data, mime_type) as image:
        width, height = _enforce_bounds(image)
        try:
            image.load()
        except Image.DecompressionBombError:
            raise ImageNormalizationError("image_pixels_exceeded") from None
        except (OSError, ValueError, SyntaxError):
            raise ImageNormalizationError("malformed_image") from None
    assert mime_type in _PILLOW_FORMATS
    return ImageSourceFacts(
        mime_type=mime_type,  # type: ignore[arg-type]
        width=width,
        height=height,
        byte_size=len(data),
    )


def _has_real_alpha(image: Image.Image) -> bool:
    """Report transparency only when the source genuinely carries it."""
    if "transparency" in image.info:
        return True
    if image.mode in {"RGBA", "LA", "PA"}:
        source = image if image.mode != "PA" else image.convert("RGBA")
        extrema: object = source.getchannel("A").getextrema()
        minimum = extrema[0] if isinstance(extrema, tuple) else extrema
        return isinstance(minimum, (int, float)) and minimum < 255
    return False


def normalize_to_png(data: bytes, *, source_mime_type: str) -> NormalizedImage:
    """Decode validated source bytes and re-encode them as a deterministic PNG.

    Orientation is applied deterministically, the pixel buffer is copied into a
    fresh image so no EXIF, comment, ICC profile or provider metadata survives,
    and the PNG encoder uses fixed options so identical input always produces
    identical output.
    """
    with _open(data, source_mime_type) as opened:
        _enforce_bounds(opened)
        try:
            oriented = ImageOps.exif_transpose(opened) or opened
            width, height = _enforce_bounds(oriented)
            mode = "RGBA" if _has_real_alpha(oriented) else "RGB"
            converted = oriented.convert(mode)
            # A fresh image from raw pixels cannot carry any inherited metadata.
            stripped = Image.frombytes(mode, (width, height), converted.tobytes())
        except Image.DecompressionBombError:
            raise ImageNormalizationError("image_pixels_exceeded") from None
        except (OSError, ValueError, SyntaxError):
            raise ImageNormalizationError("image_decoding_failure") from None
    buffer = io.BytesIO()
    try:
        stripped.save(
            buffer,
            format="PNG",
            optimize=False,
            compress_level=PNG_COMPRESS_LEVEL,
            pnginfo=None,
        )
    except (OSError, ValueError) as exc:
        raise ImageNormalizationError("png_normalization_failure") from exc
    payload = buffer.getvalue()
    if not payload.startswith(PNG_MAGIC):
        raise ImageNormalizationError("non_png_normalized_output")
    return NormalizedImage(data=payload, width=width, height=height)
