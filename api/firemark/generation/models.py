"""Immutable provider-neutral multimedia generation models."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
MP3_ID3_MAGIC = b"ID3"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

MediaType = Literal["image", "audio"]
#: Source formats a provider may deliver. FIREMARK always seals a PNG carrier,
#: but it never relabels source bytes to claim they already are one.
SourceImageMimeType = Literal["image/png", "image/jpeg"]
SourceImageExtension = Literal["png", "jpg"]
_SOURCE_IMAGE_MAGIC: dict[str, bytes] = {"image/png": PNG_MAGIC, "image/jpeg": JPEG_MAGIC}
_SOURCE_IMAGE_EXTENSIONS: dict[str, str] = {"image/png": "png", "image/jpeg": "jpg"}


class GenerationRequest(BaseModel):
    """Validated private request passed to one injected provider."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt: str = Field(min_length=1, max_length=4000, repr=False)
    model: str
    size: str
    request_id: str
    seed: int | None = None
    provider_parameters: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @field_validator("prompt")
    @classmethod
    def normalize_prompt(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Generation prompt must not be blank")
        return normalized

    @field_validator("model", "request_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("Generation identifiers must use safe characters")
        return value


class GeneratedImage(BaseModel):
    """Validated immutable provider source image.

    ``data`` holds the exact bytes the provider produced, in whatever format it
    delivered. ``source_mime_type`` and ``source_extension`` describe those
    bytes truthfully; a JPEG source is never labelled PNG. The sealed PNG
    carrier is produced separately by the normalization boundary.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    data: bytes = Field(repr=False)
    source_mime_type: SourceImageMimeType = "image/png"
    source_extension: SourceImageExtension = "png"
    width: int | None = Field(default=None, gt=0)
    height: int | None = Field(default=None, gt=0)
    provider: str
    model: str
    provider_request_id: str | None = None
    provider_created_at: datetime
    safe_generation_metadata: dict[str, Any] = Field(default_factory=dict)
    seed: int | None = None
    ai_generated: bool

    @property
    def source_bytes(self) -> bytes:
        """The untouched provider bytes that define ``source_sha256``."""
        return self.data

    @property
    def media_type(self) -> str:
        """Source MIME type, used for private source custody."""
        return self.source_mime_type

    @property
    def file_extension(self) -> str:
        """Source file extension, used for private source custody."""
        return self.source_extension

    @model_validator(mode="after")
    def validate_source_format(self) -> GeneratedImage:
        if not self.data.startswith(_SOURCE_IMAGE_MAGIC[self.source_mime_type]):
            raise ValueError(f"Generated image is not a {self.source_mime_type}")
        if self.source_extension != _SOURCE_IMAGE_EXTENSIONS[self.source_mime_type]:
            raise ValueError("Source extension does not match the source MIME type")
        return self

    @field_validator("provider", "model")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        if not value.strip() or len(value) > 128:
            raise ValueError("Provider metadata must not be blank")
        return value

    @field_validator("provider_request_id")
    @classmethod
    def validate_optional_request_id(cls, value: str | None) -> str | None:
        if value is not None and not _IDENTIFIER.fullmatch(value):
            raise ValueError("Provider request identifier is unsafe")
        return value

    @field_validator("safe_generation_metadata")
    @classmethod
    def validate_safe_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        forbidden = (
            "prompt",
            "credential",
            "authorization",
            "api_key",
            "secret",
            "response",
            "url",
        )

        def visit(item: object) -> None:
            if isinstance(item, dict):
                for key, nested in item.items():
                    if any(token in key.lower() for token in forbidden):
                        raise ValueError("Generation metadata contains a private field")
                    visit(nested)
            elif isinstance(item, list):
                for nested in item:
                    visit(nested)
            elif not isinstance(item, (str, int, float, bool, type(None))):
                raise ValueError("Generation metadata must contain JSON-safe values")

        visit(value)
        return value

    @field_validator("provider_created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Provider timestamp must be timezone-aware")
        return value.astimezone(UTC)


class AudioGenerationRequest(BaseModel):
    """Validated private text-to-speech request passed to one provider."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(min_length=1, max_length=5000, repr=False)
    model: str
    voice_id: str
    request_id: str
    provider_parameters: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @field_validator("text")
    @classmethod
    def normalize_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Speech text must not be blank")
        return normalized

    @field_validator("model", "voice_id", "request_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("Audio generation identifiers must use safe characters")
        return value


class GeneratedAudio(BaseModel):
    """Validated immutable MP3 returned by a speech provider."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    data: bytes = Field(repr=False)
    media_type: Literal["audio/mpeg"] = "audio/mpeg"
    file_extension: Literal["mp3"] = "mp3"
    provider: str
    model: str
    voice_id: str
    provider_request_id: str | None = None
    provider_created_at: datetime
    safe_generation_metadata: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int | None = Field(default=None, ge=1)
    ai_generated: bool

    @field_validator("data")
    @classmethod
    def validate_mp3(cls, value: bytes) -> bytes:
        has_mpeg_frame = len(value) >= 2 and value[0] == 0xFF and value[1] & 0xE0 == 0xE0
        if not value.startswith(MP3_ID3_MAGIC) and not has_mpeg_frame:
            raise ValueError("Generated audio is not an MP3")
        return value

    @field_validator("provider", "model", "voice_id")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        if not value.strip() or len(value) > 128:
            raise ValueError("Provider metadata must not be blank")
        return value

    @field_validator("provider_request_id")
    @classmethod
    def validate_optional_request_id(cls, value: str | None) -> str | None:
        if value is not None and not _IDENTIFIER.fullmatch(value):
            raise ValueError("Provider request identifier is unsafe")
        return value

    @field_validator("safe_generation_metadata")
    @classmethod
    def validate_safe_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        forbidden = ("text", "prompt", "credential", "authorization", "api_key", "secret", "response", "url")

        def visit(item: object) -> None:
            if isinstance(item, dict):
                for key, nested in item.items():
                    if any(token in key.lower() for token in forbidden):
                        raise ValueError("Generation metadata contains a private field")
                    visit(nested)
            elif isinstance(item, list):
                for nested in item:
                    visit(nested)
            elif not isinstance(item, (str, int, float, bool, type(None))):
                raise ValueError("Generation metadata must contain JSON-safe values")

        visit(value)
        return value

    @field_validator("provider_created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Provider timestamp must be timezone-aware")
        return value.astimezone(UTC)


GeneratedMedia = GeneratedImage | GeneratedAudio
