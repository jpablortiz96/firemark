"""Immutable provider-neutral image generation models."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


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
    """Validated immutable PNG returned by a generation provider."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    data: bytes = Field(repr=False)
    media_type: Literal["image/png"] = "image/png"
    file_extension: Literal["png"] = "png"
    provider: str
    model: str
    provider_request_id: str | None = None
    provider_created_at: datetime
    safe_generation_metadata: dict[str, Any] = Field(default_factory=dict)
    seed: int | None = None
    ai_generated: bool

    @field_validator("data")
    @classmethod
    def validate_png(cls, value: bytes) -> bytes:
        if not value.startswith(PNG_MAGIC):
            raise ValueError("Generated image is not a PNG")
        return value

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
