"""Accurate provider identity for public and private FIREMARK metadata."""

from __future__ import annotations

from typing import Final

GOOGLE_GEMINI_PROVIDER: Final = "google_gemini"
OPENAI_PROVIDER: Final = "openai"
ELEVENLABS_PROVIDER: Final = "elevenlabs"

#: Marketing names published by the provider for an exact model identifier.
#: FIREMARK never substitutes a marketing name for the real provider or model ID.
PROVIDER_MODEL_DISPLAY_NAMES: dict[tuple[str, str], str] = {
    (GOOGLE_GEMINI_PROVIDER, "gemini-3.1-flash-image"): "Nano Banana 2",
    (GOOGLE_GEMINI_PROVIDER, "gemini-3-pro-image"): "Nano Banana Pro",
}

#: Historical provider labels normalized to the accurate current identity.
_PROVIDER_ALIASES: dict[str, str] = {"gemini": GOOGLE_GEMINI_PROVIDER}


def normalize_provider(provider: str) -> str:
    """Return the accurate provider identity for a supported alias."""
    return _PROVIDER_ALIASES.get(provider, provider)


def provider_model_display_name(provider: str | None, model: str | None) -> str | None:
    """Return the provider's published model name, or None when it is unknown."""
    if provider is None or model is None:
        return None
    return PROVIDER_MODEL_DISPLAY_NAMES.get((normalize_provider(provider), model))
