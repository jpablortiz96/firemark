"""Deterministic local PNG provider used only by explicit tests."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from api.firemark.generation.models import GeneratedImage, GenerationRequest

_TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


class FakeGenerationProvider:
    """Return one deterministic fixture that can never be production evidence."""

    def __init__(self) -> None:
        self.calls = 0

    def generate_image(self, request: GenerationRequest) -> GeneratedImage:
        self.calls += 1
        return GeneratedImage(
            data=_TINY_PNG,
            provider="fake",
            model=request.model,
            provider_request_id=None,
            provider_created_at=datetime(2026, 7, 30, tzinfo=UTC),
            safe_generation_metadata={"local_fixture": True, "production_evidence": False},
            seed=request.seed,
            ai_generated=False,
        )
