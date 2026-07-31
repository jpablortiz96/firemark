"""Deterministic local PNG provider used only by explicit tests."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from api.firemark.generation.models import (
    AudioGenerationRequest,
    GeneratedAudio,
    GeneratedImage,
    GenerationRequest,
)

_TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)
#: A deterministic 2x2 JPEG fixture. It mirrors the format a provider such as
#: Google Gemini actually delivers, so tests can prove the JPEG source contract
#: and the normalization boundary without a network call.
_TINY_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsK"
    "CwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQU"
    "FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wAARCAACAAIDASIA"
    "AhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQA"
    "AAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3"
    "ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWm"
    "p6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEA"
    "AwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSEx"
    "BhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElK"
    "U1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3"
    "uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDwlmO4"
    "8nrRRRX3WE/3en/hX5I+zxf+81P8T/M//9k="
)
_TINY_MP3 = b"ID3\x04\x00\x00\x00\x00\x00\x00FIREMARK-LOCAL-AUDIO-FIXTURE"


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


class FakeAudioProvider:
    """Return deterministic non-production MP3-shaped bytes for tests."""

    def __init__(self) -> None:
        self.calls = 0

    def generate_audio(self, request: AudioGenerationRequest) -> GeneratedAudio:
        self.calls += 1
        return GeneratedAudio(
            data=_TINY_MP3,
            provider="fake-elevenlabs",
            model=request.model,
            voice_id=request.voice_id,
            provider_request_id=None,
            provider_created_at=datetime(2026, 7, 30, tzinfo=UTC),
            safe_generation_metadata={"local_fixture": True, "production_evidence": False},
            ai_generated=False,
        )
