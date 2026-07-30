"""Validate production environment inventory without disclosing configured values."""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from dotenv import dotenv_values

from api.firemark.settings import classify_supabase_key
from api.firemark.signer import Ed25519Signer

Status = Literal["PRESENT", "MISSING", "VALID", "INVALID"]
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = ROOT / ".env"

BACKEND_FIELDS = (
    "FIREMARK_REPOSITORY_BACKEND",
    "FIREMARK_ADMIN_API_KEY",
    "FIREMARK_DELIVERY_API_KEY",
    "FIREMARK_SIGNING_PRIVATE_KEY_B64",
    "FIREMARK_SIGNING_PUBLIC_KEY_B64",
    "FIREMARK_PUBLIC_BASE_URL",
    "FIREMARK_ALLOWED_ORIGINS",
    "FIREMARK_DELIVERY_TTL_SECONDS",
    "FIREMARK_GENERATION_TIMEOUT_SECONDS",
    "FIREMARK_MAX_GENERATED_IMAGE_BYTES",
    "FIREMARK_MAX_GENERATED_AUDIO_BYTES",
    "FIREMARK_VAULT_RETENTION_DAYS",
    "FIREMARK_PRESIGNED_URL_TTL_SECONDS",
    "OPENAI_API_KEY",
    "OPENAI_IMAGE_MODEL",
    "OPENAI_IMAGE_SIZE",
    "GEMINI_API_KEY",
    "GEMINI_IMAGE_MODEL",
    "ELEVENLABS_API_KEY",
    "ELEVENLABS_VOICE_ID",
    "ELEVENLABS_MODEL_ID",
    "SUPABASE_URL",
    "SUPABASE_PUBLISHABLE_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "B2_ENDPOINT",
    "B2_REGION",
    "B2_ASSETS_BUCKET",
    "B2_ASSETS_KEY_ID",
    "B2_ASSETS_APPLICATION_KEY",
    "B2_VAULT_BUCKET",
    "B2_VAULT_KEY_ID",
    "B2_VAULT_APPLICATION_KEY",
)
FRONTEND_FIELDS = (
    "NEXT_PUBLIC_FIREMARK_API_BASE_URL",
    "FIREMARK_DELIVERY_API_KEY",
    "FIREMARK_PUBLIC_SITE_URL",
)
_B2_ALIASES = {
    "B2_ASSETS_APPLICATION_KEY": "B2_ASSETS_APP_KEY",
    "B2_VAULT_APPLICATION_KEY": "B2_VAULT_APP_KEY",
}
_BUCKET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{4,48}[A-Za-z0-9]$")
_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SECRET_NAME_PARTS = ("SECRET", "TOKEN", "PASSWORD", "PRIVATE", "API_KEY")


@dataclass(frozen=True)
class FieldCheck:
    """One disclosure-safe inventory result."""

    scope: Literal["BACKEND", "FRONTEND"]
    name: str
    status: Status


def _value(values: Mapping[str, str | None], name: str) -> str | None:
    direct = values.get(name)
    if direct is not None and direct.strip():
        return direct.strip()
    alias = _B2_ALIASES.get(name)
    legacy = values.get(alias) if alias is not None else None
    return legacy.strip() if legacy is not None and legacy.strip() else None


def _https_origin(value: str | None) -> bool:
    if value is None:
        return False
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        return False
    return bool(
        parsed.scheme.lower() == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and parsed.path in ("", "/")
        and (port is None or 1 <= port <= 65535)
    )


def _origins(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list) or not parsed or any(not isinstance(x, str) for x in parsed):
        return None
    origins = tuple(parsed)
    if len(set(origins)) != len(origins) or "*" in origins:
        return None
    return origins if all(_https_origin(origin) for origin in origins) else None


def _bounded_integer(value: str | None, minimum: int, maximum: int) -> bool:
    if value is None or not re.fullmatch(r"[0-9]+", value):
        return False
    return minimum <= int(value) <= maximum


def _set(
    statuses: dict[tuple[str, str], Status],
    scope: Literal["BACKEND", "FRONTEND"],
    name: str,
    valid: bool,
) -> None:
    if statuses[(scope, name)] != "MISSING":
        statuses[(scope, name)] = "VALID" if valid else "INVALID"


def evaluate_readiness(
    backend: Mapping[str, str | None],
    frontend: Mapping[str, str | None] | None = None,
) -> list[FieldCheck]:
    """Return safe field-level checks without retaining printable configuration values."""
    frontend_values = backend if frontend is None else frontend
    statuses: dict[tuple[str, str], Status] = {}
    for name in BACKEND_FIELDS:
        statuses[("BACKEND", name)] = "PRESENT" if _value(backend, name) else "MISSING"
    for name in FRONTEND_FIELDS:
        statuses[("FRONTEND", name)] = (
            "PRESENT" if _value(frontend_values, name) else "MISSING"
        )

    simple_present = {
        "FIREMARK_ADMIN_API_KEY",
        "FIREMARK_DELIVERY_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "ELEVENLABS_API_KEY",
        "B2_ASSETS_KEY_ID",
        "B2_ASSETS_APPLICATION_KEY",
        "B2_VAULT_KEY_ID",
        "B2_VAULT_APPLICATION_KEY",
    }
    for name in simple_present:
        _set(statuses, "BACKEND", name, _value(backend, name) is not None)
    _set(
        statuses,
        "FRONTEND",
        "FIREMARK_DELIVERY_API_KEY",
        _value(frontend_values, "FIREMARK_DELIVERY_API_KEY") is not None,
    )

    _set(
        statuses,
        "BACKEND",
        "FIREMARK_REPOSITORY_BACKEND",
        _value(backend, "FIREMARK_REPOSITORY_BACKEND") == "supabase",
    )
    for name in ("FIREMARK_PUBLIC_BASE_URL", "SUPABASE_URL", "B2_ENDPOINT"):
        _set(statuses, "BACKEND", name, _https_origin(_value(backend, name)))
    for name in ("NEXT_PUBLIC_FIREMARK_API_BASE_URL", "FIREMARK_PUBLIC_SITE_URL"):
        _set(statuses, "FRONTEND", name, _https_origin(_value(frontend_values, name)))

    allowed = _origins(_value(backend, "FIREMARK_ALLOWED_ORIGINS"))
    site_url = _value(frontend_values, "FIREMARK_PUBLIC_SITE_URL")
    allowed_valid = allowed is not None and site_url is not None
    if allowed_valid:
        assert allowed is not None
        assert site_url is not None
        site = urlsplit(site_url)
        site_origin = f"{site.scheme}://{site.netloc}".rstrip("/")
        allowed_valid = site_origin in allowed
    _set(statuses, "BACKEND", "FIREMARK_ALLOWED_ORIGINS", allowed_valid)

    integer_rules = {
        "FIREMARK_DELIVERY_TTL_SECONDS": (60, 900),
        "FIREMARK_GENERATION_TIMEOUT_SECONDS": (5, 300),
        "FIREMARK_MAX_GENERATED_IMAGE_BYTES": (1024 * 1024, 50 * 1024 * 1024),
        "FIREMARK_MAX_GENERATED_AUDIO_BYTES": (1024 * 1024, 100 * 1024 * 1024),
        "FIREMARK_VAULT_RETENTION_DAYS": (1, 3650),
        "FIREMARK_PRESIGNED_URL_TTL_SECONDS": (60, 900),
    }
    for name, bounds in integer_rules.items():
        _set(statuses, "BACKEND", name, _bounded_integer(_value(backend, name), *bounds))

    model = _value(backend, "OPENAI_IMAGE_MODEL")
    _set(statuses, "BACKEND", "OPENAI_IMAGE_MODEL", bool(model and _MODEL_PATTERN.fullmatch(model)))
    for name in ("GEMINI_IMAGE_MODEL", "ELEVENLABS_MODEL_ID", "ELEVENLABS_VOICE_ID"):
        provider_value = _value(backend, name)
        _set(
            statuses,
            "BACKEND",
            name,
            bool(provider_value and _MODEL_PATTERN.fullmatch(provider_value)),
        )
    _set(
        statuses,
        "BACKEND",
        "OPENAI_IMAGE_SIZE",
        _value(backend, "OPENAI_IMAGE_SIZE")
        in {
            "auto",
            "256x256",
            "512x512",
            "1024x1024",
            "1536x1024",
            "1024x1536",
            "1792x1024",
            "1024x1792",
        },
    )
    region = _value(backend, "B2_REGION")
    _set(statuses, "BACKEND", "B2_REGION", bool(region))
    for name in ("B2_ASSETS_BUCKET", "B2_VAULT_BUCKET"):
        bucket = _value(backend, name)
        _set(statuses, "BACKEND", name, bool(bucket and _BUCKET_PATTERN.fullmatch(bucket)))

    private = _value(backend, "FIREMARK_SIGNING_PRIVATE_KEY_B64")
    public = _value(backend, "FIREMARK_SIGNING_PUBLIC_KEY_B64")
    signing_valid = False
    if private is not None and public is not None:
        try:
            Ed25519Signer.from_private_key_base64(private, public)
            signing_valid = True
        except ValueError:
            signing_valid = False
    _set(statuses, "BACKEND", "FIREMARK_SIGNING_PRIVATE_KEY_B64", signing_valid)
    _set(statuses, "BACKEND", "FIREMARK_SIGNING_PUBLIC_KEY_B64", signing_valid)

    publishable = _value(backend, "SUPABASE_PUBLISHABLE_KEY")
    service = _value(backend, "SUPABASE_SERVICE_ROLE_KEY")
    supabase_distinct = bool(
        publishable and service and not hmac.compare_digest(publishable, service)
    )
    _set(
        statuses,
        "BACKEND",
        "SUPABASE_PUBLISHABLE_KEY",
        supabase_distinct
        and classify_supabase_key(publishable) in {"SB_PUBLISHABLE", "LEGACY_ANON_JWT"},
    )
    _set(
        statuses,
        "BACKEND",
        "SUPABASE_SERVICE_ROLE_KEY",
        supabase_distinct
        and classify_supabase_key(service) in {"SB_SECRET", "LEGACY_SERVICE_ROLE_JWT"},
    )

    admin = _value(backend, "FIREMARK_ADMIN_API_KEY")
    backend_delivery = _value(backend, "FIREMARK_DELIVERY_API_KEY")
    frontend_delivery = _value(frontend_values, "FIREMARK_DELIVERY_API_KEY")
    admin_distinct = bool(admin and backend_delivery and not hmac.compare_digest(admin, backend_delivery))
    delivery_matches = bool(
        backend_delivery
        and frontend_delivery
        and hmac.compare_digest(backend_delivery, frontend_delivery)
    )
    _set(statuses, "BACKEND", "FIREMARK_ADMIN_API_KEY", admin_distinct)
    _set(statuses, "BACKEND", "FIREMARK_DELIVERY_API_KEY", admin_distinct and delivery_matches)
    _set(statuses, "FRONTEND", "FIREMARK_DELIVERY_API_KEY", delivery_matches)

    assets_bucket = _value(backend, "B2_ASSETS_BUCKET")
    vault_bucket = _value(backend, "B2_VAULT_BUCKET")
    if assets_bucket and vault_bucket and hmac.compare_digest(assets_bucket, vault_bucket):
        statuses[("BACKEND", "B2_ASSETS_BUCKET")] = "INVALID"
        statuses[("BACKEND", "B2_VAULT_BUCKET")] = "INVALID"
    for left, right in (
        ("B2_ASSETS_KEY_ID", "B2_VAULT_KEY_ID"),
        ("B2_ASSETS_APPLICATION_KEY", "B2_VAULT_APPLICATION_KEY"),
    ):
        left_value, right_value = _value(backend, left), _value(backend, right)
        separated = bool(left_value and right_value and not hmac.compare_digest(left_value, right_value))
        _set(statuses, "BACKEND", left, separated)
        _set(statuses, "BACKEND", right, separated)

    for name, value in {**backend, **frontend_values}.items():
        if name.startswith("NEXT_PUBLIC_") and any(part in name for part in _SECRET_NAME_PARTS):
            if value is not None and value.strip():
                statuses[("FRONTEND", "NEXT_PUBLIC_FIREMARK_API_BASE_URL")] = "INVALID"

    return [
        *(FieldCheck("BACKEND", name, statuses[("BACKEND", name)]) for name in BACKEND_FIELDS),
        *(FieldCheck("FRONTEND", name, statuses[("FRONTEND", name)]) for name in FRONTEND_FIELDS),
    ]


def load_environment(path: Path = DEFAULT_ENV_FILE) -> dict[str, str | None]:
    """Explicitly read the ignored deployment inventory without mutating process state."""
    return dict(dotenv_values(path)) if path.is_file() else {}


def main() -> int:
    checks = evaluate_readiness(load_environment())
    for check in checks:
        print(f"{check.scope}.{check.name}={check.status}")
    return 0 if all(check.status == "VALID" for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
