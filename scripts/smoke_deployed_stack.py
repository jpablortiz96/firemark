"""Read-only verification of an already deployed FIREMARK stack and certificate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from dotenv import dotenv_values
from pydantic import ValidationError

from api.firemark.control_plane.models import PublicCertificate, VerificationResult
from api.firemark.public_capsule import PublicCapsuleError, extract_public_capsule_png

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = ROOT / ".env"
DEFAULT_EVIDENCE_REPORT = ROOT / ".artifacts" / "generate-and-seal-report.json"
DEFAULT_OUTPUT_REPORT = ROOT / ".artifacts" / "deployed-stack-report.json"
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
STAGES = (
    "configuration_validation",
    "backend_health",
    "frontend_landing",
    "frontend_verify_page",
    "frontend_certificate_page",
    "public_certificate_api",
    "public_verify_api",
    "frontend_delivery_route",
    "delivered_asset_download",
    "delivered_sha256_verification",
    "embedded_capsule_verification",
    "response_header_security",
    "secret_leak_scan",
    "safe_report",
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_FIELDS = (
    "prompt_private",
    "parameters_private",
    "seed_private",
    "private_manifest",
    "manifest_storage_key",
    "assets_bucket",
    "assets_key",
    "assets_version_id",
    "vault_bucket",
    "vault_key",
    "vault_version_id",
    "custody_receipt",
    "signed_envelope",
    "service_role_key",
    "authorization",
)
_SECRET_FIELDS = (
    "FIREMARK_ADMIN_API_KEY",
    "FIREMARK_DELIVERY_API_KEY",
    "FIREMARK_SIGNING_PRIVATE_KEY_B64",
    "OPENAI_API_KEY",
    "SUPABASE_SERVICE_ROLE_KEY",
    "B2_ASSETS_APPLICATION_KEY",
    "B2_ASSETS_APP_KEY",
    "B2_VAULT_APPLICATION_KEY",
    "B2_VAULT_APP_KEY",
)


class SmokeFailure(RuntimeError):
    """A safe, normalized deployed-stack failure."""


@dataclass(frozen=True)
class ExistingEvidence:
    cert_id: str
    asset_id: str
    run_id: str
    sealed_sha256: str
    canonical_hash: str
    source_sha256: str | None


class StageTracker:
    """Emit only fixed stage names and retain ordered safe results."""

    def __init__(self) -> None:
        self.index = 0
        self.current = STAGES[0]
        self.completed: list[dict[str, str]] = []

    def begin(self, stage: str) -> None:
        if self.index >= len(STAGES) or STAGES[self.index] != stage:
            raise SmokeFailure("STAGE_ORDER_INVALID")
        self.current = stage

    def passed(self) -> None:
        self.completed.append({"stage": self.current, "status": "PASS"})
        print(f"PASS: {self.current}")
        self.index += 1

    def failed(self, code: str) -> None:
        print(f"FAIL: {self.current} CODE={code}")


def _https_origin(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value.strip())
    try:
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or (port is not None and not 1 <= port <= 65535)
    ):
        return None
    return f"https://{parsed.netloc}".rstrip("/")


def _https_delivery_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        return None
    return value


def load_existing_evidence(path: Path = DEFAULT_EVIDENCE_REPORT) -> ExistingEvidence:
    """Load only the public identifiers needed from an ignored completed report."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SmokeFailure("EVIDENCE_REPORT_INVALID") from exc
    if not isinstance(raw, dict):
        raise SmokeFailure("EVIDENCE_REPORT_INVALID")
    schema = raw.get("schema_version")
    if schema not in {
        "firemark.generate-and-seal-report.v1",
        "firemark.generate-and-seal-recovery-report.v1",
    }:
        raise SmokeFailure("EVIDENCE_REPORT_INVALID")
    values = {name: raw.get(name) for name in ("cert_id", "asset_id", "run_id")}
    if any(not isinstance(value, str) or not _ID.fullmatch(value) for value in values.values()):
        raise SmokeFailure("EVIDENCE_REPORT_INVALID")
    digests = {name: raw.get(name) for name in ("sealed_sha256", "canonical_hash")}
    if any(
        not isinstance(value, str) or not _SHA256.fullmatch(value)
        for value in digests.values()
    ):
        raise SmokeFailure("EVIDENCE_REPORT_INVALID")
    source = raw.get("source_sha256")
    if source is not None and (not isinstance(source, str) or not _SHA256.fullmatch(source)):
        raise SmokeFailure("EVIDENCE_REPORT_INVALID")
    return ExistingEvidence(
        cert_id=str(values["cert_id"]),
        asset_id=str(values["asset_id"]),
        run_id=str(values["run_id"]),
        sealed_sha256=str(digests["sealed_sha256"]),
        canonical_hash=str(digests["canonical_hash"]),
        source_sha256=source,
    )


def contains_forbidden_private_fields(value: object) -> bool:
    """Find private field names recursively without inspecting or returning their values."""
    if isinstance(value, list):
        return any(contains_forbidden_private_fields(item) for item in value)
    if not isinstance(value, dict):
        return False
    for key, nested in value.items():
        normalized = str(key).lower()
        if any(field in normalized for field in _PRIVATE_FIELDS):
            return True
        if contains_forbidden_private_fields(nested):
            return True
    return False


def text_contains_private_fields(text: str) -> bool:
    """Detect exact private schema identifiers in rendered public responses."""
    normalized = text.lower()
    return any(field in normalized for field in _PRIVATE_FIELDS)


def _contains_configured_secret(texts: list[str], values: Mapping[str, str | None]) -> bool:
    secrets = [
        value
        for name in _SECRET_FIELDS
        if (value := values.get(name)) is not None and value.strip()
    ]
    return any(secret in text for secret in secrets for text in texts)


def _safe_json(response: httpx.Response) -> dict[str, Any]:
    try:
        value = response.json()
    except (ValueError, UnicodeError) as exc:
        raise SmokeFailure("RESPONSE_INVALID") from exc
    if not isinstance(value, dict):
        raise SmokeFailure("RESPONSE_INVALID")
    return value


def _require_status(response: httpx.Response, expected: int = 200) -> None:
    if response.status_code != expected:
        raise SmokeFailure("HTTP_STATUS_INVALID")


def _security_headers(response: httpx.Response) -> bool:
    csp = response.headers.get("content-security-policy", "").lower()
    return bool(
        response.headers.get("x-content-type-options", "").lower() == "nosniff"
        and response.headers.get("referrer-policy")
        and response.headers.get("permissions-policy")
        and "frame-ancestors 'none'" in csp
    )


def _write_report(path: Path, report: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise SmokeFailure("REPORT_EXISTS")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False, newline="\n"
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_live(output_report: Path, *, force: bool) -> int:
    tracker = StageTracker()
    values = dict(dotenv_values(DEFAULT_ENV_FILE)) if DEFAULT_ENV_FILE.is_file() else {}
    try:
        tracker.begin("configuration_validation")
        api_base = _https_origin(values.get("FIREMARK_DEPLOYED_API_BASE_URL"))
        web_base = _https_origin(values.get("FIREMARK_DEPLOYED_WEB_BASE_URL"))
        if api_base is None or web_base is None or api_base == web_base:
            raise SmokeFailure("DEPLOYED_CONFIGURATION_INVALID")
        evidence = load_existing_evidence(DEFAULT_EVIDENCE_REPORT)
        tracker.passed()

        statuses: dict[str, int] = {}
        public_texts: list[str] = []
        public_json: list[dict[str, Any]] = []
        frontend_responses: list[httpx.Response] = []
        timeout = httpx.Timeout(15.0, connect=5.0)
        tracker.begin("backend_health")
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            health = client.get(f"{api_base}/healthz")
            _require_status(health)
            health_json = _safe_json(health)
            if health_json.get("status") != "ok" or health_json.get("service") != "firemark-api":
                raise SmokeFailure("HEALTH_RESPONSE_INVALID")
            statuses["backend_health"] = health.status_code
            public_json.append(health_json)
            tracker.passed()

            tracker.begin("frontend_landing")
            landing = client.get(f"{web_base}/")
            _require_status(landing)
            statuses["frontend_landing"] = landing.status_code
            public_texts.append(landing.text)
            frontend_responses.append(landing)
            tracker.passed()

            tracker.begin("frontend_verify_page")
            verify_page = client.get(f"{web_base}/verify")
            _require_status(verify_page)
            statuses["frontend_verify_page"] = verify_page.status_code
            public_texts.append(verify_page.text)
            frontend_responses.append(verify_page)
            tracker.passed()

            tracker.begin("frontend_certificate_page")
            certificate_page = client.get(f"{web_base}/certificate/{evidence.cert_id}")
            _require_status(certificate_page)
            statuses["frontend_certificate_page"] = certificate_page.status_code
            public_texts.append(certificate_page.text)
            frontend_responses.append(certificate_page)
            tracker.passed()

            tracker.begin("public_certificate_api")
            certificate_response = client.get(f"{api_base}/v1/certificates/{evidence.cert_id}")
            _require_status(certificate_response)
            certificate_json = _safe_json(certificate_response)
            if contains_forbidden_private_fields(certificate_json):
                raise SmokeFailure("PRIVATE_FIELD_EXPOSED")
            certificate = PublicCertificate.model_validate(certificate_json)
            if (
                certificate.cert_id != evidence.cert_id
                or certificate.asset_id != evidence.asset_id
                or certificate.run_id != evidence.run_id
                or certificate.sealed_sha256 != evidence.sealed_sha256
                or certificate.canonical_hash != evidence.canonical_hash
                or certificate.certificate_status != "active"
            ):
                raise SmokeFailure("CERTIFICATE_MISMATCH")
            statuses["public_certificate_api"] = certificate_response.status_code
            public_json.append(certificate_json)
            tracker.passed()

            tracker.begin("public_verify_api")
            verify_response = client.post(
                f"{api_base}/v1/verify",
                json={"cert_id": evidence.cert_id, "presented_sha256": evidence.sealed_sha256},
            )
            _require_status(verify_response)
            verify_json = _safe_json(verify_response)
            verification = VerificationResult.model_validate(verify_json)
            if verification.cert_id != evidence.cert_id or not verification.verified:
                raise SmokeFailure("VERIFICATION_FAILED")
            if verification.status != "verified" or verification.hash_match is not True:
                raise SmokeFailure("VERIFICATION_FAILED")
            statuses["public_verify_api"] = verify_response.status_code
            public_json.append(verify_json)
            tracker.passed()

            tracker.begin("frontend_delivery_route")
            delivery_response = client.post(
                f"{web_base}/api/delivery/{evidence.cert_id}",
                json={"cert_id": evidence.cert_id, "presented_sha256": evidence.sealed_sha256},
            )
            _require_status(delivery_response)
            delivery_json = _safe_json(delivery_response)
            delivery_url = _https_delivery_url(delivery_json.get("download_url"))
            if (
                delivery_json.get("status") != "issued"
                or delivery_json.get("cert_id") != evidence.cert_id
                or delivery_url is None
            ):
                raise SmokeFailure("DELIVERY_RESPONSE_INVALID")
            statuses["frontend_delivery_route"] = delivery_response.status_code
            frontend_responses.append(delivery_response)
            sanitized_delivery = {key: value for key, value in delivery_json.items() if key != "download_url"}
            public_json.append(sanitized_delivery)
            tracker.passed()

            tracker.begin("delivered_asset_download")
            delivered = bytearray()
            with client.stream("GET", delivery_url) as media_response:
                _require_status(media_response)
                statuses["delivered_asset_download"] = media_response.status_code
                for chunk in media_response.iter_bytes():
                    delivered.extend(chunk)
                    if len(delivered) > MAX_DOWNLOAD_BYTES:
                        raise SmokeFailure("DELIVERED_ASSET_TOO_LARGE")
            if not delivered:
                raise SmokeFailure("DELIVERED_ASSET_EMPTY")
            delivered_bytes = bytes(delivered)
            tracker.passed()

        tracker.begin("delivered_sha256_verification")
        if hashlib.sha256(delivered_bytes).hexdigest() != evidence.sealed_sha256:
            raise SmokeFailure("DELIVERED_HASH_MISMATCH")
        tracker.passed()

        tracker.begin("embedded_capsule_verification")
        try:
            capsule = extract_public_capsule_png(delivered_bytes)
        except PublicCapsuleError as exc:
            raise SmokeFailure("PUBLIC_CAPSULE_INVALID") from exc
        if (
            capsule.cert_id != evidence.cert_id
            or capsule.asset_id != evidence.asset_id
            or capsule.run_id != evidence.run_id
            or capsule.canonical_hash != evidence.canonical_hash
            or (evidence.source_sha256 is not None and capsule.source_sha256 != evidence.source_sha256)
        ):
            raise SmokeFailure("PUBLIC_CAPSULE_MISMATCH")
        tracker.passed()

        tracker.begin("response_header_security")
        if not all(_security_headers(response) for response in frontend_responses):
            raise SmokeFailure("SECURITY_HEADERS_MISSING")
        tracker.passed()

        tracker.begin("secret_leak_scan")
        if any(text_contains_private_fields(text) for text in public_texts):
            raise SmokeFailure("PRIVATE_FIELD_EXPOSED")
        if any(contains_forbidden_private_fields(value) for value in public_json):
            raise SmokeFailure("PRIVATE_FIELD_EXPOSED")
        serialized_public = public_texts + [
            json.dumps(value, ensure_ascii=True, sort_keys=True) for value in public_json
        ]
        if _contains_configured_secret(serialized_public, values):
            raise SmokeFailure("SECRET_VALUE_EXPOSED")
        tracker.passed()

        tracker.begin("safe_report")
        report = {
            "schema_version": "firemark.deployed-stack-report.v1",
            "api_hostname": urlsplit(api_base).hostname,
            "web_hostname": urlsplit(web_base).hostname,
            "cert_id": evidence.cert_id,
            "asset_id": evidence.asset_id,
            "run_id": evidence.run_id,
            "sealed_sha256": evidence.sealed_sha256,
            "canonical_hash": evidence.canonical_hash,
            "http_status_codes": statuses,
            "byte_count": len(delivered_bytes),
            "production_deployment_evidence": True,
            "reused_existing_certificate": True,
            "new_provider_calls": 0,
            "new_certificates": 0,
            "stages": tracker.completed + [{"stage": "safe_report", "status": "PASS"}],
        }
        _write_report(output_report, report, force=force)
        tracker.passed()
        return 0
    except (SmokeFailure, ValidationError, httpx.HTTPError, OSError):
        tracker.failed("DEPLOYED_STACK_CHECK_FAILED")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify an existing certificate through an explicitly deployed FIREMARK stack."
    )
    parser.add_argument("--live", action="store_true", help="Permit deployed read/verify requests.")
    parser.add_argument(
        "--output-report", type=Path, default=DEFAULT_OUTPUT_REPORT, help="Safe JSON report path."
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing safe report.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.live:
        print("INFO: non-live mode; zero network calls.")
        print("INFO: no OpenAI, B2, Supabase, or deployed HTTP client was constructed.")
        print("INFO: pass --live only after both production deployments are configured.")
        return 2
    return run_live(args.output_report, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
