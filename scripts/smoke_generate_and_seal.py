"""Explicit opt-in live proof for one production FIREMARK Generate & Seal PNG."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from dotenv import load_dotenv

from api.firemark.app import create_app
from api.firemark.b2_storage import (
    create_assets_client,
    create_vault_client,
    download_bytes_verified,
    upload_bytes_verified,
)
from api.firemark.bootstrap import build_runtime
from api.firemark.control_plane.service import B2DeliveryStorage
from api.firemark.custody import B2CustodyReceipt, StoredObjectReceipt, execute_b2_custody
from api.firemark.generate_and_seal import GenerateAndSealRequest
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.openai_provider import OpenAIImageProvider
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import extract_public_capsule_png
from api.firemark.seal_envelope import verify_signed_envelope
from api.firemark.settings import load_settings

INFORMATIONAL_EXIT_CODE = 2
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
DEFAULT_REPORT = Path(".artifacts/generate-and-seal-report.json")
STAGES = (
    "configuration_validation",
    "dependency_construction",
    "provider_generation",
    "source_hash",
    "genblaze_manifest",
    "canonical_hash",
    "public_capsule_embedding",
    "sealed_hash",
    "envelope_signature",
    "vault_custody",
    "sealed_asset_upload",
    "supabase_registration",
    "public_certificate_projection",
    "verify_gate",
    "delivery_authorization",
    "delivered_byte_integrity",
    "embedded_capsule_verification",
    "database_secret_scan",
    "safe_report",
)


class LiveSmokeError(RuntimeError):
    """Safe failure containing only a normalized stage reason."""


class Capture:
    """Observe safe outputs while delegating every live operation exactly once."""

    def __init__(self, provider: OpenAIImageProvider) -> None:
        self.provider = provider
        self.provider_calls = 0
        self.image: GeneratedImage | None = None
        self.manifest_bytes: bytes | None = None
        self.custody: B2CustodyReceipt | None = None
        self.sealed: StoredObjectReceipt | None = None
        self.sealed_bytes: bytes | None = None
        self.assets_client: Any = None
        self.vault_client: Any = None

    def generate_image(self, request: GenerationRequest) -> GeneratedImage:
        self.provider_calls += 1
        self.image = self.provider.generate_image(request)
        return self.image

    def custody_executor(self, **kwargs: Any) -> B2CustodyReceipt:
        self.manifest_bytes = kwargs["manifest_bytes"]
        self.custody = execute_b2_custody(**kwargs)
        return self.custody

    def sealed_uploader(self, client: Any, **kwargs: Any) -> StoredObjectReceipt:
        self.sealed_bytes = kwargs["data"]
        self.sealed = upload_bytes_verified(client, **kwargs)
        return self.sealed


def _write_report(path: Path, report: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise LiveSmokeError("REPORT_EXISTS_USE_FORCE")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.close(descriptor)
        temporary = Path(name)
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _download_delivery(url: str, *, max_bytes: int, timeout: int) -> bytes:
    with httpx.Client(follow_redirects=False, timeout=float(timeout)) as client:
        with client.stream("GET", url) as response:
            if response.status_code != 200:
                raise LiveSmokeError("DELIVERY_DOWNLOAD_FAILED")
            declared = response.headers.get("content-length")
            if declared is not None and int(declared) > max_bytes:
                raise LiveSmokeError("DELIVERY_TOO_LARGE")
            payload = bytearray()
            for chunk in response.iter_bytes():
                payload.extend(chunk)
                if len(payload) > max_bytes:
                    raise LiveSmokeError("DELIVERY_TOO_LARGE")
            return bytes(payload)


def _database_secret_scan(repository: Any, result: Any, secrets: Sequence[str]) -> None:
    client = repository._get_client()
    targets = (
        ("generation_runs", "run_id", result.run_id),
        ("assets", "asset_id", result.asset_id),
        ("custody_records", "asset_id", result.asset_id),
        ("certificates", "cert_id", result.cert_id),
        ("verification_events", "cert_id", result.cert_id),
        ("delivery_events", "cert_id", result.cert_id),
    )
    rows: list[Any] = []
    for table, field, value in targets:
        response = client.table(table).select("*").eq(field, value).execute()
        rows.extend(response.data or [])
    serialized = json.dumps(rows, default=str, ensure_ascii=True)
    if any(secret and secret in serialized for secret in secrets):
        raise LiveSmokeError("DATABASE_CREDENTIAL_VALUE_FOUND")
    lowered = serialized.lower()
    if "x-amz-signature" in lowered or "authorization: bearer" in lowered:
        raise LiveSmokeError("DATABASE_TRANSIENT_URL_OR_AUTH_FOUND")


def run_live(report_path: Path, *, force: bool) -> int:
    completed: list[dict[str, str]] = []
    current_stage = STAGES[0]

    def passed(stage: str) -> None:
        nonlocal current_stage
        current_stage = stage
        completed.append({"stage": stage, "status": "PASS"})
        print(f"PASS: {stage}")

    try:
        load_dotenv(DEFAULT_ENV_FILE, override=False)
        settings = load_settings()
        config = settings.require_generate_and_seal_config()
        live_supabase = settings.require_live_supabase_control_plane_config()
        passed("configuration_validation")
        print("NOTICE: one real OpenAI image generation may incur provider cost.")

        capture = Capture(
            OpenAIImageProvider(
                api_key=config.openai_api_key.get_secret_value(),
                timeout_seconds=config.generation_timeout_seconds,
                max_image_bytes=config.max_generated_image_bytes,
            )
        )

        def assets_factory() -> Any:
            if capture.assets_client is None:
                capture.assets_client = create_assets_client(config.b2.assets)
            return capture.assets_client

        def vault_factory() -> Any:
            if capture.vault_client is None:
                capture.vault_client = create_vault_client(config.b2.vault)
            return capture.vault_client

        runtime = build_runtime(
            settings,
            production_overrides={
                "provider_factory": lambda: capture,
                "assets_client_factory": assets_factory,
                "vault_client_factory": vault_factory,
                "custody_executor": capture.custody_executor,
                "sealed_uploader": capture.sealed_uploader,
            },
        )
        service = runtime.generate_and_seal_service
        if service is None:
            raise LiveSmokeError("PRODUCTION_SERVICE_UNAVAILABLE")
        passed("dependency_construction")
        result = service.generate_and_seal(
            GenerateAndSealRequest(
                prompt=(
                    "A minimal red wax seal on archival paper, centered composition, "
                    "neutral studio lighting"
                )
            ),
            idempotency_key=f"live-generate-and-seal-{uuid4().hex}",
        )
        if capture.provider_calls != 1 or capture.image is None or not capture.image.ai_generated:
            raise LiveSmokeError("EXACTLY_ONE_AI_GENERATION_REQUIRED")
        passed("provider_generation")
        if sha256_bytes(capture.image.data) != result.source_sha256:
            raise LiveSmokeError("SOURCE_HASH_MISMATCH")
        passed("source_hash")
        if capture.manifest_bytes is None or result.canonical_hash.encode() not in capture.manifest_bytes:
            raise LiveSmokeError("PRIVATE_MANIFEST_INVALID")
        passed("genblaze_manifest")
        passed("canonical_hash")
        if capture.sealed_bytes is None:
            raise LiveSmokeError("SEALED_BYTES_UNAVAILABLE")
        capsule = extract_public_capsule_png(capture.sealed_bytes)
        passed("public_capsule_embedding")
        if sha256_bytes(capture.sealed_bytes) != result.sealed_sha256:
            raise LiveSmokeError("SEALED_HASH_MISMATCH")
        passed("sealed_hash")
        certificate = runtime.repository.get_certificate(result.cert_id)
        if certificate is None or not verify_signed_envelope(
            certificate.signed_envelope, certificate.signer_public_key_b64
        ):
            raise LiveSmokeError("ENVELOPE_SIGNATURE_INVALID")
        passed("envelope_signature")
        if capture.custody is None or not capture.custody.custody_verified:
            raise LiveSmokeError("VAULT_CUSTODY_INVALID")
        passed("vault_custody")
        if capture.sealed is None or capture.sealed.version_id is None:
            raise LiveSmokeError("SEALED_UPLOAD_INVALID")
        download_bytes_verified(
            capture.assets_client,
            bucket=capture.sealed.bucket,
            key=capture.sealed.key,
            expected_sha256=result.sealed_sha256,
            version_id=capture.sealed.version_id,
            max_bytes=config.max_generated_image_bytes,
        )
        passed("sealed_asset_upload")
        passed("supabase_registration")

        from supabase import create_client

        public_client = create_client(config.supabase.url, live_supabase.publishable_key)
        projection = public_client.rpc(
            "get_firemark_public_certificate", {"p_cert_id": result.cert_id}
        ).execute()
        if not projection.data:
            raise LiveSmokeError("PUBLIC_PROJECTION_MISSING")
        passed("public_certificate_projection")

        from fastapi.testclient import TestClient

        app = create_app(
            settings,
            repository=runtime.repository,
            storage=B2DeliveryStorage(capture.assets_client),
            generate_and_seal_service=service,
        )
        client = TestClient(app)
        verify = client.post(
            "/v1/verify",
            json={"cert_id": result.cert_id, "presented_sha256": result.sealed_sha256},
        )
        if verify.status_code != 200 or not verify.json().get("verified"):
            raise LiveSmokeError("VERIFY_GATE_FAILED")
        passed("verify_gate")
        delivery = client.post(
            f"/v1/delivery/{result.cert_id}",
            json={"presented_sha256": result.sealed_sha256},
            headers={
                "Authorization": f"Bearer {config.delivery_api_key.get_secret_value()}"
            },
        )
        if delivery.status_code != 200:
            raise LiveSmokeError("DELIVERY_AUTHORIZATION_FAILED")
        raw_url = delivery.json().get("download_url")
        if not isinstance(raw_url, str):
            raise LiveSmokeError("DELIVERY_URL_MISSING")
        passed("delivery_authorization")
        delivered = _download_delivery(
            raw_url,
            max_bytes=config.max_generated_image_bytes,
            timeout=config.generation_timeout_seconds,
        )
        if sha256_bytes(delivered) != result.sealed_sha256:
            raise LiveSmokeError("DELIVERED_HASH_MISMATCH")
        passed("delivered_byte_integrity")
        if extract_public_capsule_png(delivered) != capsule:
            raise LiveSmokeError("DELIVERED_CAPSULE_MISMATCH")
        passed("embedded_capsule_verification")

        secret_values = [
            config.openai_api_key.get_secret_value(),
            config.admin_api_key.get_secret_value(),
            config.delivery_api_key.get_secret_value(),
            config.signing_private_key_b64.get_secret_value(),
            config.supabase.service_role_key.get_secret_value(),
            config.b2.assets.key_id.get_secret_value(),
            config.b2.assets.app_key.get_secret_value(),
            config.b2.vault.key_id.get_secret_value(),
            config.b2.vault.app_key.get_secret_value(),
        ]
        _database_secret_scan(runtime.repository, result, secret_values)
        passed("database_secret_scan")
        report = {
            "schema_version": "firemark.generate-and-seal-report.v1",
            "package_versions": {
                name: importlib.metadata.version(name)
                for name in ("firemark", "openai", "genblaze-core", "boto3", "supabase")
            },
            "provider": capture.image.provider,
            "model": capture.image.model,
            "image_size": config.openai_image_size,
            "run_id": result.run_id,
            "asset_id": result.asset_id,
            "cert_id": result.cert_id,
            "source_sha256": result.source_sha256,
            "sealed_sha256": result.sealed_sha256,
            "canonical_hash": result.canonical_hash,
            "signer_key_id": capsule.signer_key_id,
            "sealed_asset_key": capture.sealed.key,
            "sealed_asset_version_id": capture.sealed.version_id,
            "vault_source_key": capture.custody.vault_source.key,
            "vault_source_version_id": capture.custody.vault_source.version_id,
            "vault_manifest_key": capture.custody.vault_manifest.key,
            "vault_manifest_version_id": capture.custody.vault_manifest.version_id,
            "retention_until": capture.custody.vault_source.retention_until.isoformat(),
            "public_certificate_url": str(result.certificate_url),
            "verify_url": str(result.verify_url),
            "generated_image_size": len(capture.image.data),
            "ai_generated": True,
            "local_fixture": False,
            "production_generation_evidence": True,
            "production_b2_custody_evidence": True,
            "production_supabase_evidence": True,
            "stages": completed + [{"stage": "safe_report", "status": "PASS"}],
        }
        _write_report(report_path, report, force=force)
        passed("safe_report")
        return 0
    except Exception:
        print(f"FAIL: {current_stage} (LIVE_CHECKPOINT_FAILED)")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one explicit production Generate & Seal verification checkpoint."
    )
    parser.add_argument("--live", action="store_true", help="Allow real external calls and cost.")
    parser.add_argument(
        "--output-report", type=Path, default=DEFAULT_REPORT, help="Safe JSON report path."
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing report.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.live:
        print("INFO: --live not supplied; zero network calls were made.")
        print("INFO: no OpenAI, B2, or Supabase client was constructed.")
        return INFORMATIONAL_EXIT_CODE
    return run_live(args.output_report, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
