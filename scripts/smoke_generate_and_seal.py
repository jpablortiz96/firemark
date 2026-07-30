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
from botocore.exceptions import (  # type: ignore[import-untyped]
    ClientError,
    EndpointConnectionError,
    ReadTimeoutError,
)
from dotenv import load_dotenv

from api.firemark.app import create_app
from api.firemark.b2_storage import (
    B2Error,
    classify_b2_failure,
    create_assets_client,
    create_vault_client,
    upload_bytes_verified,
)
from api.firemark.bootstrap import build_runtime
from api.firemark.control_plane.service import B2DeliveryStorage
from api.firemark.custody import (
    B2CustodyReceipt,
    B2CustodyWorkflowError,
    StoredObjectReceipt,
    execute_b2_custody,
)
from api.firemark.generate_and_seal import GenerateAndSealRequest
from api.firemark.generate_checkpoint import (
    DEFAULT_CHECKPOINT_PATH,
    DEFAULT_PRIVATE_ROOT,
    CheckpointPartialObject,
    CheckpointSerializationError,
    GenerateAndSealCheckpoint,
    checkpoint_object,
    read_checkpoint,
    write_checkpoint_atomic,
    write_private_evidence_atomic,
)
from api.firemark.generation.models import GeneratedImage, GenerationRequest
from api.firemark.generation.openai_provider import OpenAIImageProvider
from api.firemark.generation.provider import GenerationProviderError
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
    "provider_request_construction",
    "provider_generation",
    "provider_response_validation",
    "source_hash",
    "genblaze_manifest",
    "canonical_hash",
    "public_capsule_embedding",
    "sealed_hash",
    "vault_source_upload",
    "vault_source_hash_verification",
    "vault_source_retention_verification",
    "vault_manifest_upload",
    "vault_manifest_hash_verification",
    "vault_manifest_retention_readback",
    "vault_manifest_retention_validation",
    "checkpoint_after_vault_manifest",
    "sealed_asset_upload",
    "sealed_asset_hash_verification",
    "custody_receipt_construction",
    "envelope_signature",
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


_PROVIDER_CATEGORIES = {
    "authentication": "AUTHENTICATION_FAILURE",
    "permission_denied": "PERMISSION_DENIED",
    "quota_or_billing": "QUOTA_OR_BILLING_FAILURE",
    "rate_limit": "RATE_LIMIT",
    "invalid_request": "INVALID_REQUEST",
    "model_or_size_unsupported": "MODEL_OR_SIZE_UNSUPPORTED",
    "safety_rejection": "SAFETY_REJECTION",
    "timeout": "TIMEOUT",
    "unavailable": "PROVIDER_UNAVAILABLE",
    "malformed_response": "MALFORMED_RESPONSE",
    "non_png_response": "NON_PNG_RESPONSE",
    "response_too_large": "RESPONSE_TOO_LARGE",
}


def _safe_exception_details(
    exc: BaseException,
) -> tuple[str | None, CheckpointSerializationError | None]:
    current: BaseException | None = exc
    while current is not None:
        if isinstance(current, CheckpointSerializationError):
            return "CheckpointSerializationError", current
        if isinstance(current, ClientError):
            return "ClientError", None
        if isinstance(current, EndpointConnectionError):
            return "EndpointConnectionError", None
        if isinstance(current, ReadTimeoutError):
            return "ReadTimeoutError", None
        if isinstance(current, ValueError):
            return "ValueError", None
        if isinstance(current, TypeError):
            return "TypeError", None
        if isinstance(current, OSError):
            return "OSError", None
        current = current.__cause__
    return None, None


class StageTracker:
    """Advance an ordered stage before work and emit only safe status lines."""

    def __init__(self) -> None:
        self.current = STAGES[0]
        self.completed: list[dict[str, str]] = []

    def begin(self, stage: str) -> None:
        if stage == self.current:
            return
        if STAGES.index(stage) < STAGES.index(self.current):
            raise LiveSmokeError("STAGE_ORDER_INVALID")
        self.complete_current()
        self.current = stage

    def complete_current(self) -> None:
        if any(item["stage"] == self.current for item in self.completed):
            return
        self.completed.append({"stage": self.current, "status": "PASS"})
        print(f"PASS: {self.current}")

    def fail(self, exc: Exception) -> None:
        exception_class, checkpoint_error = _safe_exception_details(exc)
        if checkpoint_error is not None and checkpoint_error.stage in STAGES:
            self.current = checkpoint_error.stage
        if isinstance(exc, B2CustodyWorkflowError) and exc.stage in STAGES:
            self.current = exc.stage
        provider_code = exc.code if isinstance(exc, GenerationProviderError) else None
        b2_category: str | None = None
        b2_code: str | None = None
        bucket_role: str | None = None
        object_kind: str | None = None
        if isinstance(exc, B2CustodyWorkflowError):
            b2_category = exc.category
            b2_code = exc.service_error_code
            bucket_role = exc.bucket_role
            object_kind = exc.object_kind
        elif isinstance(exc, B2Error):
            failure = classify_b2_failure(exc, stage=self.current)
            b2_category = failure.category
            b2_code = failure.service_error_code
        elif exception_class in {
            "ClientError",
            "EndpointConnectionError",
            "ReadTimeoutError",
        }:
            failure = classify_b2_failure(exc, stage=self.current)
            b2_category = failure.category
            b2_code = failure.service_error_code
        local_category = (
            "CHECKPOINT_SERIALIZATION_ERROR"
            if checkpoint_error is not None
            else "LOCAL_VALIDATION_ERROR"
            if exception_class == "ValueError"
            else "LOCAL_TYPE_ERROR"
            if exception_class == "TypeError"
            else "LOCAL_IO_ERROR"
            if exception_class == "OSError"
            else None
        )
        if provider_code is not None:
            category = _PROVIDER_CATEGORIES.get(provider_code, "UNKNOWN_SAFE_ERROR")
        elif b2_category is not None and b2_category != "UNKNOWN_SAFE_ERROR":
            category = b2_category
        elif self.current == "configuration_validation":
            category = "CONFIGURATION_ERROR"
        elif local_category is not None:
            category = local_category
        elif b2_category is not None:
            category = b2_category
        elif isinstance(exc, LiveSmokeError):
            category = "LOCAL_ADAPTER_ERROR"
        else:
            category = "UNKNOWN_SAFE_ERROR"
        suffix = f", PROVIDER_CODE={provider_code}" if provider_code is not None else ""
        if b2_code is not None:
            suffix += f", B2_CODE={b2_code}"
        if bucket_role is not None:
            suffix += f", BUCKET_ROLE={bucket_role}"
        if object_kind is not None:
            suffix += f", OBJECT_KIND={object_kind}"
        if exception_class is not None:
            suffix += f", EXCEPTION_CLASS={exception_class}"
        if checkpoint_error is not None:
            suffix += (
                f", FIELD_PATH={checkpoint_error.field_path}, "
                f"VALUE_TYPE={checkpoint_error.value_type}"
            )
        print(f"FAIL: {self.current} (CATEGORY={category}{suffix})")
        if isinstance(exc, B2CustodyWorkflowError):
            for item in exc.partial_objects:
                version = item.version_id or "MISSING"
                print(
                    "PARTIAL: "
                    f"BUCKET_ROLE={item.bucket_role}, OBJECT_KIND={item.object_kind}, "
                    f"KEY={item.key}, VERSION_ID={version}, RETAINED={str(item.retained).lower()}"
                )


class Capture:
    """Observe safe outputs while delegating every live operation exactly once."""

    def __init__(
        self,
        provider: OpenAIImageProvider,
        stage_callback: Any = None,
        *,
        tracker: StageTracker | None = None,
        checkpoint_path: Path = DEFAULT_CHECKPOINT_PATH,
        private_root: Path = DEFAULT_PRIVATE_ROOT,
    ) -> None:
        self.provider = provider
        self.stage_callback = stage_callback or (lambda _stage: None)
        self.provider_calls = 0
        self.image: GeneratedImage | None = None
        self.manifest_bytes: bytes | None = None
        self.custody: B2CustodyReceipt | None = None
        self.sealed: StoredObjectReceipt | None = None
        self.sealed_bytes: bytes | None = None
        self.assets_client: Any = None
        self.vault_client: Any = None
        self.tracker = tracker
        self.checkpoint_path = checkpoint_path
        self.private_root = private_root

    def _checkpoint(self) -> GenerateAndSealCheckpoint:
        return read_checkpoint(self.checkpoint_path)

    def _write_checkpoint(self, checkpoint: GenerateAndSealCheckpoint) -> None:
        stages = tuple(self.tracker.completed) if self.tracker is not None else ()
        write_checkpoint_atomic(
            self.checkpoint_path,
            checkpoint.model_copy(update={"stage_results": stages}),
            stage=self.tracker.current if self.tracker is not None else "checkpoint_serialization",
        )

    def checkpoint_event(self, event: str, values: dict[str, Any]) -> None:
        """Persist allowlisted recovery state after each irreversible boundary."""
        if event == "prepared":
            source = values.pop("source_bytes")
            manifest = values.pop("manifest_bytes")
            source_path, manifest_path = write_private_evidence_atomic(
                self.private_root,
                run_id=values["run_id"],
                source_bytes=source,
                manifest_bytes=manifest,
            )
            checkpoint = GenerateAndSealCheckpoint(
                operation_state="prepared",
                generated_byte_count=len(source),
                source_path=str(source_path),
                manifest_path=str(manifest_path),
                **values,
            )
            self._write_checkpoint(checkpoint)
            return
        checkpoint = self._checkpoint()
        if event == "custody_persisted":
            custody = values["custody_receipt"]
            checkpoint = checkpoint.model_copy(
                update={
                    "operation_state": "custody_persisted",
                    "assets_source": checkpoint_object(
                        custody.assets_source, bucket_role="assets", object_kind="source"
                    ),
                    "assets_manifest": checkpoint_object(
                        custody.assets_manifest, bucket_role="assets", object_kind="manifest"
                    ),
                    "vault_source": checkpoint_object(
                        custody.vault_source, bucket_role="vault", object_kind="source"
                    ),
                    "vault_manifest": checkpoint_object(
                        custody.vault_manifest, bucket_role="vault", object_kind="manifest"
                    ),
                }
            )
        elif event == "sealed_persisted":
            checkpoint = checkpoint.model_copy(
                update={
                    "operation_state": "sealed_persisted",
                    "sealed_asset": checkpoint_object(
                        values["sealed_receipt"],
                        bucket_role="assets",
                        object_kind="sealed",
                    ),
                }
            )
        elif event == "registered":
            checkpoint = checkpoint.model_copy(update={"operation_state": "registered"})
        else:
            raise LiveSmokeError("CHECKPOINT_EVENT_INVALID")
        self._write_checkpoint(checkpoint)

    def generate_image(self, request: GenerationRequest) -> GeneratedImage:
        self.provider_calls += 1
        parameters = self.provider.build_request_parameters(request)
        self.stage_callback("provider_generation")
        client = self.provider.construct_client()
        response = self.provider.request_image(client, parameters)
        self.stage_callback("provider_response_validation")
        self.image = self.provider.validate_response(response, request)
        return self.image

    def custody_executor(self, **kwargs: Any) -> B2CustodyReceipt:
        self.manifest_bytes = kwargs["manifest_bytes"]
        kwargs["persistence_callback"] = self.checkpoint_partials
        try:
            self.custody = execute_b2_custody(**kwargs)
        except B2CustodyWorkflowError as exc:
            try:
                checkpoint = self._checkpoint()
                partials = tuple(
                    CheckpointPartialObject.model_validate(item.__dict__)
                    for item in exc.partial_objects
                )
                self._write_checkpoint(checkpoint.model_copy(update={"partial_objects": partials}))
            except Exception:
                # Preserve the precise B2 failure if a secondary checkpoint write fails.
                pass
            raise
        return self.custody

    def checkpoint_partials(self, partial_objects: tuple[Any, ...]) -> None:
        """Durably record every exact version as soon as custody persists it."""
        checkpoint = self._checkpoint()
        partials = tuple(
            CheckpointPartialObject.model_validate(item.__dict__) for item in partial_objects
        )
        self._write_checkpoint(checkpoint.model_copy(update={"partial_objects": partials}))

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
    tracker = StageTracker()
    capture: Capture | None = None

    try:
        load_dotenv(DEFAULT_ENV_FILE, override=False)
        settings = load_settings()
        config = settings.require_generate_and_seal_config()
        if config.openai_api_key is None:
            raise LiveSmokeError("OPENAI_NOT_CONFIGURED")
        live_supabase = settings.require_live_supabase_control_plane_config()
        tracker.begin("dependency_construction")
        print("NOTICE: one real OpenAI image generation may incur provider cost.")

        capture = Capture(
            OpenAIImageProvider(
                api_key=config.openai_api_key.get_secret_value(),
                timeout_seconds=config.generation_timeout_seconds,
                max_image_bytes=config.max_generated_image_bytes,
            ),
            tracker.begin,
            tracker=tracker,
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
                "stage_callback": tracker.begin,
                "checkpoint_callback": capture.checkpoint_event,
            },
        )
        service = runtime.generate_and_seal_service
        if service is None:
            raise LiveSmokeError("PRODUCTION_SERVICE_UNAVAILABLE")
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
        if sha256_bytes(capture.image.data) != result.source_sha256:
            raise LiveSmokeError("SOURCE_HASH_MISMATCH")
        if (
            capture.manifest_bytes is None
            or result.canonical_hash.encode() not in capture.manifest_bytes
        ):
            raise LiveSmokeError("PRIVATE_MANIFEST_INVALID")
        if capture.sealed_bytes is None:
            raise LiveSmokeError("SEALED_BYTES_UNAVAILABLE")
        capsule = extract_public_capsule_png(capture.sealed_bytes)
        if sha256_bytes(capture.sealed_bytes) != result.sealed_sha256:
            raise LiveSmokeError("SEALED_HASH_MISMATCH")
        certificate = runtime.repository.get_certificate(result.cert_id)
        if certificate is None or not verify_signed_envelope(
            certificate.signed_envelope, certificate.signer_public_key_b64
        ):
            raise LiveSmokeError("ENVELOPE_SIGNATURE_INVALID")
        if capture.custody is None or not capture.custody.custody_verified:
            raise LiveSmokeError("VAULT_CUSTODY_INVALID")
        if capture.sealed is None or capture.sealed.version_id is None:
            raise LiveSmokeError("SEALED_UPLOAD_INVALID")
        tracker.begin("public_certificate_projection")
        from supabase import create_client

        public_client = create_client(config.supabase.url, live_supabase.publishable_key)
        projection = public_client.rpc(
            "get_firemark_public_certificate", {"p_cert_id": result.cert_id}
        ).execute()
        if not projection.data:
            raise LiveSmokeError("PUBLIC_PROJECTION_MISSING")

        tracker.begin("verify_gate")
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
        tracker.begin("delivery_authorization")
        delivery = client.post(
            f"/v1/delivery/{result.cert_id}",
            json={"presented_sha256": result.sealed_sha256},
            headers={"Authorization": f"Bearer {config.delivery_api_key.get_secret_value()}"},
        )
        if delivery.status_code != 200:
            raise LiveSmokeError("DELIVERY_AUTHORIZATION_FAILED")
        raw_url = delivery.json().get("download_url")
        if not isinstance(raw_url, str):
            raise LiveSmokeError("DELIVERY_URL_MISSING")
        tracker.begin("delivered_byte_integrity")
        delivered = _download_delivery(
            raw_url,
            max_bytes=config.max_generated_image_bytes,
            timeout=config.generation_timeout_seconds,
        )
        if sha256_bytes(delivered) != result.sealed_sha256:
            raise LiveSmokeError("DELIVERED_HASH_MISMATCH")
        tracker.begin("embedded_capsule_verification")
        if extract_public_capsule_png(delivered) != capsule:
            raise LiveSmokeError("DELIVERED_CAPSULE_MISMATCH")

        tracker.begin("database_secret_scan")
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
        checkpoint = capture._checkpoint().model_copy(update={"operation_state": "complete"})
        capture._write_checkpoint(checkpoint)
        tracker.begin("safe_report")
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
            "stages": tracker.completed + [{"stage": "safe_report", "status": "PASS"}],
        }
        _write_report(report_path, report, force=force)
        tracker.complete_current()
        return 0
    except Exception as exc:
        tracker.fail(exc)
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
