"""Provider-free recovery for one interrupted production Generate & Seal operation."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn

import httpx
from dotenv import load_dotenv

from api.firemark.b2_storage import (
    B2EventualConsistencyTimeout,
    B2IntegrityError,
    B2RetentionExpiredError,
    B2RetentionModeError,
    B2VersionIdError,
    create_assets_client,
    create_vault_client,
    download_bytes_verified,
    head_object_receipt,
    sealed_asset_key,
    upload_bytes_verified,
    verify_locked_object_exact,
)
from api.firemark.control_plane.models import (
    AssetRecord,
    CustodyRecord,
    DeliveryAuthorization,
    GenerationRunRecord,
    VerificationRequest,
)
from api.firemark.control_plane.service import (
    AuthorizedDelivery,
    B2DeliveryStorage,
    CertificateService,
)
from api.firemark.control_plane.supabase_repository import SupabaseCertificateRepository
from api.firemark.custody import B2CustodyReceipt, LockedObjectReceipt, StoredObjectReceipt
from api.firemark.genblaze_provenance import parse_complete_manifest_payload
from api.firemark.generate_and_seal import _request_fingerprint
from api.firemark.generate_checkpoint import (
    DEFAULT_CHECKPOINT_PATH,
    GenerateAndSealCheckpoint,
    checkpoint_object,
    read_checkpoint,
    write_checkpoint_atomic,
)
from api.firemark.hashing import sha256_bytes
from api.firemark.public_capsule import (
    FiremarkPublicCapsuleV1,
    embed_public_capsule_png,
    extract_public_capsule_png,
)
from api.firemark.seal_envelope import SealEnvelopeV1, sign_envelope
from api.firemark.settings import load_settings
from api.firemark.signer import Ed25519Signer

INFORMATIONAL_EXIT_CODE = 2
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
DEFAULT_REPORT = Path(".artifacts/generate-and-seal-report.json")
MAX_DISCOVERY_VERSIONS = 20
STAGES = (
    "configuration_validation",
    "checkpoint_discovery",
    "incomplete_bundle_discovery",
    "vault_source_validation",
    "vault_source_retention_verification",
    "vault_manifest_validation",
    "vault_manifest_retention_readback",
    "vault_manifest_retention_validation",
    "checkpoint_after_vault_manifest",
    "public_capsule_reconstruction",
    "sealed_asset_reconstruction",
    "sealed_hash_verification",
    "sealed_asset_upload",
    "sealed_asset_hash_verification",
    "envelope_construction",
    "envelope_signature",
    "custody_receipt_construction",
    "supabase_registration",
    "public_certificate_projection",
    "verify_gate",
    "delivery_authorization",
    "delivered_byte_integrity",
    "embedded_capsule_verification",
    "database_secret_scan",
    "checkpoint_completion",
    "safe_report",
)


class RecoveryError(RuntimeError):
    """Safe, allowlisted recovery failure with no raw remote service text."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


class StageTracker:
    """Emit deterministic stage attribution without rendering exception messages."""

    def __init__(self) -> None:
        self.current = STAGES[0]
        self.completed: list[dict[str, str]] = []

    def begin(self, stage: str) -> None:
        if stage != self.current:
            self.complete_current()
            self.current = stage

    def complete_current(self) -> None:
        if not any(item["stage"] == self.current for item in self.completed):
            self.completed.append({"stage": self.current, "status": "PASS"})
            print(f"PASS: {self.current}")

    def fail(self, category: str) -> None:
        print(f"FAIL: {self.current} (CATEGORY={category})")


@dataclass(frozen=True)
class ManifestEvidence:
    run_id: str
    provider: str
    model: str
    prompt: str
    parameters: dict[str, Any]
    seed: int | str | None
    canonical_hash: str
    source_sha256: str


def _download_delivery(url: str, *, max_bytes: int, timeout: int) -> bytes:
    with httpx.Client(follow_redirects=False, timeout=float(timeout)) as client:
        with client.stream("GET", url) as response:
            if response.status_code != 200:
                _fail("DELIVERY_FAILED")
            declared = response.headers.get("content-length")
            if declared is not None and int(declared) > max_bytes:
                _fail("DELIVERY_FAILED")
            payload = bytearray()
            for chunk in response.iter_bytes():
                payload.extend(chunk)
                if len(payload) > max_bytes:
                    _fail("DELIVERY_FAILED")
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
        _fail("VERIFICATION_FAILED")
    lowered = serialized.lower()
    if "x-amz-signature" in lowered or "authorization: bearer" in lowered:
        _fail("VERIFICATION_FAILED")


def _fail(category: str) -> NoReturn:
    raise RecoveryError(category)


def _retention_covers(returned: datetime, requested: datetime) -> bool:
    normalized_returned = returned.astimezone(UTC)
    normalized_requested = requested.astimezone(UTC)
    return normalized_returned >= normalized_requested or (
        normalized_requested - normalized_returned < timedelta(seconds=1)
    )


def validate_manifest_evidence(
    payload: bytes, checkpoint: GenerateAndSealCheckpoint | None = None
) -> ManifestEvidence:
    """Parse one private manifest in memory and require real OpenAI evidence."""
    try:
        manifest = parse_complete_manifest_payload(payload)
        if len(manifest.run.steps) != 1:
            _fail("MANIFEST_INVALID")
        step = manifest.run.steps[0]
        metadata = dict(step.metadata)
        run_metadata = dict(manifest.run.metadata)
        provider = str(step.provider).lower()
        ai_generated = (
            metadata.get("ai_generated") is True and run_metadata.get("ai_generated") is True
        )
        local_fixture = metadata.get("local_fixture") is True
        if provider != "openai" or not ai_generated or local_fixture:
            _fail("PROVIDER_EVIDENCE_INVALID")
        if len(step.assets) != 1 or not step.assets[0].sha256:
            _fail("MANIFEST_INVALID")
        evidence = ManifestEvidence(
            run_id=manifest.run.run_id,
            provider=provider,
            model=step.model,
            prompt=step.prompt or "",
            parameters=dict(step.params),
            seed=step.seed,
            canonical_hash=manifest.canonical_hash,
            source_sha256=step.assets[0].sha256,
        )
    except RecoveryError:
        raise
    except Exception:
        _fail("MANIFEST_INVALID")
    if checkpoint is not None and (
        evidence.run_id != checkpoint.run_id
        or evidence.provider != checkpoint.provider.lower()
        or evidence.model != checkpoint.model
        or evidence.canonical_hash != checkpoint.canonical_hash
        or evidence.source_sha256 != checkpoint.source_sha256
    ):
        _fail("INCOMPLETE_EVIDENCE")
    return evidence


def reconstruct_sealed_bytes(
    checkpoint: GenerateAndSealCheckpoint, source: bytes, *, public_base_url: str
) -> tuple[bytes, FiremarkPublicCapsuleV1]:
    """Deterministically recreate the public capsule and distributable PNG."""
    capsule = FiremarkPublicCapsuleV1.model_validate(
        {
            "cert_id": checkpoint.cert_id,
            "asset_id": checkpoint.asset_id,
            "run_id": checkpoint.run_id,
            "canonical_hash": checkpoint.canonical_hash,
            "source_sha256": checkpoint.source_sha256,
            "signer_key_id": checkpoint.signer_key_id,
            "verify_url": (f"{public_base_url.rstrip('/')}/v1/certificates/{checkpoint.cert_id}"),
            "issued_at": checkpoint.issued_at,
        }
    )
    try:
        sealed = embed_public_capsule_png(source, capsule)
    except Exception:
        _fail("SEALED_RECONSTRUCTION_FAILED")
    if sha256_bytes(sealed) != checkpoint.sealed_sha256:
        _fail("SEALED_RECONSTRUCTION_FAILED")
    return sealed, capsule


def select_single_candidate(candidates: Sequence[Any]) -> Any:
    """Fail closed instead of guessing between incomplete production bundles."""
    if not candidates:
        _fail("CHECKPOINT_NOT_FOUND")
    if len(candidates) != 1:
        _fail("AMBIGUOUS_INCOMPLETE_BUNDLE")
    return candidates[0]


def _safe_report_write(path: Path, report: Mapping[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        _fail("SAFE_UNEXPECTED_FAILURE")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_local_evidence(
    checkpoint: GenerateAndSealCheckpoint, *, max_bytes: int
) -> tuple[bytes, bytes]:
    source_path = Path(checkpoint.source_path)
    manifest_path = Path(checkpoint.manifest_path)
    if not source_path.is_file() or not manifest_path.is_file():
        _fail("INCOMPLETE_EVIDENCE")
    if source_path.stat().st_size > max_bytes or manifest_path.stat().st_size > max_bytes:
        _fail("INCOMPLETE_EVIDENCE")
    source = source_path.read_bytes()
    manifest = manifest_path.read_bytes()
    if sha256_bytes(source) != checkpoint.source_sha256:
        _fail("HASH_MISMATCH")
    return source, manifest


def _partial_version(checkpoint: GenerateAndSealCheckpoint, *, object_kind: str) -> tuple[str, str]:
    reference = checkpoint.vault_source if object_kind == "source" else checkpoint.vault_manifest
    if reference is not None:
        return reference.key, reference.version_id
    matches = [
        item
        for item in checkpoint.partial_objects
        if item.bucket_role == "vault" and item.object_kind == object_kind
    ]
    if len(matches) != 1 or not matches[0].version_id:
        _fail("VERSION_ID_MISSING")
    return matches[0].key, matches[0].version_id


def _verify_locked(
    client: Any,
    *,
    bucket: str,
    key: str,
    version_id: str,
    digest: str,
    max_bytes: int,
    retention_verification_callback: Callable[[], None] | None = None,
    retention_validation_callback: Callable[[], None] | None = None,
) -> tuple[LockedObjectReceipt, bytes]:
    try:
        return verify_locked_object_exact(
            client,
            bucket=bucket,
            key=key,
            expected_sha256=digest,
            version_id=version_id,
            max_bytes=max_bytes,
            retention_verification_callback=retention_verification_callback,
            retention_validation_callback=retention_validation_callback,
        )
    except B2EventualConsistencyTimeout:
        _fail("RETENTION_EVENTUAL_CONSISTENCY_TIMEOUT")
    except B2RetentionModeError:
        _fail("RETENTION_MODE_INVALID")
    except B2RetentionExpiredError:
        _fail("RETENTION_EXPIRED")
    except B2VersionIdError:
        _fail("VERSION_ID_MISSING")
    except B2IntegrityError:
        _fail("HASH_MISMATCH")
    except Exception:
        _fail("STORAGE_FAILURE")


def _ensure_unlocked(
    client: Any,
    *,
    bucket: str,
    key: str,
    payload: bytes,
    digest: str,
    content_type: str,
    kind: str,
    metadata: Mapping[str, str] | None = None,
    hash_verification_callback: Callable[[], None] | None = None,
    exact_version_id: str | None = None,
) -> StoredObjectReceipt:
    try:
        receipt = head_object_receipt(
            client,
            bucket=bucket,
            key=key,
            expected_sha256=digest,
            version_id=exact_version_id,
        )
        if receipt is None:
            if exact_version_id is not None:
                _fail("VERSION_ID_MISSING")
            receipt = upload_bytes_verified(
                client,
                bucket=bucket,
                key=key,
                data=payload,
                expected_sha256=digest,
                content_type=content_type,
                metadata={
                    "firemark-kind": kind,
                    "firemark-schema": "1",
                    **dict(metadata or {}),
                },
                known_unlocked=True,
                stage_callback=(
                    (lambda _stage: hash_verification_callback())
                    if hash_verification_callback is not None
                    else None
                ),
                hash_verification_stage=(
                    "exact_hash_verification" if hash_verification_callback is not None else None
                ),
            )
        elif receipt.version_id is None:
            _fail("VERSION_ID_MISSING")
        elif exact_version_id is not None and receipt.version_id != exact_version_id:
            _fail("VERSION_ID_MISSING")
        elif hash_verification_callback is not None:
            hash_verification_callback()
        download_bytes_verified(
            client,
            bucket=bucket,
            key=key,
            expected_sha256=digest,
            version_id=receipt.version_id,
            max_bytes=max(len(payload), 1),
        )
        return receipt
    except RecoveryError:
        raise
    except B2IntegrityError:
        _fail("HASH_MISMATCH")
    except Exception:
        _fail("STORAGE_FAILURE")


def discover_legacy_b2_bundle(
    vault_client: Any, *, vault_bucket: str, max_bytes: int
) -> dict[str, str]:
    """Discover one exact retained OpenAI bundle, without inventing capsule IDs."""
    try:
        response = vault_client.list_object_versions(
            Bucket=vault_bucket,
            Prefix="vault/manifests/",
            MaxKeys=MAX_DISCOVERY_VERSIONS,
        )
        versions = response.get("Versions", [])
        candidates: list[dict[str, str]] = []
        for item in versions:
            key = item.get("Key")
            version_id = item.get("VersionId")
            if not isinstance(key, str) or not isinstance(version_id, str):
                continue
            raw_head = vault_client.head_object(Bucket=vault_bucket, Key=key, VersionId=version_id)
            metadata = raw_head.get("Metadata", {})
            digest = metadata.get("firemark-sha256") if isinstance(metadata, dict) else None
            if not isinstance(digest, str):
                continue
            _, payload = _verify_locked(
                vault_client,
                bucket=vault_bucket,
                key=key,
                version_id=version_id,
                digest=digest,
                max_bytes=max_bytes,
            )
            try:
                evidence = validate_manifest_evidence(payload)
            except RecoveryError as exc:
                if exc.category == "PROVIDER_EVIDENCE_INVALID":
                    continue
                raise
            source_key = (
                f"vault/sources/{evidence.source_sha256[:2]}/"
                f"{evidence.source_sha256[2:4]}/{evidence.source_sha256}.png"
            )
            source_listing = vault_client.list_object_versions(
                Bucket=vault_bucket, Prefix=source_key, MaxKeys=MAX_DISCOVERY_VERSIONS
            )
            source_versions = [
                entry
                for entry in source_listing.get("Versions", [])
                if entry.get("Key") == source_key and isinstance(entry.get("VersionId"), str)
            ]
            if len(source_versions) != 1:
                continue
            source_version = source_versions[0]["VersionId"]
            _verify_locked(
                vault_client,
                bucket=vault_bucket,
                key=source_key,
                version_id=source_version,
                digest=evidence.source_sha256,
                max_bytes=max_bytes,
            )
            candidates.append(
                {
                    "run_id": evidence.run_id,
                    "manifest_key": key,
                    "manifest_version_id": version_id,
                    "source_key": source_key,
                    "source_version_id": source_version,
                }
            )
        selected = select_single_candidate(candidates)
        if not isinstance(selected, dict):
            _fail("INCOMPLETE_EVIDENCE")
        return selected
    except RecoveryError:
        raise
    except Exception:
        _fail("STORAGE_FAILURE")


def _existing_certificate_matches(certificate: Any, checkpoint: GenerateAndSealCheckpoint) -> bool:
    return bool(
        certificate.cert_id == checkpoint.cert_id
        and certificate.asset_id == checkpoint.asset_id
        and certificate.run_id == checkpoint.run_id
        and certificate.source_sha256 == checkpoint.source_sha256
        and certificate.sealed_sha256 == checkpoint.sealed_sha256
        and certificate.canonical_hash == checkpoint.canonical_hash
        and certificate.signer_key_id == checkpoint.signer_key_id
    )


def _complete_registration(
    existing: Any,
    checkpoint: GenerateAndSealCheckpoint,
    register: Callable[[], object],
) -> None:
    """Complete one atomic registration or accept identical existing evidence."""
    if existing is not None:
        if not _existing_certificate_matches(existing, checkpoint):
            _fail("CONFLICTING_CERTIFICATE")
        return
    try:
        register()
    except RecoveryError:
        raise
    except Exception:
        _fail("REGISTRATION_FAILURE")


def run_live(report_path: Path, *, force: bool) -> int:
    tracker = StageTracker()
    try:
        load_dotenv(DEFAULT_ENV_FILE, override=False)
        settings = load_settings()
        config = settings.require_generate_and_seal_config()
        live_supabase = settings.require_live_supabase_control_plane_config()
        tracker.begin("checkpoint_discovery")
        checkpoint: GenerateAndSealCheckpoint | None = None
        if DEFAULT_CHECKPOINT_PATH.is_file():
            try:
                checkpoint = read_checkpoint(DEFAULT_CHECKPOINT_PATH)
            except Exception:
                _fail("INCOMPLETE_EVIDENCE")
        tracker.begin("incomplete_bundle_discovery")
        assets_client = create_assets_client(config.b2.assets)
        vault_client = create_vault_client(config.b2.vault)
        if checkpoint is None:
            discover_legacy_b2_bundle(
                vault_client,
                vault_bucket=config.b2.vault.bucket,
                max_bytes=config.max_generated_image_bytes,
            )
            _fail("INCOMPLETE_EVIDENCE")
        source, manifest_bytes = _read_local_evidence(
            checkpoint, max_bytes=config.max_generated_image_bytes
        )
        evidence = validate_manifest_evidence(manifest_bytes, checkpoint)
        manifest_sha256 = sha256_bytes(manifest_bytes)

        repository = SupabaseCertificateRepository.from_config(config.supabase)
        existing = repository.get_certificate(checkpoint.cert_id)
        if existing is not None and not _existing_certificate_matches(existing, checkpoint):
            _fail("CONFLICTING_CERTIFICATE")

        source_key, source_version = _partial_version(checkpoint, object_kind="source")
        tracker.begin("vault_source_validation")
        vault_source, remote_source = _verify_locked(
            vault_client,
            bucket=config.b2.vault.bucket,
            key=source_key,
            version_id=source_version,
            digest=checkpoint.source_sha256,
            max_bytes=config.max_generated_image_bytes,
            retention_verification_callback=lambda: tracker.begin(
                "vault_source_retention_verification"
            ),
        )
        if remote_source != source:
            _fail("HASH_MISMATCH")
        if not _retention_covers(
            vault_source.retention_until, checkpoint.requested_retention_until
        ):
            _fail("RETENTION_EXPIRED")

        manifest_key, manifest_version = _partial_version(checkpoint, object_kind="manifest")
        tracker.begin("vault_manifest_validation")
        vault_manifest, remote_manifest = _verify_locked(
            vault_client,
            bucket=config.b2.vault.bucket,
            key=manifest_key,
            version_id=manifest_version,
            digest=manifest_sha256,
            max_bytes=config.max_generated_image_bytes,
            retention_verification_callback=lambda: tracker.begin(
                "vault_manifest_retention_readback"
            ),
            retention_validation_callback=lambda: tracker.begin(
                "vault_manifest_retention_validation"
            ),
        )
        if remote_manifest != manifest_bytes:
            _fail("HASH_MISMATCH")
        if not _retention_covers(
            vault_manifest.retention_until, checkpoint.requested_retention_until
        ):
            _fail("RETENTION_EXPIRED")
        if vault_source.version_id is None or vault_manifest.version_id is None:
            _fail("VERSION_ID_MISSING")
        vault_source_version = vault_source.version_id
        vault_manifest_version = vault_manifest.version_id
        tracker.begin("checkpoint_after_vault_manifest")
        checkpoint = checkpoint.model_copy(
            update={
                "vault_source": checkpoint_object(
                    vault_source, bucket_role="vault", object_kind="source"
                ),
                "vault_manifest": checkpoint_object(
                    vault_manifest, bucket_role="vault", object_kind="manifest"
                ),
                "stage_results": tuple(tracker.completed),
            }
        )
        write_checkpoint_atomic(DEFAULT_CHECKPOINT_PATH, checkpoint, stage=tracker.current)

        tracker.begin("public_capsule_reconstruction")
        signer = Ed25519Signer.from_private_key_base64(
            config.signing_private_key_b64.get_secret_value(),
            config.signing_public_key_b64,
        )
        if signer.signer_key_id != checkpoint.signer_key_id:
            _fail("SIGNATURE_FAILED")
        tracker.begin("sealed_asset_reconstruction")
        sealed_bytes, capsule = reconstruct_sealed_bytes(
            checkpoint, source, public_base_url=config.public_base_url
        )
        tracker.begin("sealed_hash_verification")
        if sha256_bytes(sealed_bytes) != checkpoint.sealed_sha256:
            _fail("HASH_MISMATCH")

        source_assets_key = (
            f"assets/{checkpoint.source_sha256[:2]}/{checkpoint.source_sha256[2:4]}/"
            f"{checkpoint.source_sha256}.png"
        )
        manifest_assets_key = f"manifests/{checkpoint.run_id}/{checkpoint.canonical_hash}.json"
        assets_source = _ensure_unlocked(
            assets_client,
            bucket=config.b2.assets.bucket,
            key=source_assets_key,
            payload=source,
            digest=checkpoint.source_sha256,
            content_type="image/png",
            kind="source",
        )
        assets_manifest = _ensure_unlocked(
            assets_client,
            bucket=config.b2.assets.bucket,
            key=manifest_assets_key,
            payload=manifest_bytes,
            digest=manifest_sha256,
            content_type="application/json",
            kind="manifest",
        )
        checkpoint = checkpoint.model_copy(
            update={
                "operation_state": (
                    "complete" if checkpoint.operation_state == "complete" else "custody_persisted"
                ),
                "assets_source": checkpoint_object(
                    assets_source, bucket_role="assets", object_kind="source"
                ),
                "assets_manifest": checkpoint_object(
                    assets_manifest, bucket_role="assets", object_kind="manifest"
                ),
                "vault_source": checkpoint_object(
                    vault_source, bucket_role="vault", object_kind="source"
                ),
                "vault_manifest": checkpoint_object(
                    vault_manifest, bucket_role="vault", object_kind="manifest"
                ),
                "stage_results": tuple(tracker.completed),
            }
        )
        write_checkpoint_atomic(DEFAULT_CHECKPOINT_PATH, checkpoint, stage=tracker.current)
        tracker.begin("sealed_asset_upload")
        sealed_key = sealed_asset_key(checkpoint.sealed_sha256)
        sealed_exact_version = (
            checkpoint.sealed_asset.version_id
            if checkpoint.sealed_asset is not None
            else existing.asset.assets_version_id
            if existing is not None and existing.asset is not None
            else None
        )
        sealed_receipt = _ensure_unlocked(
            assets_client,
            bucket=config.b2.assets.bucket,
            key=sealed_key,
            payload=sealed_bytes,
            digest=checkpoint.sealed_sha256,
            content_type="image/png",
            kind="sealed",
            metadata={"firemark-cert-id": checkpoint.cert_id},
            hash_verification_callback=lambda: tracker.begin("sealed_asset_hash_verification"),
            exact_version_id=sealed_exact_version,
        )
        if sealed_receipt.version_id is None:
            _fail("VERSION_ID_MISSING")
        checkpoint = checkpoint.model_copy(
            update={
                "operation_state": (
                    "complete" if checkpoint.operation_state == "complete" else "sealed_persisted"
                ),
                "sealed_asset": checkpoint_object(
                    sealed_receipt, bucket_role="assets", object_kind="sealed"
                ),
                "stage_results": tuple(tracker.completed),
            }
        )
        write_checkpoint_atomic(DEFAULT_CHECKPOINT_PATH, checkpoint, stage=tracker.current)

        tracker.begin("envelope_construction")
        envelope = SealEnvelopeV1(
            cert_id=checkpoint.cert_id,
            run_id=checkpoint.run_id,
            canonical_hash=checkpoint.canonical_hash,
            source_sha256=checkpoint.source_sha256,
            sealed_sha256=checkpoint.sealed_sha256,
            sealed_asset_bucket=sealed_receipt.bucket,
            sealed_asset_key=sealed_receipt.key,
            public_manifest_bucket=sealed_receipt.bucket,
            public_manifest_key=sealed_receipt.key,
            vault_bucket=vault_source.bucket,
            vault_source_key=vault_source.key,
            vault_source_version_id=vault_source_version,
            vault_manifest_key=vault_manifest.key,
            vault_manifest_version_id=vault_manifest_version,
            retention_until=vault_source.retention_until,
            signer_key_id=checkpoint.signer_key_id,
            created_at=checkpoint.issued_at,
        )
        tracker.begin("envelope_signature")
        try:
            signed = sign_envelope(envelope, signer)
        except Exception:
            _fail("SIGNATURE_FAILED")
        tracker.begin("custody_receipt_construction")
        custody_receipt = B2CustodyReceipt(
            source_sha256=checkpoint.source_sha256,
            canonical_hash=checkpoint.canonical_hash,
            assets_source=assets_source,
            assets_manifest=assets_manifest,
            vault_source=vault_source,
            vault_manifest=vault_manifest,
            requested_retention_until=checkpoint.requested_retention_until,
            created_at=checkpoint.issued_at,
            custody_verified=True,
        )
        generation_run = GenerationRunRecord(
            run_id=checkpoint.run_id,
            provider=evidence.provider,
            model=evidence.model,
            ai_generated=True,
            prompt_private=evidence.prompt,
            parameters_private={
                "_firemark_request_fingerprint": _request_fingerprint(
                    evidence.prompt, evidence.model, checkpoint.size
                ),
                "requested_size": checkpoint.size,
                "provider": evidence.parameters,
            },
            seed_private=evidence.seed,
            canonical_hash=checkpoint.canonical_hash,
            manifest_storage_key=assets_manifest.key,
            manifest_version_id=assets_manifest.version_id,
            created_at=checkpoint.issued_at,
        )
        asset = AssetRecord(
            asset_id=checkpoint.asset_id,
            run_id=checkpoint.run_id,
            asset_type="image",
            media_type="image/png",
            file_extension="png",
            byte_size=sealed_receipt.size_bytes,
            source_sha256=checkpoint.source_sha256,
            sealed_sha256=checkpoint.sealed_sha256,
            assets_bucket=sealed_receipt.bucket,
            assets_key=sealed_receipt.key,
            assets_version_id=sealed_receipt.version_id,
            vault_bucket=vault_source.bucket,
            vault_key=vault_source.key,
            vault_version_id=vault_source_version,
            created_at=checkpoint.issued_at,
        )
        custody = CustodyRecord(
            asset_id=checkpoint.asset_id,
            custody_receipt=custody_receipt,
            retention_mode="COMPLIANCE",
            retention_until=vault_source.retention_until,
            custody_verified=True,
            created_at=checkpoint.issued_at,
        )
        service = CertificateService(
            repository,
            public_base_url=config.public_base_url,
            storage=B2DeliveryStorage(assets_client),
            delivery_ttl_seconds=live_supabase.delivery_ttl_seconds,
        )
        tracker.begin("supabase_registration")
        registration_checkpoint = checkpoint
        _complete_registration(
            existing,
            registration_checkpoint,
            lambda: service.register_certificate(
                generation_run=generation_run,
                asset=asset,
                custody=custody,
                envelope=envelope,
                signature_b64=signed.signature,
                signer_public_key_b64=signer.export_public_key_base64(),
                public_manifest=capsule.model_dump(mode="json"),
                canonical_hash=registration_checkpoint.canonical_hash,
                cert_id=registration_checkpoint.cert_id,
                asset_id=registration_checkpoint.asset_id,
                run_id=registration_checkpoint.run_id,
            ),
        )
        checkpoint = checkpoint.model_copy(
            update={
                "operation_state": (
                    "complete" if checkpoint.operation_state == "complete" else "registered"
                ),
                "stage_results": tuple(tracker.completed),
            }
        )
        write_checkpoint_atomic(DEFAULT_CHECKPOINT_PATH, checkpoint, stage=tracker.current)
        tracker.begin("public_certificate_projection")
        if service.get_public_certificate(checkpoint.cert_id) is None:
            _fail("VERIFICATION_FAILED")
        tracker.begin("verify_gate")
        verification = service.verify(
            VerificationRequest(
                cert_id=checkpoint.cert_id,
                presented_sha256=checkpoint.sealed_sha256,
            )
        )
        if not verification.verified:
            _fail("VERIFICATION_FAILED")
        tracker.begin("delivery_authorization")
        delivery = service.authorize_delivery(
            checkpoint.cert_id,
            DeliveryAuthorization(presented_sha256=checkpoint.sealed_sha256),
        )
        if not isinstance(delivery, AuthorizedDelivery):
            _fail("DELIVERY_FAILED")
        transient_url = delivery.download.reveal_url()
        tracker.begin("delivered_byte_integrity")
        try:
            delivered = _download_delivery(
                transient_url,
                max_bytes=config.max_generated_image_bytes,
                timeout=config.generation_timeout_seconds,
            )
        finally:
            transient_url = ""
        if sha256_bytes(delivered) != checkpoint.sealed_sha256:
            _fail("DELIVERY_FAILED")
        tracker.begin("embedded_capsule_verification")
        if extract_public_capsule_png(delivered) != capsule:
            _fail("VERIFICATION_FAILED")
        tracker.begin("database_secret_scan")
        if config.openai_api_key is None:
            _fail("OPENAI_NOT_CONFIGURED")
        _database_secret_scan(
            repository,
            type(
                "Result",
                (),
                {
                    "run_id": checkpoint.run_id,
                    "asset_id": checkpoint.asset_id,
                    "cert_id": checkpoint.cert_id,
                },
            )(),
            [
                config.openai_api_key.get_secret_value(),
                config.admin_api_key.get_secret_value(),
                config.delivery_api_key.get_secret_value(),
                config.signing_private_key_b64.get_secret_value(),
                config.supabase.service_role_key.get_secret_value(),
                config.b2.assets.key_id.get_secret_value(),
                config.b2.assets.app_key.get_secret_value(),
                config.b2.vault.key_id.get_secret_value(),
                config.b2.vault.app_key.get_secret_value(),
            ],
        )
        tracker.begin("checkpoint_completion")
        updated = checkpoint.model_copy(
            update={
                "operation_state": "complete",
                "assets_source": checkpoint_object(
                    assets_source, bucket_role="assets", object_kind="source"
                ),
                "assets_manifest": checkpoint_object(
                    assets_manifest, bucket_role="assets", object_kind="manifest"
                ),
                "vault_source": checkpoint_object(
                    vault_source, bucket_role="vault", object_kind="source"
                ),
                "vault_manifest": checkpoint_object(
                    vault_manifest, bucket_role="vault", object_kind="manifest"
                ),
                "sealed_asset": checkpoint_object(
                    sealed_receipt, bucket_role="assets", object_kind="sealed"
                ),
                "stage_results": tuple(tracker.completed),
            }
        )
        write_checkpoint_atomic(DEFAULT_CHECKPOINT_PATH, updated, stage=tracker.current)
        tracker.begin("safe_report")
        write_checkpoint_atomic(
            DEFAULT_CHECKPOINT_PATH,
            updated.model_copy(update={"stage_results": tuple(tracker.completed)}),
            stage=tracker.current,
        )
        report = {
            "schema_version": "firemark.generate-and-seal-recovery-report.v1",
            "package_versions": {
                name: importlib.metadata.version(name)
                for name in ("firemark", "genblaze-core", "boto3", "supabase")
            },
            "provider": checkpoint.provider,
            "model": checkpoint.model,
            "run_id": checkpoint.run_id,
            "asset_id": checkpoint.asset_id,
            "cert_id": checkpoint.cert_id,
            "source_sha256": checkpoint.source_sha256,
            "sealed_sha256": checkpoint.sealed_sha256,
            "canonical_hash": checkpoint.canonical_hash,
            "signer_key_id": checkpoint.signer_key_id,
            "vault_source_key": vault_source.key,
            "vault_source_version_id": vault_source.version_id,
            "vault_manifest_key": vault_manifest.key,
            "vault_manifest_version_id": vault_manifest.version_id,
            "sealed_asset_key": sealed_receipt.key,
            "sealed_asset_version_id": sealed_receipt.version_id,
            "retention_until": vault_source.retention_until.isoformat(),
            "generated_byte_count": checkpoint.generated_byte_count,
            "ai_generated": True,
            "local_fixture": False,
            "resumed_from_existing_objects": True,
            "new_provider_calls": 0,
            "production_generation_evidence": True,
            "production_b2_custody_evidence": True,
            "production_supabase_evidence": True,
            "stages": tracker.completed + [{"stage": "safe_report", "status": "PASS"}],
        }
        _safe_report_write(report_path, report, force=force)
        tracker.complete_current()
        return 0
    except RecoveryError as exc:
        tracker.fail(exc.category)
        return 1
    except (httpx.HTTPError, ValueError):
        tracker.fail("SAFE_UNEXPECTED_FAILURE")
        return 1
    except Exception:
        tracker.fail("SAFE_UNEXPECTED_FAILURE")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Resume one interrupted Generate & Seal checkpoint without constructing "
            "or calling an OpenAI client."
        )
    )
    parser.add_argument("--live", action="store_true", help="Allow B2 and Supabase recovery calls.")
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
        print("INFO: recovery performs zero provider calls in every mode.")
        return INFORMATIONAL_EXIT_CODE
    return run_live(args.output_report, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
