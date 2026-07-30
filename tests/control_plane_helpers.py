"""Deterministic internal evidence used by zero-network control-plane tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from api.firemark.control_plane.memory_repository import MemoryCertificateRepository
from api.firemark.control_plane.models import AssetRecord, CustodyRecord, GenerationRunRecord
from api.firemark.control_plane.service import CertificateService
from api.firemark.custody import B2CustodyReceipt, LockedObjectReceipt, StoredObjectReceipt
from api.firemark.public_capsule import FiremarkPublicCapsuleV1
from api.firemark.seal_envelope import SealEnvelopeV1, sign_envelope
from api.firemark.signer import Ed25519Signer

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
SOURCE = "1" * 64
SEALED = "2" * 64
CANONICAL = "3" * 64
MANIFEST = "4" * 64


@dataclass(frozen=True)
class Evidence:
    """One internally consistent certificate registration bundle."""

    generation_run: GenerationRunRecord
    asset: AssetRecord
    custody: CustodyRecord
    envelope: SealEnvelopeV1
    signature_b64: str
    signer_public_key_b64: str
    public_manifest: dict[str, object]


def build_evidence() -> Evidence:
    signer = Ed25519Signer.generate()
    retention = NOW + timedelta(days=90)
    assets_source = StoredObjectReceipt(
        bucket="assets-bucket",
        key="assets/11/11/source.png",
        sha256=SOURCE,
        content_type="image/png",
        size_bytes=100,
        version_id="assets-source-version",
        created_at=NOW,
    )
    assets_manifest = StoredObjectReceipt(
        bucket="assets-bucket",
        key=f"manifests/firemark-run-1/{CANONICAL}.json",
        sha256=MANIFEST,
        content_type="application/json",
        size_bytes=200,
        version_id="assets-manifest-version",
        created_at=NOW,
    )
    vault_source = LockedObjectReceipt(
        **assets_source.model_dump(exclude={"bucket", "key", "version_id"}),
        bucket="vault-bucket",
        key="vault/sources/11/11/source.png",
        version_id="vault-source-version",
        retention_until=retention,
    )
    vault_manifest = LockedObjectReceipt(
        **assets_manifest.model_dump(exclude={"bucket", "key", "version_id"}),
        bucket="vault-bucket",
        key=f"vault/manifests/firemark-run-1/{CANONICAL}.json",
        version_id="vault-manifest-version",
        retention_until=retention,
    )
    receipt = B2CustodyReceipt(
        source_sha256=SOURCE,
        canonical_hash=CANONICAL,
        assets_source=assets_source,
        assets_manifest=assets_manifest,
        vault_source=vault_source,
        vault_manifest=vault_manifest,
        requested_retention_until=retention,
        created_at=NOW,
        custody_verified=True,
    )
    generation = GenerationRunRecord(
        run_id="firemark-run-1",
        provider="private-provider",
        model="private-model",
        ai_generated=True,
        prompt_private="private prompt",
        parameters_private={"private": True},
        seed_private=42,
        canonical_hash=CANONICAL,
        manifest_storage_key=assets_manifest.key,
        manifest_version_id=assets_manifest.version_id,
        created_at=NOW,
    )
    asset = AssetRecord(
        asset_id="firemark-asset-1",
        run_id=generation.run_id,
        asset_type="image",
        media_type="image/png",
        file_extension="png",
        byte_size=100,
        source_sha256=SOURCE,
        sealed_sha256=SEALED,
        assets_bucket="assets-bucket",
        assets_key="sealed/22/22/final.png",
        assets_version_id="sealed-assets-version",
        vault_bucket="vault-bucket",
        vault_key=vault_source.key,
        vault_version_id=vault_source.version_id,
        created_at=NOW,
    )
    custody = CustodyRecord(
        asset_id=asset.asset_id,
        custody_receipt=receipt,
        retention_mode="COMPLIANCE",
        retention_until=retention,
        custody_verified=True,
        created_at=NOW,
    )
    envelope = SealEnvelopeV1(
        cert_id="firemark-cert-1",
        run_id=generation.run_id,
        canonical_hash=CANONICAL,
        source_sha256=SOURCE,
        sealed_sha256=SEALED,
        sealed_asset_bucket=asset.assets_bucket,
        sealed_asset_key=asset.assets_key,
        public_manifest_bucket="assets-bucket",
        public_manifest_key="public/firemark-cert-1/pointer.json",
        vault_bucket=asset.vault_bucket,
        vault_source_key=asset.vault_key,
        vault_source_version_id=asset.vault_version_id,
        vault_manifest_key=vault_manifest.key,
        vault_manifest_version_id=vault_manifest.version_id,
        retention_until=retention,
        signer_key_id=signer.signer_key_id,
        created_at=NOW,
    )
    signed = sign_envelope(envelope, signer)
    return Evidence(
        generation_run=generation,
        asset=asset,
        custody=custody,
        envelope=envelope,
        signature_b64=signed.signature,
        signer_public_key_b64=signer.export_public_key_base64(),
        public_manifest=FiremarkPublicCapsuleV1(
            cert_id=envelope.cert_id,
            asset_id=asset.asset_id,
            run_id=generation.run_id,
            canonical_hash=CANONICAL,
            source_sha256=SOURCE,
            signer_key_id=signer.signer_key_id,
            verify_url=f"https://certs.firemark.test/v1/certificates/{envelope.cert_id}",
            issued_at=NOW,
        ).model_dump(mode="json"),
    )


def register(service: CertificateService, evidence: Evidence) -> None:
    service.register_certificate(
        generation_run=evidence.generation_run,
        asset=evidence.asset,
        custody=evidence.custody,
        envelope=evidence.envelope,
        signature_b64=evidence.signature_b64,
        signer_public_key_b64=evidence.signer_public_key_b64,
        public_manifest=evidence.public_manifest,
        canonical_hash=CANONICAL,
        cert_id=evidence.envelope.cert_id,
        asset_id=evidence.asset.asset_id,
        run_id=evidence.generation_run.run_id,
    )


def registered_service() -> tuple[CertificateService, MemoryCertificateRepository, Evidence]:
    repository = MemoryCertificateRepository()
    service = CertificateService(repository, public_base_url="https://certs.firemark.test")
    evidence = build_evidence()
    register(service, evidence)
    return service, repository, evidence
