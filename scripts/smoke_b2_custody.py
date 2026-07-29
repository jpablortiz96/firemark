"""Run an explicit live Backblaze B2 custody proof with local fixture content."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import urllib3
from dotenv import load_dotenv
from genblaze_core import (
    Manifest,
    Modality,
    RunBuilder,
    RunStatus,
    StepBuilder,
    StepStatus,
)
from PIL import Image, PngImagePlugin

from api.firemark.b2_storage import (
    B2Error,
    RedactedPresignedURL,
    check_bucket_access,
    create_assets_client,
    create_genblaze_assets_backend,
    create_genblaze_assets_sink,
    create_vault_client,
    delete_unlocked_version_verified,
    generate_presigned_get,
    prove_locked_delete_denial,
)
from api.firemark.custody import B2CustodyReceipt, LockedDeleteProof, execute_b2_custody
from api.firemark.hashing import sha256_file
from api.firemark.settings import load_settings

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = REPOSITORY_ROOT / ".env"
MAX_SMOKE_DOWNLOAD_BYTES = 4 * 1024 * 1024
LOCAL_RUN_ID = "firemark-b2-local-fixture-run-v1"


class LiveSmokeError(RuntimeError):
    """Raised for a safe, non-secret live smoke failure."""


def _create_deterministic_png(path: Path) -> None:
    """Create a fixed local PNG that is not AI-generated or production evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    image = Image.new("RGB", (8, 6))
    pixels = [
        ((x * 31 + y * 17) % 256, (x * 13 + y * 47) % 256, (x * 59 + y * 7) % 256)
        for y in range(6)
        for x in range(8)
    ]
    image.putdata(pixels)
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text(
        "fixture_notice",
        "FIREMARK local deterministic fixture; not AI-generated; not production evidence",
    )
    image.save(path, format="PNG", pnginfo=metadata, compress_level=9, optimize=False)


def _build_local_manifest(source_path: Path, source_sha256: str) -> Manifest:
    """Build a real Genblaze Manifest through public builders for local fixture bytes."""
    step = (
        StepBuilder("firemark-local-fixture", "deterministic-png-v1")
        .prompt("private local fixture prompt; never report or publish")
        .modality(Modality.IMAGE)
        .status(StepStatus.SUCCEEDED)
        .seed(424242)
        .params(private_fixture_parameter="local-only", fixture_guidance=7.25)
        .asset(
            source_path.resolve().as_uri(),
            "image/png",
            sha256=source_sha256,
            size_bytes=source_path.stat().st_size,
            width=8,
            height=6,
        )
        .meta(local_fixture=True, production_evidence=False)
        .build()
    )
    run = (
        RunBuilder("FIREMARK local deterministic B2 fixture")
        .run_id(LOCAL_RUN_ID)
        .status(RunStatus.COMPLETED)
        .add_step(step)
        .meta(
            local_fixture=True,
            ai_generated=False,
            provider_generated=False,
            production_evidence=False,
        )
        .build()
    )
    return Manifest.from_run(run)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prove FIREMARK custody against explicitly configured Backblaze B2 buckets.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Opt in to real network writes and persistent COMPLIANCE-locked objects.",
    )
    parser.add_argument(
        "--output-report",
        type=Path,
        help="Optional path for a safe JSON evidence report without credentials or URLs.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing output report after an explicit live run.",
    )
    return parser


def _download_presigned_https(
    value: RedactedPresignedURL,
    *,
    endpoint: str,
    expected_sha256: str,
    max_bytes: int = MAX_SMOKE_DOWNLOAD_BYTES,
) -> int:
    """Download once over bounded TLS without redirects or URL persistence."""
    url = value.reveal_url()
    parsed = urlsplit(url)
    endpoint_host = urlsplit(endpoint).hostname
    if parsed.scheme != "https" or not parsed.hostname or parsed.hostname != endpoint_host:
        raise LiveSmokeError("Presigned URL host is outside the configured B2 endpoint")
    manager = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=5, read=30),
        retries=False,
        cert_reqs="CERT_REQUIRED",
    )
    try:
        response = manager.request(
            "GET",
            url,
            preload_content=False,
            redirect=False,
        )
    except urllib3.exceptions.HTTPError as exc:
        raise LiveSmokeError("Bounded presigned HTTPS download failed") from exc
    try:
        if response.status != 200:
            raise LiveSmokeError("Presigned HTTPS download returned a non-success status")
        import hashlib

        hasher = hashlib.sha256()
        total = 0
        while chunk := response.read(64 * 1024, decode_content=False):
            total += len(chunk)
            if total > max_bytes:
                raise LiveSmokeError("Presigned HTTPS download exceeded the safety limit")
            hasher.update(chunk)
        if hasher.hexdigest() != expected_sha256:
            raise LiveSmokeError("Presigned HTTPS bytes failed SHA-256 verification")
        return total
    finally:
        response.release_conn()
        manager.clear()


def _write_report(path: Path, report: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        raise LiveSmokeError("Output report already exists; use --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        temporary.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_report(
    receipt: B2CustodyReceipt,
    proof: LockedDeleteProof,
    *,
    endpoint_host: str,
    region: str,
    presigned_size: int,
) -> dict[str, Any]:
    return {
        "ai_generated": False,
        "canonical_hash": receipt.canonical_hash,
        "checks": {
            "custody_verified": receipt.custody_verified,
            "delete_denied_by_object_lock": proof.verified,
            "genblaze_storage_contract": True,
            "presigned_download_verified": True,
        },
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "delete_proof": proof.model_dump(mode="json"),
        "endpoint_hostname": endpoint_host,
        "local_fixture": True,
        "network_scope": "configured B2 endpoint only",
        "package_versions": {
            name: importlib.metadata.version(name)
            for name in ("boto3", "botocore", "genblaze-core", "genblaze-s3")
        },
        "presigned_download_size_bytes": presigned_size,
        "production_b2_custody_evidence": True,
        "receipt": receipt.model_dump(mode="json"),
        "region": region,
    }


def _print_live_header(endpoint_host: str, region: str, assets_bucket: str, vault_bucket: str) -> None:
    print("FIREMARK B2 custody smoke test - live verification pending")
    print("Local fixture content: YES")
    print("AI-generated content: NO")
    print("Provider generation evidence: NO")
    print("Network scope: configured B2 endpoint only")
    print(f"Endpoint hostname: {endpoint_host}")
    print(f"Region: {region}")
    print(f"Assets bucket: {assets_bucket}")
    print(f"Vault bucket: {vault_bucket}")


def _run_live(output_report: Path | None, *, force: bool) -> int:
    if not DEFAULT_ENV_FILE.is_file():
        print("FAIL: ignored .env configuration is absent")
        return 3
    load_dotenv(dotenv_path=DEFAULT_ENV_FILE, override=False)
    try:
        complete = load_settings().require_complete_b2_config()
    except ValueError:
        print("FAIL: complete validated assets and vault B2 configuration is required")
        return 3

    endpoint_host = urlsplit(complete.assets.endpoint).hostname
    if endpoint_host is None:
        print("FAIL: validated B2 endpoint has no hostname")
        return 3
    _print_live_header(
        endpoint_host,
        complete.assets.region,
        complete.assets.bucket,
        complete.vault.bucket,
    )

    assets_client = create_assets_client(complete.assets)
    vault_client = create_vault_client(complete.vault)
    try:
        check_bucket_access(assets_client, bucket=complete.assets.bucket)
        check_bucket_access(vault_client, bucket=complete.vault.bucket)
        backend = create_genblaze_assets_backend(complete.assets)
        sink = create_genblaze_assets_sink(backend)
        sink.close()

        with tempfile.TemporaryDirectory(prefix="firemark-b2-custody-") as directory:
            source_path = Path(directory) / "local-fixture.png"
            _create_deterministic_png(source_path)
            source_sha256 = sha256_file(source_path)
            manifest = _build_local_manifest(source_path, source_sha256)
            manifest_bytes = manifest.to_canonical_json().encode("utf-8")
            retention_until = datetime.now(UTC) + timedelta(days=complete.vault.retention_days)
            receipt = execute_b2_custody(
                assets_client=assets_client,
                vault_client=vault_client,
                assets_bucket=complete.assets.bucket,
                vault_bucket=complete.vault.bucket,
                source_path=source_path,
                manifest_bytes=manifest_bytes,
                source_sha256=source_sha256,
                canonical_hash=manifest.canonical_hash,
                run_id=LOCAL_RUN_ID,
                cert_id="firemark-b2-live-smoke",
                extension="png",
                retention_until=retention_until,
                source_content_type="image/png",
            )
            presigned = generate_presigned_get(
                assets_client,
                bucket=receipt.assets_source.bucket,
                key=receipt.assets_source.key,
                version_id=receipt.assets_source.version_id,
                ttl_seconds=complete.assets.presigned_url_ttl_seconds,
            )
            presigned_size = _download_presigned_https(
                presigned,
                endpoint=complete.assets.endpoint,
                expected_sha256=source_sha256,
            )
            proof = prove_locked_delete_denial(vault_client, receipt.vault_manifest)

            for stored in (receipt.assets_source, receipt.assets_manifest):
                delete_unlocked_version_verified(
                    assets_client,
                    bucket=stored.bucket,
                    key=stored.key,
                    version_id=stored.version_id,
                    expected_sha256=stored.sha256,
                    known_unlocked=True,
                )

        report = _safe_report(
            receipt,
            proof,
            endpoint_host=endpoint_host,
            region=complete.assets.region,
            presigned_size=presigned_size,
        )
        if output_report is not None:
            _write_report(output_report.resolve(), report, force=force)
        print("Real Backblaze B2: YES")
        print("B2 custody evidence: YES")
        print("Object Lock mode: COMPLIANCE")
        print("Check                                      Result")
        print("------------------------------------------ ------")
        print("Genblaze public storage contract           PASS")
        print("Assets source byte verification             PASS")
        print("Assets manifest byte verification           PASS")
        print("Vault source COMPLIANCE retention           PASS")
        print("Vault manifest COMPLIANCE retention         PASS")
        print("Private presigned HTTPS download            PASS")
        print("Delete denied by Object Lock                PASS")
        print(f"Vault source key: {receipt.vault_source.key}")
        print(f"Vault source retention: {receipt.vault_source.retention_until.isoformat()}")
        print(f"Vault manifest key: {receipt.vault_manifest.key}")
        print(f"Vault manifest retention: {receipt.vault_manifest.retention_until.isoformat()}")
        return 0
    except (B2Error, LiveSmokeError, ValueError):
        print("FAIL: live custody proof did not complete")
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run only after explicit live opt-in; default behavior performs zero network calls."""
    args = _build_parser().parse_args(argv)
    if not args.live:
        print("FIREMARK B2 custody smoke test: network disabled (no --live).")
        print("Configure the ignored .env with two private B2 buckets and separate credentials.")
        print("Then rerun with --live; retained vault objects will incur storage until expiry.")
        return 2
    return _run_live(args.output_report, force=args.force)


if __name__ == "__main__":
    raise SystemExit(main())
