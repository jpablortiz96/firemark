"""Pinned public-contract tests for the authorized Genblaze S3 adapter matrix."""

from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path

from genblaze_core import KeyStrategy, ObjectStorageSink, StorageBackend
from genblaze_s3 import S3StorageBackend
from packaging.requirements import Requirement
from packaging.version import Version

from api.firemark.settings import B2AssetsConfig

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_exact_authorized_versions_and_declared_core_range() -> None:
    """Pin the spike result and prove core 0.3.8 remains inside adapter metadata."""
    assert importlib.metadata.version("genblaze-core") == "0.3.8"
    assert importlib.metadata.version("genblaze-s3") == "0.3.6"
    assert importlib.metadata.version("boto3") == "1.43.58"
    assert importlib.metadata.version("botocore") == "1.43.58"
    requirements = importlib.metadata.requires("genblaze-s3") or []
    core_requirement = next(
        Requirement(value) for value in requirements if Requirement(value).name == "genblaze-core"
    )
    assert Version("0.3.8") in core_requirement.specifier


def test_public_backend_implements_core_protocol_and_sink_accepts_it() -> None:
    """Construct the public adapter with lifecycle and preflight disabled."""
    config = B2AssetsConfig(
        endpoint="https://s3.test.invalid",
        region="test-region",
        bucket="assets-test",
        key_id="dummy-test-key-id",
        app_key="dummy-test-app-key",
        presigned_url_ttl_seconds=300,
    )
    backend = S3StorageBackend.for_backblaze(
        bucket=config.bucket,
        region=config.region,
        key_id=config.key_id.get_secret_value(),
        app_key=config.app_key.get_secret_value(),
        public_url_base=None,
        auto_lifecycle=False,
        preflight=False,
    )
    try:
        assert isinstance(backend, StorageBackend)
        sink = ObjectStorageSink(backend, key_strategy=KeyStrategy.CONTENT_ADDRESSABLE)
        assert sink is not None
    finally:
        backend.close()


def test_firemark_never_imports_private_genblaze_modules() -> None:
    """Reject direct FIREMARK coupling to underscore-prefixed upstream internals."""
    private_import = re.compile(
        r"(?:from|import)\s+(?:genblaze_core|genblaze_s3)\.[A-Za-z0-9.]*_"
    )
    offenders: list[str] = []
    for root in (REPOSITORY_ROOT / "api", REPOSITORY_ROOT / "scripts"):
        for path in root.rglob("*.py"):
            if private_import.search(path.read_text(encoding="utf-8")):
                offenders.append(str(path.relative_to(REPOSITORY_ROOT)))
    assert offenders == []
