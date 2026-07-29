"""Zero-network tests for FIREMARK Backblaze storage controls."""

from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import EndpointConnectionError  # type: ignore[import-untyped]

from api.firemark.b2_storage import (
    B2ConfigurationError,
    B2DeleteProofError,
    B2IntegrityError,
    B2OperationError,
    B2RetentionError,
    RedactedPresignedURL,
    assets_manifest_key,
    assets_source_key,
    check_bucket_access,
    create_assets_client,
    create_genblaze_assets_backend,
    create_genblaze_assets_sink,
    create_vault_client,
    delete_unlocked_object,
    download_bytes_verified,
    generate_presigned_get,
    head_object_receipt,
    normalize_extension,
    prove_locked_delete_denial,
    public_custody_receipt_key,
    public_pointer_key,
    public_signed_envelope_key,
    read_object_retention,
    stream_download_verified,
    upload_bytes_verified,
    upload_file_verified,
    upload_locked_bytes,
    upload_locked_file,
    vault_manifest_key,
    vault_source_key,
    verify_bucket_object_lock_enabled,
)
from api.firemark.custody import LockedObjectReceipt
from api.firemark.hashing import sha256_bytes
from api.firemark.settings import B2AssetsConfig, B2VaultConfig
from tests.conftest import FakeS3Client, service_error

DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64


@pytest.mark.parametrize(
    ("builder", "expected"),
    [
        (lambda: assets_source_key(DIGEST, ".PNG"), f"assets/aa/aa/{DIGEST}.png"),
        (lambda: assets_manifest_key("run-1", DIGEST), f"manifests/run-1/{DIGEST}.json"),
        (lambda: public_pointer_key("cert-1"), "public/cert-1/pointer.json"),
        (
            lambda: public_signed_envelope_key("cert-1"),
            "public/cert-1/signed-envelope.json",
        ),
        (
            lambda: public_custody_receipt_key("cert-1"),
            "public/cert-1/custody-receipt.json",
        ),
        (lambda: vault_source_key(DIGEST, "PNG"), f"vault/sources/aa/aa/{DIGEST}.png"),
        (lambda: vault_manifest_key("run-1", DIGEST), f"vault/manifests/run-1/{DIGEST}.json"),
    ],
)
def test_deterministic_key_layout(builder: Any, expected: str) -> None:
    assert builder() == expected
    assert not expected.startswith("/")
    assert "\\" not in expected


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "g" * 64])
def test_key_builders_reject_noncanonical_digest(digest: str) -> None:
    with pytest.raises(ValueError, match="64 lowercase"):
        assets_source_key(digest, "png")


@pytest.mark.parametrize("identifier", ["", "../escape", "a/b", "a\\b", "a..b", "?bad"])
def test_key_builders_reject_blank_or_traversing_identifiers(identifier: str) -> None:
    with pytest.raises(ValueError):
        assets_manifest_key(identifier, DIGEST)
    with pytest.raises(ValueError):
        public_pointer_key(identifier)


@pytest.mark.parametrize("extension", ["exe", "png.exe", "../png", "", "prompt text"])
def test_extension_allowlist_rejects_unsafe_values(extension: str) -> None:
    with pytest.raises(ValueError, match="Unsupported"):
        normalize_extension(extension)


def test_client_factory_receives_explicit_secure_configuration() -> None:
    captured: dict[str, Any] = {}

    def factory(service: str, **kwargs: Any) -> FakeS3Client:
        captured.update({"service": service, **kwargs})
        return FakeS3Client()

    config = B2AssetsConfig(
        endpoint="https://s3.test.invalid",
        region="test-region",
        bucket="assets-test",
        key_id="test-key-id",
        app_key="test-app-key",
        presigned_url_ttl_seconds=300,
    )
    client = create_assets_client(config, client_factory=factory)

    assert isinstance(client, FakeS3Client)
    assert captured["service"] == "s3"
    assert captured["endpoint_url"] == "https://s3.test.invalid"
    assert captured["region_name"] == "test-region"
    assert captured["aws_access_key_id"] == "test-key-id"
    assert captured["aws_secret_access_key"] == "test-app-key"
    assert captured["verify"] is True
    botocore_config = captured["config"]
    assert botocore_config.signature_version == "s3v4"
    assert botocore_config.s3["addressing_style"] == "path"
    assert botocore_config.connect_timeout == 5
    assert botocore_config.read_timeout == 30
    assert botocore_config.retries == {"mode": "standard", "max_attempts": 3}

    vault = B2VaultConfig(
        endpoint="https://s3.test.invalid",
        region="test-region",
        bucket="vault-test",
        key_id="vault-key-id",
        app_key="vault-app-key",
        retention_days=90,
    )
    assert isinstance(create_vault_client(vault, client_factory=factory), FakeS3Client)


def test_firemark_genblaze_factory_builds_public_sink_without_network() -> None:
    config = B2AssetsConfig(
        endpoint="https://s3.test.invalid",
        region="test-region",
        bucket="assets-test",
        key_id="dummy-key-id",
        app_key="dummy-app-key",
        presigned_url_ttl_seconds=300,
    )
    backend = create_genblaze_assets_backend(config)
    try:
        sink = create_genblaze_assets_sink(backend)
        assert sink is not None
    finally:
        backend.close()
    with pytest.raises(B2ConfigurationError, match="does not implement"):
        create_genblaze_assets_sink(object())  # type: ignore[arg-type]


def test_bucket_access_success_and_wrapped_failure(fake_s3: FakeS3Client) -> None:
    check_bucket_access(fake_s3, bucket="assets-test")
    fake_s3.raise_for["head_bucket"] = service_error("AccessDenied", "HeadBucket")
    with pytest.raises(B2OperationError, match="head_bucket"):
        check_bucket_access(fake_s3, bucket="assets-test")


def test_upload_bytes_heads_downloads_and_does_not_trust_etag(fake_s3: FakeS3Client) -> None:
    data = b"verified object bytes"
    digest = sha256_bytes(data)

    receipt = upload_bytes_verified(
        fake_s3,
        bucket="assets-test",
        key=assets_source_key(digest, "png"),
        data=data,
        expected_sha256=digest,
        content_type="image/png",
        metadata={"firemark-kind": "source", "firemark-schema": "1"},
        known_unlocked=True,
    )

    assert receipt.sha256 == digest
    assert receipt.etag == '"etag-is-not-sha256"'
    assert receipt.version_id == "test-version-1"
    assert [name for name, _ in fake_s3.calls] == ["put_object", "head_object", "get_object"]
    put = fake_s3.calls[0][1]
    assert put["ContentType"] == "image/png"
    assert put["Metadata"]["firemark-sha256"] == digest


def test_upload_file_and_local_digest_guard(
    fake_s3: FakeS3Client,
    source_file: tuple[Path, bytes],
) -> None:
    path, data = source_file
    digest = sha256_bytes(data)
    receipt = upload_file_verified(
        fake_s3,
        bucket="assets-test",
        key=assets_source_key(digest, "png"),
        path=path,
        expected_sha256=digest,
        content_type="image/png",
        known_unlocked=True,
    )
    assert receipt.size_bytes == len(data)

    with pytest.raises(B2IntegrityError, match="Upload file"):
        upload_file_verified(
            fake_s3,
            bucket="assets-test",
            key="assets/conflict.png",
            path=path,
            expected_sha256=OTHER_DIGEST,
            content_type="image/png",
        )


def test_upload_rejects_local_and_remote_checksum_mismatch(fake_s3: FakeS3Client) -> None:
    data = b"expected"
    with pytest.raises(B2IntegrityError, match="Upload bytes"):
        upload_bytes_verified(
            fake_s3,
            bucket="assets-test",
            key="assets/bad.bin",
            data=data,
            expected_sha256=OTHER_DIGEST,
            content_type="application/octet-stream",
        )

    fake_s3.corrupt_download = True
    fake_s3.delete_error_code = None
    with pytest.raises(B2IntegrityError, match="Downloaded"):
        upload_bytes_verified(
            fake_s3,
            bucket="assets-test",
            key="assets/corrupt.bin",
            data=data,
            expected_sha256=sha256_bytes(data),
            content_type="application/octet-stream",
            known_unlocked=True,
        )
    assert "delete_object" in [name for name, _ in fake_s3.calls]


def test_metadata_allowlist_and_values_are_enforced(fake_s3: FakeS3Client) -> None:
    data = b"metadata"
    digest = sha256_bytes(data)
    with pytest.raises(B2ConfigurationError, match="non-allowlisted"):
        upload_bytes_verified(
            fake_s3,
            bucket="assets-test",
            key="assets/metadata.bin",
            data=data,
            expected_sha256=digest,
            content_type="application/octet-stream",
            metadata={"prompt": "must-not-store"},
        )
    with pytest.raises(B2ConfigurationError, match="value is unsafe"):
        upload_bytes_verified(
            fake_s3,
            bucket="assets-test",
            key="assets/metadata.bin",
            data=data,
            expected_sha256=digest,
            content_type="application/octet-stream",
            metadata={"firemark-kind": "x" * 300},
        )


def test_service_errors_wrapped_but_programming_errors_propagate(fake_s3: FakeS3Client) -> None:
    data = b"errors"
    digest = sha256_bytes(data)
    fake_s3.raise_for["put_object"] = service_error("AccessDenied", "PutObject")
    with pytest.raises(B2OperationError, match="put_object"):
        upload_bytes_verified(
            fake_s3,
            bucket="assets-test",
            key="assets/error.bin",
            data=data,
            expected_sha256=digest,
            content_type="application/octet-stream",
        )

    fake_s3.raise_for["put_object"] = TypeError("test-only programming error")
    with pytest.raises(TypeError, match="programming"):
        upload_bytes_verified(
            fake_s3,
            bucket="assets-test",
            key="assets/error.bin",
            data=data,
            expected_sha256=digest,
            content_type="application/octet-stream",
        )


def test_bounded_download_and_missing_head(fake_s3: FakeS3Client) -> None:
    data = b"bounded"
    digest = sha256_bytes(data)
    upload_bytes_verified(
        fake_s3,
        bucket="assets-test",
        key="assets/bounded.bin",
        data=data,
        expected_sha256=digest,
        content_type="application/octet-stream",
    )
    with pytest.raises(B2IntegrityError, match="memory limit"):
        download_bytes_verified(
            fake_s3,
            bucket="assets-test",
            key="assets/bounded.bin",
            expected_sha256=digest,
            max_bytes=2,
        )
    assert (
        head_object_receipt(
            fake_s3,
            bucket="assets-test",
            key="missing",
            expected_sha256=digest,
        )
        is None
    )


def test_stream_download_hashes_atomically_and_protects_destination(
    fake_s3: FakeS3Client,
    tmp_path: Path,
) -> None:
    data = b"streamed bytes" * 50
    digest = sha256_bytes(data)
    upload_bytes_verified(
        fake_s3,
        bucket="assets-test",
        key="assets/stream.bin",
        data=data,
        expected_sha256=digest,
        content_type="application/octet-stream",
    )
    destination = tmp_path / "download.bin"
    receipt = stream_download_verified(
        fake_s3,
        bucket="assets-test",
        key="assets/stream.bin",
        destination=destination,
        expected_sha256=digest,
        chunk_size=7,
        max_bytes=len(data),
    )
    assert destination.read_bytes() == data
    assert receipt.sha256 == digest
    with pytest.raises(FileExistsError):
        stream_download_verified(
            fake_s3,
            bucket="assets-test",
            key="assets/stream.bin",
            destination=destination,
            expected_sha256=digest,
        )


def test_presigned_get_is_bounded_and_redacted(fake_s3: FakeS3Client) -> None:
    value = generate_presigned_get(
        fake_s3,
        bucket="assets-test",
        key="assets/private.bin",
        ttl_seconds=300,
    )
    secret_url = value.reveal_url()
    assert secret_url not in repr(value)
    assert secret_url not in str(value)
    assert "test-signature" not in repr(value)
    assert str(value) == "<redacted presigned GET>"
    call = fake_s3.calls[-1][1]
    assert call["ExpiresIn"] == 300
    assert call["HttpMethod"] == "GET"
    for ttl in (59, 901, True):
        with pytest.raises(B2ConfigurationError, match="between 60 and 900"):
            generate_presigned_get(
                fake_s3,
                bucket="assets-test",
                key="assets/private.bin",
                ttl_seconds=ttl,  # type: ignore[arg-type]
            )
    with pytest.raises(B2ConfigurationError, match="HTTPS"):
        RedactedPresignedURL("http://unsafe.invalid/object?signature=x", 300)


def test_delete_requires_known_unlocked_and_sends_no_bypass(fake_s3: FakeS3Client) -> None:
    with pytest.raises(B2ConfigurationError, match="retention state is unknown"):
        delete_unlocked_object(fake_s3, bucket="assets-test", key="object")
    fake_s3.delete_error_code = None
    delete_unlocked_object(
        fake_s3,
        bucket="assets-test",
        key="object",
        known_unlocked=True,
    )
    assert "BypassGovernanceRetention" not in fake_s3.calls[-1][1]


def test_object_lock_disabled_and_past_retention_are_rejected(fake_s3: FakeS3Client) -> None:
    fake_s3.lock_enabled = False
    with pytest.raises(B2RetentionError, match="does not report"):
        verify_bucket_object_lock_enabled(fake_s3, bucket="vault-test")
    with pytest.raises(B2RetentionError, match="future"):
        upload_locked_bytes(
            fake_s3,
            bucket="vault-test",
            key="vault/past.bin",
            data=b"past",
            expected_sha256=sha256_bytes(b"past"),
            content_type="application/octet-stream",
            retention_until=datetime(2020, 1, 1, tzinfo=UTC),
        )


def test_locked_bytes_send_compliance_and_preserve_version(fake_s3: FakeS3Client) -> None:
    data = b"locked manifest"
    digest = sha256_bytes(data)
    requested = datetime.now(UTC) + timedelta(days=1)
    receipt = upload_locked_bytes(
        fake_s3,
        bucket="vault-test",
        key="vault/manifest.json",
        data=data,
        expected_sha256=digest,
        content_type="application/json",
        retention_until=requested,
        metadata={"firemark-kind": "manifest", "firemark-schema": "1"},
    )
    put = next(values for name, values in fake_s3.calls if name == "put_object")
    assert put["ObjectLockMode"] == "COMPLIANCE"
    assert put["ObjectLockRetainUntilDate"] == requested
    assert "BypassGovernanceRetention" not in put
    assert receipt.version_id == "test-version-1"
    assert receipt.retention_verified is True
    assert receipt.retention_mode == "COMPLIANCE"


def test_locked_file_and_retention_failure_modes(
    fake_s3: FakeS3Client,
    source_file: tuple[Path, bytes],
) -> None:
    path, data = source_file
    requested = datetime.now(UTC) + timedelta(days=1)
    receipt = upload_locked_file(
        fake_s3,
        bucket="vault-test",
        key="vault/source.png",
        path=path,
        expected_sha256=sha256_bytes(data),
        content_type="image/png",
        retention_until=requested,
    )
    assert receipt.size_bytes == len(data)

    fake_s3.retention_mode = "GOVERNANCE"
    with pytest.raises(B2RetentionError, match="not COMPLIANCE"):
        read_object_retention(
            fake_s3,
            bucket=receipt.bucket,
            key=receipt.key,
            version_id=receipt.version_id,
        )
    fake_s3.retention_mode = "COMPLIANCE"
    fake_s3.omit_retention = True
    with pytest.raises(B2RetentionError, match="no object retention"):
        read_object_retention(
            fake_s3,
            bucket=receipt.bucket,
            key=receipt.key,
            version_id=receipt.version_id,
        )


def _locked_receipt(fake_s3: FakeS3Client) -> LockedObjectReceipt:
    data = b"delete proof"
    return upload_locked_bytes(
        fake_s3,
        bucket="vault-test",
        key="vault/delete-proof.json",
        data=data,
        expected_sha256=sha256_bytes(data),
        content_type="application/json",
        retention_until=datetime(2030, 1, 1, tzinfo=UTC),
    )


def test_delete_denial_requires_full_corroboration(fake_s3: FakeS3Client) -> None:
    receipt = _locked_receipt(fake_s3)
    proof = prove_locked_delete_denial(
        fake_s3,
        receipt,
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert proof.verified is True
    assert proof.error_code == "AccessDenied"
    delete = next(values for name, values in fake_s3.calls if name == "delete_object")
    assert "BypassGovernanceRetention" not in delete


@pytest.mark.parametrize(
    "error_code",
    ["InvalidAccessKeyId", "SignatureDoesNotMatch", "NoSuchKey", "RequestTimeout"],
)
def test_delete_proof_rejects_unrelated_service_errors(
    fake_s3: FakeS3Client,
    error_code: str,
) -> None:
    receipt = _locked_receipt(fake_s3)
    fake_s3.delete_error_code = error_code
    with pytest.raises(B2DeleteProofError, match="not retention-compatible"):
        prove_locked_delete_denial(
            fake_s3,
            receipt,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_delete_proof_rejects_timeout_success_and_missing_afterward(fake_s3: FakeS3Client) -> None:
    receipt = _locked_receipt(fake_s3)
    fake_s3.raise_for["delete_object"] = EndpointConnectionError(endpoint_url="https://test.invalid")
    with pytest.raises(B2DeleteProofError, match="transport"):
        prove_locked_delete_denial(fake_s3, receipt, now=datetime(2026, 1, 1, tzinfo=UTC))

    fake_s3.raise_for.clear()
    fake_s3.delete_error_code = None
    with pytest.raises(B2DeleteProofError, match="unexpectedly succeeded"):
        prove_locked_delete_denial(fake_s3, receipt, now=datetime(2026, 1, 1, tzinfo=UTC))

    receipt = _locked_receipt(fake_s3)
    fake_s3.delete_error_code = "AccessDenied"
    fake_s3.remove_on_denied_delete = True
    with pytest.raises(B2DeleteProofError, match="missing after"):
        prove_locked_delete_denial(fake_s3, receipt, now=datetime(2026, 1, 1, tzinfo=UTC))


def test_expired_or_missing_retention_does_not_prove_delete(fake_s3: FakeS3Client) -> None:
    receipt = _locked_receipt(fake_s3)
    identity = (receipt.bucket, receipt.key, receipt.version_id)
    fake_s3.objects[identity]["Retention"]["RetainUntilDate"] = datetime(2025, 1, 1, tzinfo=UTC)
    with pytest.raises(B2DeleteProofError, match="not currently active"):
        prove_locked_delete_denial(fake_s3, receipt, now=datetime(2026, 1, 1, tzinfo=UTC))

    fake_s3.objects[identity]["Retention"]["RetainUntilDate"] = datetime(2030, 1, 1, tzinfo=UTC)
    fake_s3.omit_retention = True
    with pytest.raises(B2RetentionError, match="no object retention"):
        prove_locked_delete_denial(fake_s3, receipt, now=datetime(2026, 1, 1, tzinfo=UTC))


def test_download_body_shape_and_transport_failures_are_safe(fake_s3: FakeS3Client) -> None:
    fake_s3.raise_for["get_object"] = service_error("AccessDenied", "GetObject")
    with pytest.raises(B2OperationError, match="get_object"):
        download_bytes_verified(
            fake_s3,
            bucket="assets-test",
            key="asset",
            expected_sha256=DIGEST,
        )

    class MissingBodyClient(FakeS3Client):
        def get_object(self, **kwargs: Any) -> dict[str, Any]:
            return {"ContentLength": 0}

    with pytest.raises(B2OperationError, match="no readable body"):
        download_bytes_verified(
            MissingBodyClient(),
            bucket="assets-test",
            key="asset",
            expected_sha256=DIGEST,
        )


def test_head_metadata_conflict_is_integrity_failure(fake_s3: FakeS3Client) -> None:
    data = b"head conflict"
    digest = sha256_bytes(data)
    upload_bytes_verified(
        fake_s3,
        bucket="assets-test",
        key="assets/conflict.bin",
        data=data,
        expected_sha256=digest,
        content_type="application/octet-stream",
    )
    obj = next(iter(fake_s3.objects.values()))
    obj["Metadata"]["firemark-sha256"] = OTHER_DIGEST
    with pytest.raises(B2IntegrityError, match="metadata"):
        head_object_receipt(
            fake_s3,
            bucket="assets-test",
            key="assets/conflict.bin",
            expected_sha256=digest,
        )


def test_malformed_head_responses_fail_closed(fake_s3: FakeS3Client) -> None:
    data = b"malformed head"
    digest = sha256_bytes(data)
    upload_bytes_verified(
        fake_s3,
        bucket="assets-test",
        key="asset",
        data=data,
        expected_sha256=digest,
        content_type="application/octet-stream",
    )
    obj = next(iter(fake_s3.objects.values()))
    obj["LastModified"] = "not-a-date"
    with pytest.raises(B2OperationError, match="timestamp"):
        head_object_receipt(
            fake_s3, bucket="assets-test", key="asset", expected_sha256=digest
        )
    obj["LastModified"] = datetime.now(UTC)
    obj["ContentType"] = ""
    with pytest.raises(B2OperationError, match="no content type"):
        head_object_receipt(
            fake_s3, bucket="assets-test", key="asset", expected_sha256=digest
        )

    class NegativeLengthClient(FakeS3Client):
        def head_object(self, **kwargs: Any) -> dict[str, Any]:
            response = super().head_object(**kwargs)
            response["ContentLength"] = -1
            return response

    malformed = NegativeLengthClient()
    malformed.objects = fake_s3.objects
    with pytest.raises(B2OperationError, match="content length"):
        head_object_receipt(malformed, bucket="assets-test", key="asset", expected_sha256=digest)


def test_head_transport_and_service_failures_are_wrapped(fake_s3: FakeS3Client) -> None:
    fake_s3.raise_for["head_object"] = service_error("AccessDenied", "HeadObject")
    with pytest.raises(B2OperationError, match="head_object"):
        head_object_receipt(fake_s3, bucket="assets-test", key="asset", expected_sha256=DIGEST)
    fake_s3.raise_for["head_object"] = EndpointConnectionError(
        endpoint_url="https://test.invalid"
    )
    with pytest.raises(B2OperationError, match="head_object"):
        head_object_receipt(fake_s3, bucket="assets-test", key="asset", expected_sha256=DIGEST)


def test_download_rejects_invalid_limits_and_nonbytes_body() -> None:
    class NonBytesBody:
        def read(self, size: int) -> str:
            return "not bytes"

        def close(self) -> None:
            return None

    class BodyClient(FakeS3Client):
        def get_object(self, **kwargs: Any) -> dict[str, Any]:
            return {"Body": NonBytesBody()}

    with pytest.raises(ValueError, match="positive"):
        download_bytes_verified(
            BodyClient(), bucket="assets-test", key="asset", expected_sha256=DIGEST, max_bytes=0
        )
    with pytest.raises(B2OperationError, match="non-bytes"):
        download_bytes_verified(
            BodyClient(), bucket="assets-test", key="asset", expected_sha256=DIGEST
        )

    class UnboundedBodyClient(FakeS3Client):
        def get_object(self, **kwargs: Any) -> dict[str, Any]:
            return {"Body": io.BytesIO(b"too large")}

    with pytest.raises(B2IntegrityError, match="memory limit"):
        download_bytes_verified(
            UnboundedBodyClient(),
            bucket="assets-test",
            key="asset",
            expected_sha256=DIGEST,
            max_bytes=2,
        )


def test_blank_content_type_and_size_mismatch_fail(fake_s3: FakeS3Client) -> None:
    data = b"content"
    digest = sha256_bytes(data)
    with pytest.raises(B2ConfigurationError, match="content_type"):
        upload_bytes_verified(
            fake_s3,
            bucket="assets-test",
            key="asset",
            data=data,
            expected_sha256=digest,
            content_type=" ",
        )

    class WrongSizeClient(FakeS3Client):
        def head_object(self, **kwargs: Any) -> dict[str, Any]:
            response = super().head_object(**kwargs)
            response["ContentLength"] += 1
            return response

    with pytest.raises(B2IntegrityError, match="size"):
        upload_bytes_verified(
            WrongSizeClient(),
            bucket="assets-test",
            key="asset",
            data=data,
            expected_sha256=digest,
            content_type="application/octet-stream",
        )


def test_stream_failure_branches_are_bounded(fake_s3: FakeS3Client, tmp_path: Path) -> None:
    for kwargs in ({"chunk_size": 0}, {"max_bytes": 0}):
        with pytest.raises(ValueError, match="positive"):
            stream_download_verified(
                fake_s3,
                bucket="assets-test",
                key="asset",
                destination=tmp_path / "out",
                expected_sha256=DIGEST,
                **kwargs,
            )
    fake_s3.raise_for["get_object"] = service_error("AccessDenied", "GetObject")
    with pytest.raises(B2OperationError, match="get_object"):
        stream_download_verified(
            fake_s3,
            bucket="assets-test",
            key="asset",
            destination=tmp_path / "out",
            expected_sha256=DIGEST,
        )

    class MissingBody(FakeS3Client):
        def get_object(self, **kwargs: Any) -> dict[str, Any]:
            return {}

    with pytest.raises(B2OperationError, match="no readable body"):
        stream_download_verified(
            MissingBody(),
            bucket="assets-test",
            key="asset",
            destination=tmp_path / "out",
            expected_sha256=DIGEST,
        )


def test_presign_delete_lock_and_retention_service_errors(fake_s3: FakeS3Client) -> None:
    fake_s3.raise_for["generate_presigned_url"] = service_error("AccessDenied", "Presign")
    with pytest.raises(B2OperationError, match="generate_presigned_url"):
        generate_presigned_get(fake_s3, bucket="assets-test", key="asset", ttl_seconds=300)
    fake_s3.raise_for.clear()
    fake_s3.raise_for["delete_object"] = service_error("AccessDenied")
    with pytest.raises(B2OperationError, match="delete_object"):
        delete_unlocked_object(
            fake_s3, bucket="assets-test", key="asset", known_unlocked=True
        )
    fake_s3.raise_for.clear()
    fake_s3.raise_for["get_object_lock_configuration"] = service_error(
        "AccessDenied", "GetObjectLockConfiguration"
    )
    with pytest.raises(B2RetentionError, match="get_object_lock_configuration"):
        verify_bucket_object_lock_enabled(fake_s3, bucket="vault-test")
    fake_s3.raise_for.clear()
    fake_s3.raise_for["get_object_retention"] = service_error(
        "AccessDenied", "GetObjectRetention"
    )
    with pytest.raises(B2RetentionError, match="get_object_retention"):
        read_object_retention(fake_s3, bucket="vault-test", key="object")


def test_locked_upload_guards_and_service_errors(
    fake_s3: FakeS3Client,
    source_file: tuple[Path, bytes],
) -> None:
    path, data = source_file
    future = datetime.now(UTC) + timedelta(days=1)
    with pytest.raises(B2RetentionError, match="timezone-aware"):
        upload_locked_bytes(
            fake_s3,
            bucket="vault-test",
            key="object",
            data=data,
            expected_sha256=sha256_bytes(data),
            content_type="image/png",
            retention_until=datetime(2030, 1, 1),
        )
    with pytest.raises(B2IntegrityError, match="Locked upload bytes"):
        upload_locked_bytes(
            fake_s3,
            bucket="vault-test",
            key="object",
            data=data,
            expected_sha256=OTHER_DIGEST,
            content_type="image/png",
            retention_until=future,
        )
    with pytest.raises(B2IntegrityError, match="Locked upload file"):
        upload_locked_file(
            fake_s3,
            bucket="vault-test",
            key="object",
            path=path,
            expected_sha256=OTHER_DIGEST,
            content_type="image/png",
            retention_until=future,
        )
    fake_s3.raise_for["put_object"] = service_error("AccessDenied", "PutObject")
    with pytest.raises(B2OperationError, match="locked put_object"):
        upload_locked_bytes(
            fake_s3,
            bucket="vault-test",
            key="object",
            data=data,
            expected_sha256=sha256_bytes(data),
            content_type="image/png",
            retention_until=future,
        )
