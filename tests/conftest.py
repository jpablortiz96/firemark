"""Shared zero-network controls and explicit Backblaze live-test gating."""

from __future__ import annotations

import io
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

_REAL_SOCKET_CONNECT = socket.socket.connect


def _local_socketpair() -> tuple[socket.socket, socket.socket]:
    """Create only the loopback self-pipe required by Windows asyncio."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        _REAL_SOCKET_CONNECT(client, listener.getsockname())
        server, _ = listener.accept()
        return server, client
    except Exception:
        client.close()
        raise
    finally:
        listener.close()


def pytest_addoption(parser: pytest.Parser) -> None:
    """Require an explicit second opt-in before any live B2 test can run."""
    parser.addoption(
        "--run-live-b2",
        action="store_true",
        default=False,
        help="Allow tests marked live_b2 to contact the configured Backblaze endpoint.",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip live tests unless both marker selection and the command option are present."""
    enabled = bool(config.getoption("--run-live-b2")) and "live_b2" in config.option.markexpr
    if enabled:
        return
    marker = pytest.mark.skip(reason="live_b2 requires -m live_b2 and --run-live-b2")
    for item in items:
        if "live_b2" in item.keywords:
            item.add_marker(marker)


@pytest.fixture(autouse=True)
def block_ordinary_network(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail DNS and external connections while allowing only the asyncio self-pipe."""
    live_enabled = bool(request.config.getoption("--run-live-b2")) and "live_b2" in getattr(
        request.config.option, "markexpr", ""
    )
    if "live_b2" in request.keywords and live_enabled:
        return

    def blocked(*args: object, **kwargs: object) -> None:
        raise AssertionError("Ordinary FIREMARK tests must not access the network")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "socketpair", _local_socketpair)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)


def service_error(code: str, operation: str = "DeleteObject") -> ClientError:
    """Return a test-only botocore service error without request secrets."""
    return ClientError(
        {"Error": {"Code": code, "Message": "test-only service failure"}},
        operation,
    )


class FakeS3Client:
    """Small explicit in-memory double for FIREMARK's boto3 call surface."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.objects: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.lock_enabled = True
        self.retention_mode = "COMPLIANCE"
        self.omit_retention = False
        self.corrupt_download = False
        self.delete_error_code: str | None = "AccessDenied"
        self.remove_on_denied_delete = False
        self.raise_for: dict[str, Exception] = {}
        self.version_counter = 0

    def _raise(self, operation: str) -> None:
        if operation in self.raise_for:
            raise self.raise_for[operation]

    def _find(self, bucket: str, key: str, version_id: str | None) -> dict[str, Any]:
        if version_id is not None:
            identity = (bucket, key, version_id)
            if identity in self.objects:
                return self.objects[identity]
        matches = [value for (b, k, _), value in self.objects.items() if b == bucket and k == key]
        if not matches:
            raise service_error("NoSuchKey", "HeadObject")
        return matches[-1]

    def head_bucket(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("head_bucket", kwargs))
        self._raise("head_bucket")
        return {}

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("put_object", kwargs))
        self._raise("put_object")
        body = kwargs["Body"]
        data = body if isinstance(body, bytes) else body.read()
        self.version_counter += 1
        version_id = f"test-version-{self.version_counter}"
        self.objects[(kwargs["Bucket"], kwargs["Key"], version_id)] = {
            "Body": data,
            "ContentType": kwargs["ContentType"],
            "Metadata": dict(kwargs["Metadata"]),
            "VersionId": version_id,
            "ETag": '"etag-is-not-sha256"',
            "LastModified": datetime(2026, 4, 1, tzinfo=UTC),
            "Retention": {
                "Mode": self.retention_mode,
                "RetainUntilDate": kwargs.get(
                    "ObjectLockRetainUntilDate", datetime(2030, 1, 1, tzinfo=UTC)
                ),
            },
        }
        return {"VersionId": version_id, "ETag": '"etag-is-not-sha256"'}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("head_object", kwargs))
        self._raise("head_object")
        obj = self._find(kwargs["Bucket"], kwargs["Key"], kwargs.get("VersionId"))
        return {
            "ContentLength": len(obj["Body"]),
            "ContentType": obj["ContentType"],
            "Metadata": dict(obj["Metadata"]),
            "VersionId": obj["VersionId"],
            "ETag": obj["ETag"],
            "LastModified": obj["LastModified"],
        }

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object", kwargs))
        self._raise("get_object")
        obj = self._find(kwargs["Bucket"], kwargs["Key"], kwargs.get("VersionId"))
        data: bytes = obj["Body"]
        if self.corrupt_download:
            data += b"corrupt"
        return {
            "Body": io.BytesIO(data),
            "ContentLength": len(data),
            "ContentType": obj["ContentType"],
            "VersionId": obj["VersionId"],
            "ETag": obj["ETag"],
        }

    def delete_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("delete_object", kwargs))
        self._raise("delete_object")
        if self.delete_error_code is not None:
            if self.remove_on_denied_delete:
                identity = (kwargs["Bucket"], kwargs["Key"], kwargs.get("VersionId"))
                self.objects.pop(identity, None)
            raise service_error(self.delete_error_code)
        identity = (kwargs["Bucket"], kwargs["Key"], kwargs.get("VersionId"))
        self.objects.pop(identity, None)
        return {}

    def generate_presigned_url(self, *args: Any, **kwargs: Any) -> str:
        self.calls.append(("generate_presigned_url", {"args": args, **kwargs}))
        self._raise("generate_presigned_url")
        return "https://s3.test.invalid/bucket/key?X-Amz-Signature=test-signature"

    def get_object_retention(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object_retention", kwargs))
        self._raise("get_object_retention")
        obj = self._find(kwargs["Bucket"], kwargs["Key"], kwargs.get("VersionId"))
        if self.omit_retention:
            return {}
        retention = dict(obj["Retention"])
        retention["Mode"] = self.retention_mode
        return {"Retention": retention}

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_object_lock_configuration", kwargs))
        self._raise("get_object_lock_configuration")
        return {
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled" if self.lock_enabled else "Disabled"
            }
        }


@pytest.fixture
def fake_s3() -> FakeS3Client:
    """Provide one isolated storage double."""
    return FakeS3Client()


@pytest.fixture
def source_file(tmp_path: Path) -> tuple[Path, bytes]:
    """Provide deterministic test-only source bytes."""
    path = tmp_path / "test-source.png"
    payload = b"test-only-png-bytes"
    path.write_bytes(payload)
    return path, payload
