"""Explicit runtime dependency graph with no import-time external clients."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from api.firemark.control_plane.repository import CertificateRepository
from api.firemark.control_plane.service import CertificateService, DeliveryStorage
from api.firemark.generate_and_seal import GenerateAndSealService
from api.firemark.settings import Settings


class LazyDeliveryStorage:
    """Construct one injected B2 delivery adapter only on the first authorized request."""

    def __init__(self, factory: Any) -> None:
        self._factory = factory
        self._storage: DeliveryStorage | None = None
        self._lock = threading.Lock()

    def issue_download(self, asset: Any, *, ttl_seconds: int) -> Any:
        if self._storage is None:
            with self._lock:
                if self._storage is None:
                    self._storage = self._factory()
        return self._storage.issue_download(asset, ttl_seconds=ttl_seconds)


@dataclass(frozen=True)
class FiremarkRuntime:
    """Application-owned dependencies selected by the composition root."""

    settings: Settings
    repository: CertificateRepository
    certificate_service: CertificateService
    generate_and_seal_service: GenerateAndSealService | None
