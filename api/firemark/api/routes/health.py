"""Local health endpoint with no implicit dependency checks."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    """Stable process-health response."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["ok"]
    service: Literal["firemark-api"]
    version: str
    external_dependencies: Literal["not_checked"]


router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=HealthResponse, operation_id="healthz")
def healthz() -> HealthResponse:
    """Report local application health without contacting external systems."""
    return HealthResponse(
        status="ok",
        service="firemark-api",
        version="0.1.0",
        external_dependencies="not_checked",
    )
