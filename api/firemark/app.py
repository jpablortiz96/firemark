"""FastAPI application factory for the FIREMARK Control Plane."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.responses import Response

from api.firemark.api.errors import APIError, ErrorDetail, ErrorResponse
from api.firemark.api.routes import certificates, delivery, health, verify
from api.firemark.control_plane.memory_repository import MemoryCertificateRepository
from api.firemark.control_plane.repository import CertificateRepository
from api.firemark.control_plane.service import CertificateService, DeliveryStorage
from api.firemark.control_plane.supabase_repository import SupabaseCertificateRepository
from api.firemark.settings import Settings, load_settings

logger = logging.getLogger("firemark.api")


def _request_id() -> str:
    return f"fmreq_{uuid4().hex}"


def _error_payload(request: Request, code: str, message: str) -> dict[str, object]:
    response = ErrorResponse(
        error=ErrorDetail(code=code, message=message, request_id=str(request.state.request_id))
    )
    return response.model_dump(mode="json")


def create_app(
    settings: Settings | None = None,
    repository: CertificateRepository | None = None,
    storage: DeliveryStorage | None = None,
) -> FastAPI:
    """Construct a dependency-injected application without external network clients."""
    selected_settings = settings or load_settings()
    if repository is not None:
        selected_repository = repository
    elif selected_settings.supabase_url is not None:
        selected_repository = SupabaseCertificateRepository.from_config(
            selected_settings.require_supabase_config()
        )
    else:
        selected_repository = MemoryCertificateRepository()
    service = CertificateService(
        selected_repository,
        public_base_url=selected_settings.public_base_url or "https://firemark.invalid",
        storage=storage,
        delivery_ttl_seconds=selected_settings.delivery_ttl_seconds,
    )
    app = FastAPI(
        title="FIREMARK Control Plane",
        version="0.1.0",
        description="Public Birth Certificates and verification-gated delivery.",
    )
    app.state.certificate_service = service

    @app.middleware("http")
    async def correlation_and_safe_logging(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request.state.request_id = _request_id()
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        response.headers["X-Request-ID"] = request.state.request_id
        logger.info(
            "request_complete request_id=%s route=%s status=%s elapsed_ms=%s",
            request.state.request_id,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response

    @app.exception_handler(APIError)
    async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload(request, exc.code, exc.safe_message),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        del exc
        return JSONResponse(
            status_code=422,
            content=_error_payload(request, "MALFORMED_REQUEST", "Request validation failed."),
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        del exc
        return JSONResponse(
            status_code=500,
            content=_error_payload(request, "INTERNAL_ERROR", "An internal error occurred."),
        )

    app.include_router(health.router)
    app.include_router(certificates.router)
    app.include_router(verify.router)
    app.include_router(delivery.router)
    return app
