"""Authenticated Generate & Seal endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header

from api.firemark.api.auth import require_admin_api_key
from api.firemark.api.dependencies import get_generate_and_seal_service
from api.firemark.api.errors import APIError, ErrorResponse
from api.firemark.generate_and_seal import (
    GenerateAndSealError,
    GenerateAndSealRequest,
    GenerateAndSealResult,
    GenerateAndSealService,
    IdempotencyConflictError,
)
from api.firemark.generation.provider import GenerationProviderError

router = APIRouter(prefix="/v1", tags=["generation"])


@router.post(
    "/generate-and-seal",
    status_code=201,
    response_model=GenerateAndSealResult,
    responses={
        401: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        502: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    operation_id="generate_and_seal",
    dependencies=[Depends(require_admin_api_key)],
)
def generate_and_seal(
    request: GenerateAndSealRequest,
    service: Annotated[GenerateAndSealService, Depends(get_generate_and_seal_service)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
) -> GenerateAndSealResult:
    try:
        return service.generate_and_seal(request, idempotency_key=idempotency_key)
    except IdempotencyConflictError as exc:
        raise APIError(409, exc.code, "Idempotency key conflicts with a prior request.") from exc
    except GenerationProviderError as exc:
        raise APIError(502, f"PROVIDER_{exc.code.upper()}", "Media generation failed.") from exc
    except GenerateAndSealError as exc:
        if exc.code == "INVALID_IDEMPOTENCY_KEY":
            raise APIError(422, exc.code, "Idempotency key is invalid.") from exc
        raise APIError(503, exc.code, "Generate & Seal could not complete safely.") from exc
