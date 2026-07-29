"""Public hash-based certificate verification."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from api.firemark.api.dependencies import get_certificate_service
from api.firemark.api.errors import ErrorResponse
from api.firemark.control_plane.models import VerificationRequest, VerificationResult
from api.firemark.control_plane.service import CertificateService

router = APIRouter(prefix="/v1", tags=["verification"])


@router.post(
    "/verify",
    response_model=VerificationResult,
    responses={422: {"model": ErrorResponse}},
    operation_id="verify_certificate",
)
def verify_certificate(
    request: VerificationRequest,
    service: Annotated[CertificateService, Depends(get_certificate_service)],
) -> VerificationResult:
    """Verify signed evidence and an optional final-byte digest, then append an event."""
    return service.verify(request)
