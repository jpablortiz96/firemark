"""Verification-gated private asset delivery."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from api.firemark.api.dependencies import get_certificate_service
from api.firemark.api.errors import APIError, ErrorResponse
from api.firemark.control_plane.models import (
    DeliveryAuthorization,
    DeliveryHTTPResponse,
    DeliveryResult,
)
from api.firemark.control_plane.repository import DeliveryStorageError
from api.firemark.control_plane.service import AuthorizedDelivery, CertificateService

router = APIRouter(prefix="/v1/delivery", tags=["delivery"])


@router.post(
    "/{cert_id}",
    response_model=DeliveryHTTPResponse,
    responses={
        403: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
    operation_id="authorize_delivery",
)
def authorize_delivery(
    cert_id: str,
    authorization: DeliveryAuthorization,
    service: Annotated[CertificateService, Depends(get_certificate_service)],
) -> DeliveryHTTPResponse:
    """Issue an exact short-lived URL only after a successful Verify Gate decision."""
    try:
        decision = service.authorize_delivery(cert_id, authorization)
    except DeliveryStorageError as exc:
        raise APIError(
            503, "DELIVERY_STORAGE_UNAVAILABLE", "Private delivery is temporarily unavailable."
        ) from exc
    if isinstance(decision, DeliveryResult):
        if decision.status == "storage_failure":
            raise APIError(
                503,
                "DELIVERY_STORAGE_UNAVAILABLE",
                "Private delivery is temporarily unavailable.",
            )
        raise APIError(403, decision.safe_reason_code, "Certificate verification blocked delivery.")
    if not isinstance(decision, AuthorizedDelivery) or decision.result.expires_at is None:
        raise APIError(503, "DELIVERY_STORAGE_UNAVAILABLE", "Private delivery is unavailable.")
    return DeliveryHTTPResponse.model_validate(
        {
            "cert_id": cert_id,
            "status": "issued",
            "download_url": decision.download.reveal_url(),
            "expires_at": decision.result.expires_at,
            "expires_in": decision.download.expires_in,
        }
    )
