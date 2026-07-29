"""Public Birth Certificate retrieval."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from api.firemark.api.dependencies import get_certificate_service
from api.firemark.api.errors import APIError, ErrorResponse
from api.firemark.control_plane.models import PublicCertificate
from api.firemark.control_plane.service import CertificateService

router = APIRouter(prefix="/v1/certificates", tags=["certificates"])


@router.get(
    "/{cert_id}",
    response_model=PublicCertificate,
    responses={404: {"model": ErrorResponse}, 410: {"model": ErrorResponse}},
    operation_id="get_public_certificate",
)
def get_certificate(
    cert_id: str,
    service: Annotated[CertificateService, Depends(get_certificate_service)],
) -> PublicCertificate:
    """Return only the redacted public certificate projection."""
    certificate = service.get_public_certificate(cert_id)
    if certificate is None:
        raise APIError(404, "CERTIFICATE_NOT_FOUND", "Certificate not found.")
    if certificate.certificate_status == "revoked":
        raise APIError(410, "CERTIFICATE_REVOKED", "Certificate has been revoked.")
    return certificate
