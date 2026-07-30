"""Constant-time bearer API-key authentication dependencies."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr

from api.firemark.api.errors import APIError

_bearer = HTTPBearer(auto_error=False)


def _require_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
    configured: SecretStr | None,
) -> None:
    del request
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise APIError(401, "AUTHENTICATION_REQUIRED", "Bearer authentication is required.")
    if configured is None:
        raise APIError(503, "AUTHENTICATION_UNAVAILABLE", "Authentication is not configured.")
    if not hmac.compare_digest(credentials.credentials, configured.get_secret_value()):
        raise APIError(401, "INVALID_CREDENTIALS", "Bearer authentication failed.")


def require_admin_api_key(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    _require_key(request, credentials, request.app.state.settings.admin_api_key)


def require_delivery_api_key(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    _require_key(request, credentials, request.app.state.settings.delivery_api_key)
