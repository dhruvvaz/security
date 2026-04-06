"""
Authentication routes: login, token refresh, and current-user info.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    authenticate_user,
    create_access_token,
    decode_token,
    get_current_user,
)
from app.models import LoginRequest, MessageResponse, TokenRefreshRequest, TokenResponse
from app.rate_limiter import rate_limit_dependency
from app.utils.logging import security_logger

router = APIRouter(tags=["Authentication"])


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive a JWT",
    responses={401: {"description": "Invalid credentials"}},
)
async def login(
    body: LoginRequest,
    request: Request,
    _rate: None = Depends(rate_limit_dependency),
) -> TokenResponse:
    """
    Accepts username + password, returns a signed JWT on success.

    Security notes:
    - Rate-limited to prevent credential stuffing.
    - Generic error message prevents username enumeration.
    - Failed attempts are logged for SIEM alerting.
    """
    user = authenticate_user(body.username, body.password)
    if user is None:
        client_ip = request.client.host if request.client else "unknown"
        security_logger.warning(
            "login_failed",
            username=body.username,
            client_ip=client_ip,
        )
        # Generic message -- never reveal whether the username exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(
        subject=body.username,
        role=user["role"],
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    security_logger.info("login_success", username=body.username)
    return TokenResponse(
        access_token=token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh an existing (non-expired) JWT",
    dependencies=[Depends(rate_limit_dependency)],
)
async def refresh_token(body: TokenRefreshRequest) -> TokenResponse:
    """
    Issue a fresh token from a valid existing token.

    Security note: In production, implement a refresh-token flow with
    opaque refresh tokens stored server-side. This simplified version
    re-issues from the access token itself, which is acceptable for
    short-lived tokens in a demo context.
    """
    payload = decode_token(body.access_token)
    token = create_access_token(
        subject=payload["sub"],
        role=payload["role"],
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return TokenResponse(
        access_token=token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get(
    "/me",
    response_model=MessageResponse,
    summary="Get current user info",
    dependencies=[Depends(rate_limit_dependency)],
)
async def get_me(user: dict = Depends(get_current_user)) -> MessageResponse:
    """Return the authenticated user's identity and role."""
    return MessageResponse(message=f"Authenticated as {user['sub']} (role: {user['role']})")
