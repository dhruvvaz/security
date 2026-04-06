"""
Security middleware and hardening utilities.

This module applies defense-in-depth headers and request-level protections
that sit in front of all route handlers.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, Response
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.auth import ALGORITHM, SECRET_KEY
from app.utils.logging import security_logger


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects standard security headers into every response.

    These headers instruct browsers and proxies to enforce security policies.
    Even though this is an API (not serving HTML), defense-in-depth means we
    set them anyway -- an API response could be rendered by a misconfigured
    client.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Prevent MIME-type sniffing (reduces XSS risk)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Disable embedding in iframes (clickjacking protection)
        response.headers["X-Frame-Options"] = "DENY"

        # Strict transport security -- enforce HTTPS for 1 year
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Minimal referrer information to prevent URL leakage
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Restrict browser features the API doesn't need
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        # Content Security Policy -- API should only return JSON
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

        # Suppress server version disclosure
        response.headers["Server"] = "secure-api-gateway"

        return response


# ---------------------------------------------------------------------------
# JWT extraction middleware
# ---------------------------------------------------------------------------


class JWTExtractionMiddleware(BaseHTTPMiddleware):
    """
    Optionally extracts JWT claims and attaches them to request.state.user.

    This runs before rate limiting so that authenticated users can receive
    role-based rate limits. It does NOT enforce authentication -- that is
    handled by the per-route `get_current_user` dependency.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.user = None
        auth_header = request.headers.get("Authorization", "")

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                request.state.user = payload
            except JWTError:
                # Invalid token -- don't block the request here; the auth
                # dependency will reject it if the route requires auth.
                pass

        return await call_next(request)


# ---------------------------------------------------------------------------
# Request logging middleware
# ---------------------------------------------------------------------------


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every request for audit trail purposes."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        security_logger.info(
            "request_completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            client=request.client.host if request.client else "unknown",
        )
        return response


# ---------------------------------------------------------------------------
# Registration helper
# ---------------------------------------------------------------------------


def register_security_middleware(app: FastAPI) -> None:
    """Register all security middleware in the correct order.

    Middleware executes in reverse registration order (last registered = outermost).
    We want: Logging -> Security Headers -> JWT Extraction -> route handler.
    So we register in this order (innermost first):
    """
    app.add_middleware(JWTExtractionMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
