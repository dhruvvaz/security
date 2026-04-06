"""
Authentication & authorization module.

Security decisions:
- Passwords are hashed with bcrypt (adaptive cost, salt built-in).
- JWTs use HS256 with a secret key. In production, use RS256 with key rotation.
- Token expiry is short (30 min) to limit the blast radius of a leaked token.
- The "sub" claim carries the username; roles are embedded in the token so
  the gateway doesn't need a DB lookup on every request (tradeoff: role
  changes require re-issuance).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.utils.logging import security_logger

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# In production, load from a secrets manager (e.g. AWS Secrets Manager, Vault).
SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "change-me-in-production-use-a-256-bit-random-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

# bcrypt is deliberately slow, making brute-force attacks expensive.
# "deprecated='auto'" means passlib will transparently re-hash on verify
# if a newer bcrypt version is available.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------------------------------------------------------
# Simulated user store (replace with a real DB in production)
# ---------------------------------------------------------------------------

# Passwords pre-hashed with bcrypt for the demo users.
# "admin123!" and "user1234" respectively.
USERS_DB: dict[str, dict[str, Any]] = {
    "admin": {
        "password_hash": pwd_context.hash("admin123!"),
        "role": "admin",
        "rate_limit": 20,  # admins get higher rate limits
    },
    "alice": {
        "password_hash": pwd_context.hash("user1234"),
        "role": "user",
        "rate_limit": 5,
    },
}

# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

bearer_scheme = HTTPBearer()


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    """Return user dict if credentials are valid, else None."""
    user = USERS_DB.get(username)
    if user is None or not verify_password(password, user["password_hash"]):
        return None
    return user


def create_access_token(subject: str, role: str, expires_delta: timedelta | None = None) -> str:
    """
    Create a signed JWT.

    Claims:
    - sub: username (subject)
    - role: authorization level
    - exp: expiration timestamp
    - iat: issued-at timestamp (useful for token revocation windows)
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        "sub": subject,
        "role": role,
        "exp": expire,
        "iat": now,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT. Raises HTTPException on any failure.

    Security note: python-jose validates exp automatically.
    We additionally check that required claims are present.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        security_logger.warning("jwt_validation_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if "sub" not in payload or "role" not in payload:
        security_logger.warning("jwt_missing_claims", token_claims=list(payload.keys()))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing required claims",
        )
    return payload


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict[str, Any]:
    """Dependency that extracts and validates the JWT from the Authorization header."""
    return decode_token(credentials.credentials)


def require_role(required_role: str):
    """
    Factory that returns a dependency enforcing a minimum role.

    Usage:
        @router.get("/admin", dependencies=[Depends(require_role("admin"))])
    """
    def role_checker(
        user: dict[str, Any] = Depends(get_current_user),
    ) -> dict[str, Any]:
        if user.get("role") != required_role:
            security_logger.warning(
                "authorization_denied",
                user=user.get("sub"),
                required_role=required_role,
                actual_role=user.get("role"),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' required",
            )
        return user
    return role_checker
