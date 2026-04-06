"""
Rate limiting middleware with pluggable backends.

Design:
- Strategy pattern: RateLimitBackend is the interface; InMemoryBackend is the
  default. A RedisBackend can be swapped in without changing the middleware.
- Sliding window algorithm: we store timestamps of recent requests and count
  how many fall within the current window.
- Per-IP by default; per-user when a valid JWT is present.
- Role-based limits: admins get a higher ceiling than regular users.

Tradeoff: in-memory storage is not shared across workers. For multi-process
deployments, use Redis or a similar shared store.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException, Request, status

from app.utils.logging import security_logger

# ---------------------------------------------------------------------------
# Backend interface
# ---------------------------------------------------------------------------


class RateLimitBackend(ABC):
    """Abstract rate-limit storage backend."""

    @abstractmethod
    def is_rate_limited(self, key: str, max_requests: int, window_seconds: int) -> bool:
        """Return True if the key has exceeded its quota."""

    @abstractmethod
    def get_remaining(self, key: str, max_requests: int, window_seconds: int) -> int:
        """Return how many requests remain in the current window."""


# ---------------------------------------------------------------------------
# In-memory backend (default)
# ---------------------------------------------------------------------------


class InMemoryBackend(RateLimitBackend):
    """
    Thread-safe sliding-window rate limiter backed by a dict.

    Each key maps to a list of request timestamps. Old entries are pruned
    on every check to avoid unbounded memory growth.
    """

    def __init__(self) -> None:
        self._store: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def _prune(self, key: str, window_seconds: int) -> None:
        cutoff = time.monotonic() - window_seconds
        self._store[key] = [t for t in self._store[key] if t > cutoff]

    def is_rate_limited(self, key: str, max_requests: int, window_seconds: int) -> bool:
        with self._lock:
            self._prune(key, window_seconds)
            if len(self._store[key]) >= max_requests:
                return True
            self._store[key].append(time.monotonic())
            return False

    def get_remaining(self, key: str, max_requests: int, window_seconds: int) -> int:
        with self._lock:
            self._prune(key, window_seconds)
            return max(0, max_requests - len(self._store[key]))


# ---------------------------------------------------------------------------
# Singleton backend instance
# ---------------------------------------------------------------------------

_backend: RateLimitBackend = InMemoryBackend()


def set_backend(backend: RateLimitBackend) -> None:
    """Swap in a different backend (e.g. Redis) at startup."""
    global _backend
    _backend = backend


def get_backend() -> RateLimitBackend:
    return _backend


# ---------------------------------------------------------------------------
# Default limits
# ---------------------------------------------------------------------------

DEFAULT_MAX_REQUESTS = 5
DEFAULT_WINDOW_SECONDS = 10

# Role-based overrides
ROLE_LIMITS: dict[str, int] = {
    "admin": 20,
    "user": 5,
}


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


async def rate_limit_dependency(request: Request) -> None:
    """
    Dependency that enforces rate limiting.

    Identification priority:
    1. Authenticated user (from JWT in request.state)
    2. Client IP address

    This runs before the route handler. If the limit is exceeded,
    the request is rejected with HTTP 429 before any business logic executes.
    """
    # Determine identity and limit
    user = getattr(request.state, "user", None)
    if user:
        key = f"user:{user.get('sub', 'unknown')}"
        role = user.get("role", "user")
        max_requests = ROLE_LIMITS.get(role, DEFAULT_MAX_REQUESTS)
    else:
        # Fall back to IP-based limiting.
        # Security note: X-Forwarded-For can be spoofed; in production,
        # trust only the value set by your reverse proxy.
        key = f"ip:{request.client.host if request.client else 'unknown'}"
        max_requests = DEFAULT_MAX_REQUESTS

    if _backend.is_rate_limited(key, max_requests, DEFAULT_WINDOW_SECONDS):
        remaining = _backend.get_remaining(key, max_requests, DEFAULT_WINDOW_SECONDS)
        security_logger.warning(
            "rate_limit_exceeded",
            key=key,
            max_requests=max_requests,
            window_seconds=DEFAULT_WINDOW_SECONDS,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
            headers={
                "Retry-After": str(DEFAULT_WINDOW_SECONDS),
                "X-RateLimit-Limit": str(max_requests),
                "X-RateLimit-Remaining": str(remaining),
            },
        )
