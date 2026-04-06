"""
Pydantic models for request/response validation.

Security note: Pydantic v2 enforces strict type coercion and length limits,
which prevents type-confusion attacks and oversized payloads from reaching
business logic. Every external-facing field has explicit constraints.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Auth models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    """Validates login credentials before they reach the auth layer."""

    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        description="Alphanumeric username",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User password (min 8 chars)",
    )

    @field_validator("username")
    @classmethod
    def username_must_be_safe(cls, v: str) -> str:
        """Reject characters that could be used in injection attacks."""
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username must contain only alphanumeric characters and underscores")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int = Field(description="Token lifetime in seconds")


class TokenRefreshRequest(BaseModel):
    access_token: str = Field(..., min_length=1, max_length=2048)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class DataItem(BaseModel):
    """Generic data payload with strict validation."""

    name: str = Field(..., min_length=1, max_length=256)
    value: str = Field(..., min_length=1, max_length=4096)

    @field_validator("name", "value")
    @classmethod
    def reject_script_tags(cls, v: str) -> str:
        """
        Basic XSS prevention at the model layer.
        Defense-in-depth: even if output encoding handles display,
        we reject obviously malicious input early.
        """
        if re.search(r"<\s*script", v, re.IGNORECASE):
            raise ValueError("Input contains potentially malicious content")
        return v


# ---------------------------------------------------------------------------
# Simulation models
# ---------------------------------------------------------------------------

class AttackSimulationRequest(BaseModel):
    """Request model for the /simulate-attack endpoint."""

    attack_type: Literal["invalid_token", "excessive_requests", "malformed_input"] = Field(
        ...,
        description="Type of attack to simulate",
    )


# ---------------------------------------------------------------------------
# Common response models
# ---------------------------------------------------------------------------

class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    detail: str
