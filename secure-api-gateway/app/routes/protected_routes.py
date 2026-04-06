"""
Protected routes demonstrating role-based access control (RBAC).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.auth import get_current_user, require_role
from app.models import DataItem, MessageResponse
from app.rate_limiter import rate_limit_dependency

router = APIRouter(tags=["Protected Resources"])


@router.get(
    "/data",
    response_model=MessageResponse,
    summary="Access data (any authenticated user)",
    dependencies=[Depends(rate_limit_dependency)],
)
async def get_data(user: dict = Depends(get_current_user)) -> MessageResponse:
    """
    Accessible by any authenticated user regardless of role.
    Demonstrates the base authentication requirement.
    """
    return MessageResponse(
        message=f"Here is your data, {user['sub']}. Role: {user['role']}.",
    )


@router.post(
    "/data",
    response_model=MessageResponse,
    summary="Submit data (any authenticated user)",
    dependencies=[Depends(rate_limit_dependency)],
)
async def post_data(
    item: DataItem,
    user: dict = Depends(get_current_user),
) -> MessageResponse:
    """
    Accepts validated data from any authenticated user.
    Pydantic's DataItem model rejects malicious input before it reaches here.
    """
    return MessageResponse(
        message=f"Data received: name={item.name}, value={item.value}",
    )


@router.get(
    "/admin",
    response_model=MessageResponse,
    summary="Admin-only endpoint",
    dependencies=[Depends(rate_limit_dependency), Depends(require_role("admin"))],
)
async def admin_panel() -> MessageResponse:
    """
    Restricted to users with the 'admin' role.

    Security note: The require_role dependency runs BEFORE the route handler.
    If the role check fails, the handler never executes -- preventing any
    accidental data leakage from partially executed logic.
    """
    return MessageResponse(message="Welcome to the admin panel.")
