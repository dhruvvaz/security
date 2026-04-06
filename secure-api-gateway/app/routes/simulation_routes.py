"""
Attack simulation endpoint for demonstrating security controls.

This is an educational/interview endpoint that programmatically triggers
the gateway's defenses and returns structured results showing how each
attack is handled.
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, Request

from app.models import AttackSimulationRequest
from app.rate_limiter import rate_limit_dependency

router = APIRouter(tags=["Attack Simulation"])


@router.post(
    "/simulate-attack",
    summary="Simulate common attacks against the gateway",
    dependencies=[Depends(rate_limit_dependency)],
)
async def simulate_attack(
    body: AttackSimulationRequest,
    request: Request,
) -> dict:
    """
    Demonstrates how the gateway handles:
    1. Invalid JWT tokens
    2. Excessive requests (rate limiting)
    3. Malformed/malicious input

    Each simulation makes internal requests and reports the gateway's response.
    This is safe to call -- it only targets this gateway instance.
    """
    # Build base URL from the incoming request
    base_url = str(request.base_url).rstrip("/")
    results: dict = {"attack_type": body.attack_type, "results": []}

    async with httpx.AsyncClient(base_url=base_url) as client:

        if body.attack_type == "invalid_token":
            results["description"] = "Attempting to access protected resources with invalid/expired tokens"
            test_cases = [
                ("No token", {}),
                ("Garbage token", {"Authorization": "Bearer not.a.real.token"}),
                ("Expired format", {"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6InVzZXIiLCJleHAiOjB9.invalid"}),
            ]
            for label, headers in test_cases:
                resp = await client.get("/data", headers=headers)
                results["results"].append({
                    "test": label,
                    "status_code": resp.status_code,
                    "blocked": resp.status_code in (401, 403),
                    "response": resp.json(),
                })

        elif body.attack_type == "excessive_requests":
            results["description"] = "Sending rapid requests to trigger rate limiting"
            for i in range(8):
                resp = await client.get("/data", headers={"Authorization": "Bearer fake"})
                results["results"].append({
                    "request_number": i + 1,
                    "status_code": resp.status_code,
                    "rate_limited": resp.status_code == 429,
                })

        elif body.attack_type == "malformed_input":
            results["description"] = "Sending malicious payloads to test input validation"
            payloads = [
                {"name": "<script>alert('xss')</script>", "value": "test"},
                {"name": "normal", "value": "'; DROP TABLE users; --"},
                {"name": "x" * 300, "value": "oversized name field"},
                {"name": "", "value": "empty name"},
            ]
            for payload in payloads:
                resp = await client.post(
                    "/data",
                    json=payload,
                    # Use a fake auth header -- we're testing input validation, not auth
                    headers={"Authorization": "Bearer fake"},
                )
                results["results"].append({
                    "payload": payload,
                    "status_code": resp.status_code,
                    "blocked": resp.status_code in (401, 403, 422),
                    "response": resp.json(),
                })

    return results
