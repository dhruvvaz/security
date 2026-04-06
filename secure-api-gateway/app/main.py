"""
Secure API Gateway -- Application entry point.

This FastAPI application demonstrates production security patterns:
- JWT authentication with bcrypt password hashing
- Role-based access control (RBAC)
- Sliding-window rate limiting with pluggable backends
- Defense-in-depth security headers
- Structured JSON logging for security events
- Input validation and sanitization via Pydantic

Run with:
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import auth_routes, protected_routes, simulation_routes
from app.security import register_security_middleware

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Secure API Gateway",
    description=(
        "A production-quality API gateway demonstrating authentication, "
        "authorization, rate limiting, and security best practices."
    ),
    version="1.0.0",
    docs_url="/docs",      # Swagger UI
    redoc_url="/redoc",     # ReDoc
    openapi_url="/openapi.json",
)

# ---------------------------------------------------------------------------
# CORS -- restrictive by default
# ---------------------------------------------------------------------------
# In production, replace "*" with the specific origins of your frontend.
# We list it explicitly here so the security decision is visible.

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict to known frontend origins
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# ---------------------------------------------------------------------------
# Security middleware (headers, JWT extraction, request logging)
# ---------------------------------------------------------------------------

register_security_middleware(app)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

app.include_router(auth_routes.router)
app.include_router(protected_routes.router)
app.include_router(simulation_routes.router)


# ---------------------------------------------------------------------------
# Health check (unauthenticated -- used by load balancers / k8s probes)
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health_check() -> dict:
    return {"status": "healthy", "service": "secure-api-gateway"}
