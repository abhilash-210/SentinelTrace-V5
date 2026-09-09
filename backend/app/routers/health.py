"""
routers/health.py
-----------------
Health and root endpoint router for SENTINEL-TRACE.

Endpoints:
  GET /        → API information
  GET /health  → Service health check (including DB connectivity)
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.config import settings
from app.database import verify_database_connection

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Health"])


# ── Response Schemas ───────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    database: str
    timestamp: str


class APIInfoResponse(BaseModel):
    service: str
    version: str
    description: str
    docs_url: str
    health_url: str
    sprint: str


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get(
    "/",
    response_model=APIInfoResponse,
    summary="API Information",
    description="Returns service metadata and available endpoint links.",
)
def root() -> APIInfoResponse:
    """Root endpoint — useful for quick service discovery."""
    return APIInfoResponse(
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "SENTINEL-TRACE: Verifiable Security Log Normalization "
            "& Semantic Trust Governance Platform"
        ),
        docs_url="/docs",
        health_url="/health",
        sprint="Sprint 0 — Project Foundation",
    )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service Health Check",
    description=(
        "Verifies that the API service is running and that the "
        "PostgreSQL database is reachable."
    ),
)
def health_check() -> HealthResponse:
    """
    Health check endpoint.

    Checks:
    1. API service is alive.
    2. PostgreSQL connection is reachable (SELECT 1).

    Returns HTTP 503 if the database is unreachable.
    """
    db_status = "unreachable"
    try:
        verify_database_connection()
        db_status = "connected"
    except Exception as exc:
        logger.warning("Database health check failed: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "service": settings.APP_NAME,
                "version": settings.APP_VERSION,
                "database": "unreachable",
                "error": str(exc),
            },
        )

    return HealthResponse(
        status="healthy",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        database=db_status,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
