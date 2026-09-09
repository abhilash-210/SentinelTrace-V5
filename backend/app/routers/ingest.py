"""
routers/ingest.py
-----------------
Raw security log and event ingestion API endpoint.

Sprint 1 — Raw Event Preservation & Traceable Ingestion.
Preserves original raw events into PostgreSQL before any normalization or parsing.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import require_permission
from app.database import get_db
from app.models.user import User
from app.schemas.event import EventIngestRequest, EventIngestResponse
from app.services.event_service import EventService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["Ingestion"])


@router.post(
    "",
    response_model=EventIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Preserve Raw Security Event",
    description=(
        "**Core Principle**: Raw security events are preserved into PostgreSQL with an immutable "
        "SHA-256 integrity fingerprint and unique event ID before any parsing or transformation occurs.\n\n"
        "**Guarantees**:\n"
        "- Exact UTF-8 raw log text preservation without mutation\n"
        "- Deterministic SHA-256 cryptographic digest calculation\n"
        "- Traceable unique event identifier generation\n"
        "- UTC ingestion timestamping"
    ),
    responses={
        201: {"description": "Raw event successfully preserved in database"},
        400: {"description": "Invalid input or empty raw content"},
        401: {"description": "Unauthorized - Missing or invalid token"},
        403: {"description": "Forbidden - Requires EVIDENCE_INGEST permission"},
        422: {"description": "Validation error"},
        500: {"description": "Database or server error"},
    },
)
def ingest_event(
    payload: EventIngestRequest,
    current_user: User = Depends(require_permission("EVIDENCE_INGEST")),
    db: Session = Depends(get_db),
) -> EventIngestResponse:
    """Ingest and preserve a raw security event."""
    try:
        raw = payload.raw_content
        if not raw or not raw.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="raw_content cannot be empty or only whitespace.",
            )

        persisted = EventService.ingest_event(db, payload)

        return EventIngestResponse(
            event_id=persisted.event_id,
            source_name=persisted.source_name,
            source_type=persisted.source_type,
            file_format=persisted.file_format,
            raw_content_hash=persisted.raw_content_hash,
            hash_prefix=persisted.raw_content_hash[:12],
            content_size=persisted.content_size,
            processing_status=persisted.processing_status,
            ingested_at=persisted.ingested_at,
            message="Raw event preserved successfully with SHA-256 integrity fingerprint",
        )
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        ) from val_err
    except Exception as exc:
        logger.error("Failed to ingest event: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist raw event into database.",
        ) from exc
