"""
routers/events.py
-----------------
Event retrieval, listing, and cryptographic integrity verification APIs.

Sprint 1 — Raw Event Preservation & Traceable Ingestion.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import require_permission
from app.database import get_db
from app.models.user import User
from app.schemas.event import (
    EventDetailResponse,
    EventListResponse,
    EventSummaryResponse,
    EventVerificationResponse,
    PipelineStatsResponse,
)
from app.services.event_service import EventService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/events", tags=["Events & Integrity"])


@router.get(
    "",
    response_model=EventListResponse,
    summary="List Recently Ingested Events",
    description=(
        "Retrieve a paginated list of preserved raw security log events "
        "from PostgreSQL, ordered by ingestion timestamp (newest first). "
        "Returns compact summaries without massive raw payload overhead."
    ),
)
def list_events(
    limit: int = Query(default=50, ge=1, le=100, description="Maximum items per page"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    source_name: Optional[str] = Query(default=None, description="Filter by source name substring"),
    source_type: Optional[str] = Query(default=None, description="Filter by source type substring"),
    file_format: Optional[str] = Query(default=None, description="Filter by file format"),
    current_user: User = Depends(require_permission("EVIDENCE_READ")),
    db: Session = Depends(get_db),
) -> EventListResponse:
    """List paginated event summaries."""
    try:
        items, total = EventService.list_events(
            db,
            limit=limit,
            offset=offset,
            source_name=source_name,
            source_type=source_type,
            file_format=file_format,
        )
        return EventListResponse(
            items=[
                EventSummaryResponse(
                    event_id=item.event_id,
                    source_name=item.source_name,
                    source_type=item.source_type,
                    file_format=item.file_format,
                    raw_content_hash=item.raw_content_hash,
                    hash_prefix=item.raw_content_hash[:12] if item.raw_content_hash else "",
                    content_size=item.content_size,
                    processing_status=item.processing_status,
                    ingested_at=item.ingested_at,
                )
                for item in items
            ],
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        logger.error("Failed to list events: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve event list from database.",
        ) from exc

@router.get(
    "/pipeline-stats",
    response_model=PipelineStatsResponse,
    summary="Get Pipeline Dashboard Stats",
    description="Retrieve live pipeline statistics and recent events for the ULPF dashboard.",
)
def get_pipeline_stats(
    current_user: User = Depends(require_permission("EVIDENCE_READ")),
    db: Session = Depends(get_db),
) -> PipelineStatsResponse:
    try:
        stats = EventService.get_pipeline_stats(db)
        return PipelineStatsResponse(**stats)
    except Exception as exc:
        logger.error("Failed to retrieve pipeline stats: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve pipeline stats.",
        ) from exc


@router.get(
    "/{event_id}",
    response_model=EventDetailResponse,
    summary="Get Stored Event Details",
    description="Retrieve the complete stored event record including the preserved raw content.",
    responses={
        200: {"description": "Complete event record"},
        404: {"description": "Event not found"},
    },
)
def get_event(
    event_id: str,
    current_user: User = Depends(require_permission("EVIDENCE_READ")),
    db: Session = Depends(get_db),
) -> EventDetailResponse:
    """Retrieve full event details by event_id."""
    event = EventService.get_event_by_id(db, event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found.",
        )
    return EventDetailResponse(
        event_id=event.event_id,
        source_name=event.source_name,
        source_type=event.source_type,
        file_format=event.file_format,
        raw_content=event.raw_content,
        raw_content_hash=event.raw_content_hash,
        hash_prefix=event.raw_content_hash[:12] if event.raw_content_hash else "",
        content_size=event.content_size,
        processing_status=event.processing_status,
        ingested_at=event.ingested_at,
        metadata=event.metadata_ or {},
    )


@router.get(
    "/{event_id}/verify",
    response_model=EventVerificationResponse,
    summary="Verify Event Cryptographic Integrity",
    description=(
        "Recalculates the SHA-256 integrity fingerprint live over the stored raw content "
        "and compares it against the fingerprint recorded at ingestion.\n\n"
        "**Statuses**:\n"
        "- `VERIFIED`: Hash matches exactly. Data has remained untouched.\n"
        "- `MISMATCH`: Hash differs. Stored content has been modified or corrupted."
    ),
    responses={
        200: {"description": "Integrity verification result"},
        404: {"description": "Event not found"},
    },
)
@router.post(
    "/{event_id}/verify",
    response_model=EventVerificationResponse,
    summary="Verify Event Cryptographic Integrity (POST Alias)",
    include_in_schema=False,
)
def verify_event(
    event_id: str,
    current_user: User = Depends(require_permission("EVIDENCE_READ")),
    db: Session = Depends(get_db),
) -> EventVerificationResponse:
    """Perform live SHA-256 cryptographic verification."""
    result = EventService.verify_event_integrity(db, event_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found.",
        )
    return EventVerificationResponse(**result)

