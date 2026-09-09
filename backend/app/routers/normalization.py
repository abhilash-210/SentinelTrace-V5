"""
routers/normalization.py
------------------------
OCSF-Aligned Canonical Normalization API endpoints.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
Provides:
- On-demand event normalization
- Paginated normalized event inspection
- End-to-end evidence traceability
- Active Source Profile listings
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import require_permission
from app.database import get_db
from app.models.user import User
from app.schemas.normalization import (
    NormalizationTraceabilityResponse,
    NormalizedEventListResponse,
    NormalizedEventResponse,
)
from app.schemas.source_profile import (
    SourceProfileListResponse,
    SourceProfileResponse,
)
from app.services.normalization_service import NormalizationService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["OCSF Normalization"])


@router.post(
    "/api/v1/events/{event_id}/normalize",
    response_model=NormalizedEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Normalize Preserved Raw Security Event",
    description=(
        "**Core Pipeline**: Transforms a preserved raw security event into an OCSF-aligned "
        "canonical event using deterministic source-profile matching and format-specific parsing.\n\n"
        "**Guarantees**:\n"
        "- Strict reference back to `original_event_id` in Evidence Vault\n"
        "- Preserved raw content remains 100% immutable\n"
        "- Idempotent execution (returns existing record on repeat calls)\n"
        "- Deterministic confidence scoring without ML fabrication"
    ),
    responses={
        200: {"description": "Normalized canonical event record"},
        401: {"description": "Unauthorized - Missing or invalid token"},
        403: {"description": "Forbidden - Requires EVENT_NORMALIZE permission"},
        404: {"description": "Raw event not found in Evidence Vault"},
        500: {"description": "Internal normalization failure"},
    },
)
def normalize_event(
    event_id: str,
    current_user: User = Depends(require_permission("EVENT_NORMALIZE")),
    db: Session = Depends(get_db),
) -> NormalizedEventResponse:
    """Normalize a preserved raw security event."""
    try:
        normalized = NormalizationService.normalize_event(db, event_id)
        if not normalized:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Preserved event '{event_id}' not found in Evidence Vault.",
            )
        return NormalizedEventResponse(**normalized.to_dict())
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to normalize event %s: %s", event_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Normalization engine failed for event '{event_id}'.",
        ) from exc


@router.get(
    "/api/v1/normalized-events",
    response_model=NormalizedEventListResponse,
    summary="List Normalized Security Events",
    description="Retrieve paginated canonical normalized events with class and status filters.",
)
def list_normalized_events(
    limit: int = Query(default=50, ge=1, le=100, description="Items per page"),
    offset: int = Query(default=0, ge=0, description="Items to skip"),
    class_name: Optional[str] = Query(default=None, description="Filter by OCSF class (e.g. 'Network Activity')"),
    normalization_status: Optional[str] = Query(default=None, description="Filter by status (NORMALIZED, PARTIAL, FAILED)"),
    original_event_id: Optional[str] = Query(default=None, description="Filter by original raw event ID"),
    current_user: User = Depends(require_permission("NORMALIZED_EVENT_READ")),
    db: Session = Depends(get_db),
) -> NormalizedEventListResponse:
    """List paginated normalized events."""
    items, total = NormalizationService.list_normalized_events(
        db,
        limit=limit,
        offset=offset,
        class_name=class_name,
        normalization_status=normalization_status,
        original_event_id=original_event_id,
    )
    return NormalizedEventListResponse(
        items=[NormalizedEventResponse(**item.to_dict()) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/api/v1/normalized-events/{normalized_event_id}",
    response_model=NormalizedEventResponse,
    summary="Get Specific Normalized Event",
    description="Retrieve full details of a normalized canonical security event.",
    responses={
        200: {"description": "Normalized event details"},
        404: {"description": "Normalized event not found"},
    },
)
def get_normalized_event(
    normalized_event_id: str,
    current_user: User = Depends(require_permission("NORMALIZED_EVENT_READ")),
    db: Session = Depends(get_db),
) -> NormalizedEventResponse:
    """Retrieve normalized event by normalized_event_id."""
    normalized = NormalizationService.get_normalized_by_id(db, normalized_event_id)
    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Normalized event '{normalized_event_id}' not found.",
        )
    return NormalizedEventResponse(**normalized.to_dict())


@router.get(
    "/api/v1/events/{event_id}/normalization",
    response_model=NormalizationTraceabilityResponse,
    summary="Get Evidence Normalization Traceability",
    description="Retrieve the bidirectional traceability mapping linking raw evidence to its normalized canonical event.",
    responses={
        200: {"description": "Traceability link between raw and normalized events"},
        404: {"description": "Raw event not found or not yet normalized"},
    },
)
def get_normalization_traceability(
    event_id: str,
    current_user: User = Depends(require_permission("AUDIT_READ")),
    db: Session = Depends(get_db),
) -> NormalizationTraceabilityResponse:
    """Retrieve traceability record for a given raw event ID."""
    traceability = NormalizationService.get_traceability(db, event_id)
    if not traceability:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No normalization traceability found for event '{event_id}'. Event may not be normalized yet.",
        )
    return NormalizationTraceabilityResponse(**traceability)


@router.get(
    "/api/v1/source-profiles",
    response_model=SourceProfileListResponse,
    summary="List Source Profiles",
    description="Retrieve the active Source Profiles used for structural log parsing.",
)
def list_source_profiles(
    current_user: User = Depends(require_permission("NORMALIZED_EVENT_READ")),
    db: Session = Depends(get_db),
) -> SourceProfileListResponse:
    """Retrieve all available Source Profiles."""
    NormalizationService.ensure_default_source_profiles(db)
    profiles = NormalizationService.list_source_profiles(db)
    return SourceProfileListResponse(
        items=[SourceProfileResponse(**p.to_dict()) for p in profiles],
        total=len(profiles),
    )

