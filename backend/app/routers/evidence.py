"""
routers/evidence.py
-------------------
Evidence Vault retrieval and cryptographic integrity verification APIs.

Sprint 1 — Evidence Vault & Secure Log Ingestion.
"""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.evidence import (
    EvidenceEventResponse,
    EvidenceListResponse,
    EvidenceVerificationResponse,
)
from app.services.evidence import EvidenceVaultService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/evidence", tags=["Evidence Vault"])


@router.get(
    "",
    response_model=EvidenceListResponse,
    summary="List Preserved Evidence Events",
    description=(
        "Retrieve a paginated list of preserved raw security log events "
        "from the Evidence Vault, ordered by ingestion timestamp (newest first)."
    ),
)
def list_evidence_events(
    limit: int = Query(default=50, ge=1, le=100, description="Maximum items per page"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    source_name: Optional[str] = Query(default=None, description="Filter by source name substring"),
    source_type: Optional[str] = Query(default=None, description="Filter by source type substring"),
    db: Session = Depends(get_db),
) -> EvidenceListResponse:
    """List paginated evidence records."""
    try:
        items, total = EvidenceVaultService.list_events(
            db, limit=limit, offset=offset, source_name=source_name, source_type=source_type
        )
        return EvidenceListResponse(
            items=[
                EvidenceEventResponse(
                    event_id=item.event_id,
                    source_name=item.source_name,
                    source_type=item.source_type,
                    raw_event=item.raw_event,
                    raw_event_hash=item.raw_event_hash,
                    ingested_at=item.ingested_at,
                    metadata=item.metadata_ or {},
                    integrity_status=item.integrity_status,
                )
                for item in items
            ],
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        logger.error("Failed to list evidence events: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve evidence list from database.",
        ) from exc


@router.get(
    "/{event_id}",
    response_model=EvidenceEventResponse,
    summary="Get Specific Evidence Event",
    description="Retrieve the complete stored evidence record for a given UUIDv4 event ID.",
    responses={
        200: {"description": "Evidence event record"},
        404: {"description": "Evidence event not found"},
    },
)
def get_evidence_event(
    event_id: UUID,
    db: Session = Depends(get_db),
) -> EvidenceEventResponse:
    """Retrieve full evidence details by event ID."""
    evidence = EvidenceVaultService.get_event_by_id(db, event_id)
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence event '{event_id}' not found in Evidence Vault.",
        )
    return EvidenceEventResponse(
        event_id=evidence.event_id,
        source_name=evidence.source_name,
        source_type=evidence.source_type,
        raw_event=evidence.raw_event,
        raw_event_hash=evidence.raw_event_hash,
        ingested_at=evidence.ingested_at,
        metadata=evidence.metadata_ or {},
        integrity_status=evidence.integrity_status,
    )


@router.post(
    "/{event_id}/verify",
    response_model=EvidenceVerificationResponse,
    summary="Cryptographically Verify Evidence Integrity",
    description=(
        "Recalculates the SHA-256 hash live over the stored raw_event string and compares "
        "it to the stored cryptographic fingerprint recorded at ingestion.\n\n"
        "**Outcomes**:\n"
        "- `integrity_valid = true` (`INTEGRITY_VERIFIED`): Stored hash matches live recalculated hash.\n"
        "- `integrity_valid = false` (`TAMPER_DETECTED`): Stored hash differs from live recalculated hash."
    ),
    responses={
        200: {"description": "Cryptographic verification result"},
        404: {"description": "Evidence event not found"},
    },
)
def verify_evidence(
    event_id: UUID,
    db: Session = Depends(get_db),
) -> EvidenceVerificationResponse:
    """Verify cryptographic integrity of preserved evidence."""
    result = EvidenceVaultService.verify_integrity(db, event_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence event '{event_id}' not found in Evidence Vault.",
        )
    return EvidenceVerificationResponse(**result)
