"""
routers/quarantine.py
---------------------
Quarantine (DLQ) API endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.auth import require_permission
from app.database import get_db
from app.models.user import User
from app.services.quarantine_service import QuarantineService
from pydantic import BaseModel
from datetime import datetime

router = APIRouter(prefix="/api/v1/quarantine", tags=["Quarantine (DLQ)"])

class QuarantinedEventResponse(BaseModel):
    id: int
    quarantine_id: str
    source_name: str
    source_type: str
    raw_content: str
    failure_reason: str
    status: str
    quarantined_at: Optional[datetime]
    original_event_id: Optional[str]

class QuarantineListResponse(BaseModel):
    items: List[QuarantinedEventResponse]
    total: int
    limit: int
    offset: int

class ReplayRequest(BaseModel):
    pass # No new_raw_content allowed

class ReplayOperationResponse(BaseModel):
    id: int
    replay_id: str
    quarantine_id: str
    original_event_id: str
    replayed_at: Optional[datetime]
    previous_status: str
    result: str
    resulting_normalized_event_id: Optional[str]
    failure_reason: Optional[str]

@router.get("", response_model=QuarantineListResponse)
def list_quarantine(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status_filter: Optional[str] = Query(default="QUARANTINED", alias="status"),
    current_user: User = Depends(require_permission("EVIDENCE_READ")),
    db: Session = Depends(get_db),
):
    items, total = QuarantineService.list_quarantined_events(db, limit, offset, status_filter)
    return {
        "items": [item.to_dict() for item in items],
        "total": total,
        "limit": limit,
        "offset": offset
    }

@router.post("/{quarantine_id}/replay", response_model=ReplayOperationResponse)
def replay_quarantined_event(
    quarantine_id: str,
    current_user: User = Depends(require_permission("EVIDENCE_INGEST")),
    db: Session = Depends(get_db),
):
    try:
        result = QuarantineService.replay_event(db, quarantine_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{quarantine_id}/history", response_model=List[ReplayOperationResponse])
def get_replay_history(
    quarantine_id: str,
    current_user: User = Depends(require_permission("EVIDENCE_READ")),
    db: Session = Depends(get_db),
):
    return QuarantineService.list_replay_operations(db, quarantine_id)
