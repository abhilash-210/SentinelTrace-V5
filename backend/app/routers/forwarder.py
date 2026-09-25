"""
routers/forwarder.py
--------------------
SIEM Forwarder API endpoints.

Sprint 7 — Normalized Output / SIEM Forwarder.
Exposes the local SIEM-compatible output stream for inspection and demonstration.
"""

import logging
import os
import json
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.auth import require_permission
from app.models.user import User
from app.services.log_forwarder_service import SIEM_STREAM_FILE

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/forwarder", tags=["SIEM Forwarder"])

class SIEMStreamResponse(BaseModel):
    events: List[dict]
    total_returned: int

@router.get(
    "/stream",
    response_model=SIEMStreamResponse,
    summary="Read SIEM Output Stream",
    description="Retrieve the latest normalized canonical events forwarded to the local SIEM sink.",
)
def read_siem_stream(
    lines: int = 100,
    current_user: User = Depends(require_permission("NORMALIZED_EVENT_READ")),
) -> SIEMStreamResponse:
    """Read the last N lines from the SIEM stream log file."""
    if not os.path.exists(SIEM_STREAM_FILE):
        return SIEMStreamResponse(events=[], total_returned=0)
        
    try:
        events = []
        with open(SIEM_STREAM_FILE, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
            for line in all_lines[-lines:]:
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.warning("Unparseable line in SIEM stream: %s", line)
        
        return SIEMStreamResponse(
            events=events,
            total_returned=len(events)
        )
    except Exception as exc:
        logger.error("Failed to read SIEM stream: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to read SIEM stream.")

@router.delete(
    "/stream",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Clear SIEM Output Stream",
    description="Truncate the local SIEM sink file. Useful for resetting demonstrations.",
)
def clear_siem_stream(
    current_user: User = Depends(require_permission("USER_MANAGE")),
):
    """Clear the SIEM stream file."""
    try:
        if os.path.exists(SIEM_STREAM_FILE):
            # Open in write mode to truncate
            with open(SIEM_STREAM_FILE, "w", encoding="utf-8") as f:
                f.write("")
    except Exception as exc:
        logger.error("Failed to clear SIEM stream: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to clear SIEM stream.")
