"""
routers/export.py
-----------------
API for triggering Data Lake exports of validated normalized events.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any

from app.core.auth import require_permission
from app.database import get_db
from app.models.user import User
from app.services.parquet_export_service import ParquetExportService
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/export", tags=["Data Lake Export"])

@router.post(
    "/parquet",
    summary="Export to Parquet (Data Lake)",
    description="Exports all successfully normalized and validated events into a partitioned Parquet dataset.",
    response_model=Dict[str, Any],
)
def export_parquet(
    current_user: User = Depends(require_permission("EVENT_NORMALIZE")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        return ParquetExportService.export_validated_events(db)
    except Exception as exc:
        logger.error("Failed to export events to Parquet: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export events to Parquet.",
        ) from exc
