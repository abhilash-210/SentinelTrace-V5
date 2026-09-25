"""
services/quarantine_service.py
------------------------------
Service for managing Quarantined Events (DLQ).
Handles routing invalid logs into quarantine, retrieving them, and replaying them.
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.quarantined_event import QuarantinedEvent
from app.models.event import IngestedEvent
from app.services.event_service import EventService

logger = logging.getLogger(__name__)


class QuarantineService:
    """Service for managing the Quarantine Dead Letter Queue."""

    @staticmethod
    def quarantine_event(
        db: Session,
        source_name: str,
        source_type: str,
        raw_content: str,
        failure_reason: str,
        metadata: dict,
        original_event_id: Optional[str] = None,
    ) -> QuarantinedEvent:
        """Quarantine a raw event that failed parsing or validation."""
        if original_event_id:
            existing = db.execute(
                select(QuarantinedEvent).where(QuarantinedEvent.original_event_id == original_event_id)
            ).scalar_one_or_none()
            if existing:
                existing.failure_reason = failure_reason
                existing.status = "QUARANTINED"
                existing.quarantined_at = datetime.now(timezone.utc)
                db.commit()
                db.refresh(existing)
                logger.warning(f"Re-quarantined event {existing.quarantine_id}: {failure_reason}")
                return existing

        q_event = QuarantinedEvent(
            source_name=source_name,
            source_type=source_type,
            original_event_id=original_event_id,
            raw_content=raw_content,
            failure_reason=failure_reason,
            metadata_=metadata,
            status="QUARANTINED",
            quarantined_at=datetime.now(timezone.utc),
        )
        db.add(q_event)
        db.commit()
        db.refresh(q_event)
        logger.warning(f"Quarantined event {q_event.quarantine_id} from {source_name}: {failure_reason}")
        return q_event

    @staticmethod
    def get_quarantined_event(db: Session, quarantine_id: str) -> Optional[QuarantinedEvent]:
        """Fetch a specific quarantined event."""
        stmt = select(QuarantinedEvent).where(QuarantinedEvent.quarantine_id == quarantine_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def list_quarantined_events(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = "QUARANTINED",
    ) -> Tuple[List[QuarantinedEvent], int]:
        """List paginated quarantined events."""
        base_stmt = select(QuarantinedEvent)
        count_stmt = select(func.count()).select_from(QuarantinedEvent)

        if status:
            base_stmt = base_stmt.where(QuarantinedEvent.status == status.upper())
            count_stmt = count_stmt.where(QuarantinedEvent.status == status.upper())

        total = db.execute(count_stmt).scalar_one()
        query = base_stmt.order_by(QuarantinedEvent.quarantined_at.desc()).limit(limit).offset(offset)
        items = list(db.execute(query).scalars().all())

        return items, total

    @staticmethod
    def replay_event(db: Session, quarantine_id: str) -> Optional[Dict[str, Any]]:
        """
        Replay a quarantined event into the main ingestion pipeline without altering raw payload.
        """
        q_event = QuarantineService.get_quarantined_event(db, quarantine_id)
        if not q_event or q_event.status != "QUARANTINED":
            raise ValueError("Event is not in a replayable state")

        if not q_event.original_event_id:
            raise ValueError("Quarantined event missing original evidence link")

        previous_status = q_event.status
        from app.services.normalization_service import NormalizationService
        from app.models.replay_operation import ReplayOperation
        from app.services.validation_service import EventValidationException

        try:
            norm_event = NormalizationService.normalize_event(db, q_event.original_event_id, is_replay=True)
            error_reason = None
        except EventValidationException as e:
            norm_event = None
            error_reason = f"Validation failed during replay: {e.errors}"
        except Exception as e:
            norm_event = None
            error_reason = str(e)
            
        is_success = False
        if norm_event and norm_event.normalization_status in ("NORMALIZED", "PARTIAL"):
            is_success = True

        if is_success:
            q_event.status = "REPLAYED"
            result = "SUCCESS"
            fail_reason = None
            norm_id = norm_event.normalized_event_id
        else:
            q_event.status = "QUARANTINED"
            result = "FAILED"
            if norm_event and norm_event.normalization_status == "INVALID":
                fail_reason = "Validation failed during replay"
            elif norm_event and norm_event.normalization_status == "FAILED":
                fail_reason = "Parsing failed during replay"
            else:
                fail_reason = error_reason or "Unknown replay failure"
            norm_id = None
            
            # The NormalizationService already updated the QuarantinedEvent failure reason
            # because quarantine_event is idempotent. We just need to record the operation.

        op = ReplayOperation(
            quarantine_id=q_event.quarantine_id,
            original_event_id=q_event.original_event_id,
            previous_status=previous_status,
            result=result,
            resulting_normalized_event_id=norm_id,
            failure_reason=fail_reason
        )
        db.add(op)
        db.commit()
        db.refresh(op)
        db.refresh(q_event)
        
        return op.to_dict()

    @staticmethod
    def list_replay_operations(db: Session, quarantine_id: str) -> List[Dict[str, Any]]:
        """Fetch all replay operations for a given quarantined event."""
        from app.models.replay_operation import ReplayOperation
        stmt = select(ReplayOperation).where(ReplayOperation.quarantine_id == quarantine_id).order_by(ReplayOperation.replayed_at.desc())
        ops = db.execute(stmt).scalars().all()
        return [op.to_dict() for op in ops]
