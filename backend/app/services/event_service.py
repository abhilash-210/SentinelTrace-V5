"""
services/event_service.py
-------------------------
Core business logic for event ingestion, raw preservation, and live cryptographic verification.

Sprint 1 — Raw Event Preservation & Traceable Ingestion.
"""

import hashlib
import json
import logging
import uuid
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.event import IngestedEvent
from app.schemas.event import EventIngestRequest

logger = logging.getLogger(__name__)


def compute_sha256(raw_content: str) -> str:
    """
    Compute cryptographic SHA-256 digest over exact UTF-8 encoded string.

    Guarantees:
    - No modification or normalization of input
    - Deterministic output
    """
    if not isinstance(raw_content, str):
        raise TypeError("raw_content must be a string")
    return hashlib.sha256(raw_content.encode("utf-8")).hexdigest()


def detect_file_format(raw_content: str, hint: Optional[str] = None) -> str:
    """Detect file format or validate against hint."""
    if hint and hint.lower() in ["json", "csv", "text", "syslog", "xml"]:
        return hint.lower()

    stripped = raw_content.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or (
        stripped.startswith("[") and stripped.endswith("]")
    ):
        try:
            json.loads(stripped)
            return "json"
        except Exception:
            pass

    if "\n" in stripped and "," in stripped.split("\n")[0]:
        return "csv"

    return "text"


class EventService:
    """Service providing event ingestion, preservation, and integrity verification."""

    @staticmethod
    def ingest_event(db: Session, payload: EventIngestRequest) -> IngestedEvent:
        """
        Preserve a raw security event into PostgreSQL.

        Steps:
        1. Validate raw content exists
        2. Compute SHA-256 fingerprint on exact content
        3. Detect/assign format
        4. Calculate byte length
        5. Generate unique event ID
        6. Persist record with status 'PRESERVED'
        """
        raw = payload.raw_content
        if raw is None or not raw.strip():
            raise ValueError("Raw event content cannot be empty.")

        raw_hash = compute_sha256(raw)
        content_bytes = len(raw.encode("utf-8"))
        fmt = detect_file_format(raw, payload.file_format)
        event_id = f"evt_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)

        logger.info(
            "Preserving event: id=%s source='%s' format=%s bytes=%d sha256=%s",
            event_id,
            payload.source_name,
            fmt,
            content_bytes,
            raw_hash,
        )

        event = IngestedEvent(
            event_id=event_id,
            source_name=payload.source_name,
            source_type=payload.source_type,
            file_format=fmt,
            raw_content=raw,
            raw_content_hash=raw_hash,
            content_size=content_bytes,
            ingested_at=now,
            processing_status="PRESERVED",
            metadata_=payload.metadata or {},
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        return event

    @staticmethod
    def get_pipeline_stats(db: Session) -> Dict[str, Any]:
        """Retrieve ULPF pipeline dashboard statistics."""
        from app.models.normalized_event import NormalizedEvent
        from app.models.quarantined_event import QuarantinedEvent
        from app.services.log_forwarder_service import SIEM_STREAM_FILE
        from sqlalchemy import desc
        
        received = db.execute(select(func.count()).select_from(IngestedEvent)).scalar_one() or 0
        normalized = db.execute(select(func.count()).select_from(NormalizedEvent)).scalar_one() or 0
        quarantined = db.execute(select(func.count()).select_from(QuarantinedEvent)).scalar_one() or 0
        replayed = db.execute(select(func.count()).select_from(QuarantinedEvent).where(QuarantinedEvent.status == "REPLAYED")).scalar_one() or 0
        
        forwarded = 0
        if os.path.exists(SIEM_STREAM_FILE):
            with open(SIEM_STREAM_FILE, "r", encoding="utf-8") as sf:
                forwarded = sum(1 for line in sf if line.strip())
                
        recent_norm = db.execute(
            select(NormalizedEvent).order_by(desc(NormalizedEvent.normalized_at)).limit(5)
        ).scalars().all()
        
        recent_quar = db.execute(
            select(QuarantinedEvent).order_by(desc(QuarantinedEvent.quarantined_at)).limit(5)
        ).scalars().all()
        
        recent_events = []
        for n in recent_norm:
            recent_events.append({
                "time": n.normalized_at.strftime("%H:%M:%S"),
                "sort_time": n.normalized_at,
                "source": n.source_name,
                "format": n.source_type.upper(),
                "status": n.normalization_status
            })
            
        for q in recent_quar:
            recent_events.append({
                "time": q.quarantined_at.strftime("%H:%M:%S"),
                "sort_time": q.quarantined_at,
                "source": q.source_name,
                "format": q.source_type.upper(),
                "status": q.status
            })
            
        recent_events.sort(key=lambda x: x["sort_time"], reverse=True)
        recent_events = recent_events[:5]
        
        for e in recent_events:
            del e["sort_time"]
            
        return {
            "received": received,
            "parsed": normalized + quarantined,
            "normalized": normalized,
            "quarantined": quarantined,
            "replayed": replayed,
            "forwarded": forwarded,
            "recent_events": recent_events
        }

    @staticmethod
    def get_event_by_id(db: Session, event_id: str) -> Optional[IngestedEvent]:
        """Retrieve stored event record by event_id."""
        stmt = select(IngestedEvent).where(IngestedEvent.event_id == event_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def list_events(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        source_name: Optional[str] = None,
        source_type: Optional[str] = None,
        file_format: Optional[str] = None,
    ) -> Tuple[List[IngestedEvent], int]:
        """
        Retrieve paginated list of ingested events.
        Returns (items, total_count).
        """
        base_stmt = select(IngestedEvent)
        count_stmt = select(func.count()).select_from(IngestedEvent)

        if source_name:
            base_stmt = base_stmt.where(IngestedEvent.source_name.ilike(f"%{source_name}%"))
            count_stmt = count_stmt.where(IngestedEvent.source_name.ilike(f"%{source_name}%"))

        if source_type:
            base_stmt = base_stmt.where(IngestedEvent.source_type.ilike(f"%{source_type}%"))
            count_stmt = count_stmt.where(IngestedEvent.source_type.ilike(f"%{source_type}%"))

        if file_format:
            base_stmt = base_stmt.where(IngestedEvent.file_format == file_format.lower())
            count_stmt = count_stmt.where(IngestedEvent.file_format == file_format.lower())

        total = db.execute(count_stmt).scalar_one()
        query = base_stmt.order_by(IngestedEvent.ingested_at.desc()).limit(limit).offset(offset)
        items = list(db.execute(query).scalars().all())

        return items, total

    @staticmethod
    def verify_event_integrity(db: Session, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Perform live cryptographic verification on a stored event.

        Re-reads stored raw_content, computes SHA-256 live, and checks against stored_hash.
        """
        event = EventService.get_event_by_id(db, event_id)
        if not event:
            return None

        live_hash = compute_sha256(event.raw_content)
        stored_hash = event.raw_content_hash

        is_valid = live_hash == stored_hash
        status = "VERIFIED" if is_valid else "MISMATCH"

        event.processing_status = status
        db.commit()
        db.refresh(event)

        if not is_valid:
            logger.warning(
                "INTEGRITY MISMATCH DETECTED for %s: stored=%s live=%s",
                event_id,
                stored_hash,
                live_hash,
            )
        else:
            logger.info("Integrity verified for %s: hash=%s", event_id, live_hash)

        return {
            "event_id": event.event_id,
            "stored_hash": stored_hash,
            "calculated_hash": live_hash,
            "integrity_status": status,
            "checked_at": datetime.now(timezone.utc),
        }
