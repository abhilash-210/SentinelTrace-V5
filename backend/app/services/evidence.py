"""
services/evidence.py
--------------------
Cryptographic Evidence Vault service for raw security log preservation and verification.

Sprint 1 — Evidence Vault & Secure Log Ingestion.
Enforces:
1. Raw event preservation prior to parsing/normalization
2. Deterministic SHA-256 cryptographic fingerprinting
3. Live re-calculation for tamper detection
"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.evidence import EvidenceEvent
from app.schemas.evidence import EvidenceIngestRequest

logger = logging.getLogger(__name__)


def compute_raw_hash(raw_content: str) -> str:
    """
    Compute cryptographic SHA-256 digest of exact raw event string.

    CRITICAL ARCHITECTURAL GUARANTEE:
    - The raw event is encoded to UTF-8 without any normalization, trimming,
      or character modification.
    - Deterministic: Identical content produces identical hash digests.
    """
    if not isinstance(raw_content, str):
        raise TypeError("raw_content must be a string")
    return hashlib.sha256(raw_content.encode("utf-8")).hexdigest()


class EvidenceVaultService:
    """Service layer managing Evidence Vault storage and cryptographic verification."""

    @staticmethod
    def ingest_raw_event(db: Session, payload: EvidenceIngestRequest) -> EvidenceEvent:
        """
        Preserve a raw security log event into the immutable Evidence Vault.

        Execution sequence:
        1. Capture exact raw content without mutation
        2. Generate UUIDv4 identifier
        3. Capture UTC ingestion timestamp
        4. Compute SHA-256 fingerprint
        5. Persist record to PostgreSQL
        6. Commit and return persisted record
        """
        event_id = uuid.uuid4()
        ingested_at = datetime.now(timezone.utc)
        raw_hash = compute_raw_hash(payload.raw_event)

        logger.info(
            "Sealing raw evidence into Vault: event_id=%s, source='%s', type='%s', sha256=%s",
            event_id,
            payload.source_name,
            payload.source_type,
            raw_hash,
        )

        evidence = EvidenceEvent(
            event_id=event_id,
            source_name=payload.source_name,
            source_type=payload.source_type,
            raw_event=payload.raw_event,
            raw_event_hash=raw_hash,
            ingested_at=ingested_at,
            metadata_=payload.metadata or {},
            integrity_status="STORED",
        )

        db.add(evidence)
        db.commit()
        db.refresh(evidence)

        return evidence

    @staticmethod
    def get_event_by_id(db: Session, event_id: UUID) -> Optional[EvidenceEvent]:
        """Retrieve stored evidence record by UUID."""
        stmt = select(EvidenceEvent).where(EvidenceEvent.event_id == event_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def list_events(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        source_name: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> Tuple[List[EvidenceEvent], int]:
        """
        Retrieve paginated list of preserved evidence records.
        Returns (records, total_count).
        """
        base_stmt = select(EvidenceEvent)
        count_stmt = select(func.count()).select_from(EvidenceEvent)

        if source_name:
            base_stmt = base_stmt.where(EvidenceEvent.source_name.ilike(f"%{source_name}%"))
            count_stmt = count_stmt.where(EvidenceEvent.source_name.ilike(f"%{source_name}%"))

        if source_type:
            base_stmt = base_stmt.where(EvidenceEvent.source_type.ilike(f"%{source_type}%"))
            count_stmt = count_stmt.where(EvidenceEvent.source_type.ilike(f"%{source_type}%"))

        total = db.execute(count_stmt).scalar_one()

        query = base_stmt.order_by(EvidenceEvent.ingested_at.desc()).limit(limit).offset(offset)
        items = list(db.execute(query).scalars().all())

        return items, total

    @staticmethod
    def verify_integrity(db: Session, event_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Perform on-demand cryptographic verification of stored evidence.

        CRITICAL SECURITY REQUIREMENT:
        - NEVER rely solely on the database status column.
        - ALWAYS recompute the SHA-256 digest live over the stored raw_event string.
        - Compare recomputed digest with the immutable stored_hash.
        """
        evidence = EvidenceVaultService.get_event_by_id(db, event_id)
        if not evidence:
            return None

        # Recompute SHA-256 from the stored raw_event
        calculated_hash = compute_raw_hash(evidence.raw_event)
        stored_hash = evidence.raw_event_hash

        integrity_valid = calculated_hash == stored_hash
        status = "INTEGRITY_VERIFIED" if integrity_valid else "TAMPER_DETECTED"

        # Update and persist current verified status in database
        evidence.integrity_status = status
        db.commit()
        db.refresh(evidence)

        if not integrity_valid:
            logger.warning(
                "🚨 CRITICAL TAMPER ALERT: Event %s hash mismatch! Stored: %s | Calculated: %s",
                event_id,
                stored_hash,
                calculated_hash,
            )
        else:
            logger.info(
                "✅ Cryptographic integrity verified for event %s (hash=%s)",
                event_id,
                calculated_hash,
            )

        return {
            "event_id": evidence.event_id,
            "stored_hash": stored_hash,
            "calculated_hash": calculated_hash,
            "integrity_valid": integrity_valid,
            "status": status,
            "checked_at": datetime.now(timezone.utc),
        }
