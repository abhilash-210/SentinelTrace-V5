"""
services/normalization_service.py
---------------------------------
OCSF-Aligned Canonical Normalization Engine.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
Transforms raw security evidence into a canonical OCSF-aligned schema
while maintaining strict cryptographic traceability back to the Evidence Vault.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.source_profile import SourceProfile
from app.parsers import PARSER_REGISTRY
from app.services.source_detector import DEFAULT_SOURCE_PROFILES, SourceDetector

logger = logging.getLogger(__name__)


class NormalizationService:
    """Service managing OCSF-aligned log parsing and canonical event persistence."""

    @staticmethod
    def ensure_default_source_profiles(db: Session) -> None:
        """Seed default Source Profiles if not already present in the database."""
        for profile_data in DEFAULT_SOURCE_PROFILES:
            existing = db.execute(
                select(SourceProfile).where(SourceProfile.source_profile_id == profile_data["source_profile_id"])
            ).scalar_one_or_none()
            if not existing:
                profile = SourceProfile(
                    source_profile_id=profile_data["source_profile_id"],
                    profile_name=profile_data["profile_name"],
                    source_type=profile_data["source_type"],
                    supported_format=profile_data["supported_format"],
                    parser_type=profile_data["parser_type"],
                    version=profile_data["version"],
                    is_active=profile_data["is_active"],
                    configuration=profile_data["configuration"],
                )
                db.add(profile)
        db.commit()

    @staticmethod
    def list_source_profiles(db: Session) -> List[SourceProfile]:
        """Retrieve all active Source Profiles."""
        stmt = select(SourceProfile).order_by(SourceProfile.id.asc())
        return list(db.execute(stmt).scalars().all())

    @staticmethod
    def normalize_event(db: Session, event_id: str) -> Optional[NormalizedEvent]:
        """
        Normalize a preserved raw security event into an OCSF-aligned canonical event.

        Execution Pipeline:
        1. Fetch raw event from Evidence Vault (read-only)
        2. Idempotency check: reuse existing normalized event if already computed
        3. Detect source format and select parser
        4. Execute parser safely
        5. Map extracted fields to canonical OCSF classes
        6. Compute deterministic confidence score
        7. Persist to sentinel.normalized_events
        """
        # Step 1: Fetch raw evidence
        raw_event = db.execute(
            select(IngestedEvent).where(IngestedEvent.event_id == event_id)
        ).scalar_one_or_none()
        if not raw_event:
            return None

        # Step 2: Idempotency check
        existing = db.execute(
            select(NormalizedEvent)
            .where(NormalizedEvent.original_event_id == event_id)
            .order_by(NormalizedEvent.id.desc())
        ).scalar_one_or_none()
        if existing:
            logger.info("Idempotent normalization: returning existing normalized event %s", existing.normalized_event_id)
            return existing

        # Ensure seed profiles exist
        NormalizationService.ensure_default_source_profiles(db)

        # Step 3: Source detection
        parser_type, profile_id, detect_conf, detect_reasons = SourceDetector.detect(
            file_format=raw_event.file_format,
            source_type=raw_event.source_type,
            source_name=raw_event.source_name,
            raw_content=raw_event.raw_content,
        )

        parser = PARSER_REGISTRY.get(parser_type, PARSER_REGISTRY["syslog"])

        # Step 4: Parse
        parse_result = parser.parse(raw_event.raw_content, raw_event.metadata_)
        fields = parse_result.get("fields", {})
        parsed_time = parse_result.get("timestamp") or raw_event.ingested_at
        deductions = list(detect_reasons) + list(parse_result.get("confidence_deductions", []))

        # Step 5: Canonical OCSF-aligned classification
        class_uid = 4001
        class_name = "Network Activity"
        activity_id = 1
        activity_name = "Network Traffic"

        stype_lower = raw_event.source_type.lower()
        if "auth" in stype_lower or parser_type == "json":
            class_uid = 3001
            class_name = "Authentication"
            activity_id = 1 if fields.get("action") == "SUCCESS" else 2
            activity_name = "Logon Activity"
        elif "system" in stype_lower or "proc" in stype_lower or parser_type == "csv":
            class_uid = 1001
            class_name = "System Activity"
            activity_id = 1
            activity_name = "Process Activity"

        # Step 6: Deterministic confidence scoring
        confidence = detect_conf
        if not parse_result.get("success"):
            confidence = 0.20
            norm_status = "FAILED"
        else:
            # Deduct for missing key attributes
            if not fields.get("action"):
                confidence -= 0.10
                deductions.append("action not resolved")
            if class_uid == 4001 and not fields.get("src_ip"):
                confidence -= 0.15
                deductions.append("source IP missing")
            if class_uid == 3001 and not fields.get("user_name"):
                confidence -= 0.10
                deductions.append("username not resolved")
            if class_uid == 1001 and not fields.get("process_name"):
                confidence -= 0.10
                deductions.append("process name not resolved")

            confidence = max(0.10, min(1.0, round(confidence, 2)))
            norm_status = "NORMALIZED" if confidence >= 0.70 else "PARTIAL"

        # Step 7: Construct & persist NormalizedEvent
        norm_event_id = f"norm_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)

        normalized = NormalizedEvent(
            normalized_event_id=norm_event_id,
            original_event_id=raw_event.event_id,
            class_uid=class_uid,
            class_name=class_name,
            activity_id=activity_id,
            activity_name=activity_name,
            event_time=parsed_time,
            source_name=raw_event.source_name,
            source_type=raw_event.source_type,
            action=fields.get("action"),
            src_ip=fields.get("src_ip"),
            src_port=fields.get("src_port"),
            dst_ip=fields.get("dst_ip"),
            dst_port=fields.get("dst_port"),
            protocol=fields.get("protocol"),
            severity=fields.get("severity"),
            user_name=fields.get("user_name"),
            hostname=fields.get("hostname"),
            process_name=fields.get("process_name"),
            process_id=fields.get("process_id"),
            raw_data=fields,
            parser_name=parser.name,
            parser_version=parser.version,
            source_profile_id=profile_id,
            normalization_status=norm_status,
            normalization_confidence=confidence,
            confidence_reasons=deductions,
            normalized_at=now,
        )

        db.add(normalized)
        db.commit()
        db.refresh(normalized)

        logger.info(
            "Normalized event %s -> %s (Class: %s, Action: %s, Confidence: %.2f)",
            raw_event.event_id,
            normalized.normalized_event_id,
            normalized.class_name,
            normalized.action,
            normalized.normalization_confidence,
        )

        return normalized

    @staticmethod
    def get_normalized_by_id(db: Session, normalized_event_id: str) -> Optional[NormalizedEvent]:
        """Retrieve normalized event by normalized_event_id."""
        stmt = select(NormalizedEvent).where(NormalizedEvent.normalized_event_id == normalized_event_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def list_normalized_events(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        class_name: Optional[str] = None,
        normalization_status: Optional[str] = None,
        original_event_id: Optional[str] = None,
    ) -> Tuple[List[NormalizedEvent], int]:
        """List paginated normalized events with optional filters."""
        base_stmt = select(NormalizedEvent)
        count_stmt = select(func.count()).select_from(NormalizedEvent)

        if class_name:
            base_stmt = base_stmt.where(NormalizedEvent.class_name == class_name)
            count_stmt = count_stmt.where(NormalizedEvent.class_name == class_name)

        if normalization_status:
            base_stmt = base_stmt.where(NormalizedEvent.normalization_status == normalization_status.upper())
            count_stmt = count_stmt.where(NormalizedEvent.normalization_status == normalization_status.upper())

        if original_event_id:
            base_stmt = base_stmt.where(NormalizedEvent.original_event_id == original_event_id)
            count_stmt = count_stmt.where(NormalizedEvent.original_event_id == original_event_id)

        total = db.execute(count_stmt).scalar_one()
        query = base_stmt.order_by(NormalizedEvent.normalized_at.desc()).limit(limit).offset(offset)
        items = list(db.execute(query).scalars().all())

        return items, total

    @staticmethod
    def get_traceability(db: Session, original_event_id: str) -> Optional[Dict[str, Any]]:
        """
        Generate end-to-end traceability report connecting raw evidence hash to normalized canonical event.
        """
        raw_event = db.execute(
            select(IngestedEvent).where(IngestedEvent.event_id == original_event_id)
        ).scalar_one_or_none()
        if not raw_event:
            return None

        norm_event = db.execute(
            select(NormalizedEvent)
            .where(NormalizedEvent.original_event_id == original_event_id)
            .order_by(NormalizedEvent.id.desc())
        ).scalar_one_or_none()
        if not norm_event:
            return None

        return {
            "original_event_id": raw_event.event_id,
            "raw_content_hash": raw_event.raw_content_hash,
            "normalized_event_id": norm_event.normalized_event_id,
            "parser_name": norm_event.parser_name,
            "parser_version": norm_event.parser_version,
            "source_profile_id": norm_event.source_profile_id,
            "class_name": norm_event.class_name,
            "activity_name": norm_event.activity_name,
            "normalization_status": norm_event.normalization_status,
            "normalization_confidence": norm_event.normalization_confidence,
            "confidence_reasons": norm_event.confidence_reasons,
            "normalized_at": norm_event.normalized_at,
        }
