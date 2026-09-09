"""
services/investigation_timeline_service.py
------------------------------------------
Cross-Domain Chronological Investigation Timeline Reconstruction Engine.

Sprint 12A — Unified SOC Investigation & Security Case Management.
Core Invariant: "TIMELINE RECONSTRUCTION MUST PRESERVE ORIGINAL SOURCE TIMESTAMPS."
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.security_investigation import (
    SecurityInvestigationCase,
    InvestigationTimelineEvent,
    InvestigationArtifactBinding,
    TIMELINE_DOMAIN_PREFIX,
    compute_canonical_hash,
)
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.security_incident import SecurityIncident


def to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class InvestigationTimelineService:
    """
    Reconstructs end-to-end chronological timeline across all bound upstream telemetry.
    """

    @staticmethod
    def record_timeline_event(
        db: Session,
        case_id: str,
        timestamp: datetime,
        event_type: str,
        source_domain: str,
        artifact_reference: str,
        description: str,
        hash_reference: str = "",
        sequence_order: int = 0,
    ) -> InvestigationTimelineEvent:
        """
        Appends an immutable timeline event. Preserves exact source timestamp.
        """
        ts_utc = to_utc(timestamp) or datetime.now(timezone.utc)
        if not hash_reference:
            hash_reference = compute_canonical_hash(
                TIMELINE_DOMAIN_PREFIX,
                {
                    "case_id": case_id,
                    "type": event_type,
                    "ref": artifact_reference,
                    "ts": ts_utc.isoformat(),
                },
            )

        event = InvestigationTimelineEvent(
            case_id=case_id,
            timestamp=ts_utc,
            event_type=event_type,
            source_domain=source_domain,
            artifact_reference=artifact_reference,
            description=description,
            hash_reference=hash_reference,
            sequence_order=sequence_order,
        )
        db.add(event)
        db.flush()
        return event

    @staticmethod
    def reconstruct_case_timeline(
        db: Session,
        case_id: str,
    ) -> List[InvestigationTimelineEvent]:
        """
        Reconstructs the full chronological timeline from case inception and all bound artifacts.
        """
        case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found.")

        # Clear existing auto-reconstructed timeline events if any to allow fresh re-indexing
        # but keep custom analyst actions if preferred, or rebuild complete sequence
        existing = db.query(InvestigationTimelineEvent).filter(InvestigationTimelineEvent.case_id == case_id).all()
        existing_refs = {e.artifact_reference for e in existing}

        events_to_add: List[Dict[str, Any]] = []

        # 1. Case Opening Event
        if f"case-opened-{case.id}" not in existing_refs:
            events_to_add.append({
                "timestamp": to_utc(case.opened_at) or to_utc(case.created_at),
                "event_type": "CASE_OPENED",
                "source_domain": "SOC_INVESTIGATION",
                "artifact_reference": f"case-opened-{case.id}",
                "description": f"SOC Investigation Case {case.case_number} opened by {case.created_by}: {case.title}",
                "hash_reference": case.canonical_hash,
            })

        # 2. Inspect Bound Artifacts for Timestamps
        bindings = db.query(InvestigationArtifactBinding).filter(InvestigationArtifactBinding.case_id == case_id).all()
        for b in bindings:
            ref_key = f"binding-{b.id}"
            if ref_key not in existing_refs:
                events_to_add.append({
                    "timestamp": to_utc(b.binding_timestamp) or to_utc(b.created_at),
                    "event_type": f"ARTIFACT_BOUND_{b.artifact_type}",
                    "source_domain": b.source_domain,
                    "artifact_reference": ref_key,
                    "description": f"Bound {b.artifact_type} ({b.artifact_id}): {b.summary or ''}",
                    "hash_reference": b.canonical_hash,
                })

        # Sort all newly prepared events by timestamp
        events_to_add.sort(key=lambda x: x["timestamp"])

        created_events: List[InvestigationTimelineEvent] = []
        current_max_seq = len(existing)

        for idx, item in enumerate(events_to_add, start=current_max_seq + 1):
            ev = InvestigationTimelineService.record_timeline_event(
                db=db,
                case_id=case_id,
                timestamp=item["timestamp"],
                event_type=item["event_type"],
                source_domain=item["source_domain"],
                artifact_reference=item["artifact_reference"],
                description=item["description"],
                hash_reference=item["hash_reference"],
                sequence_order=idx,
            )
            created_events.append(ev)

        # Return full timeline ordered chronologically
        return (
            db.query(InvestigationTimelineEvent)
            .filter(InvestigationTimelineEvent.case_id == case_id)
            .order_by(InvestigationTimelineEvent.timestamp.asc(), InvestigationTimelineEvent.sequence_order.asc())
            .all()
        )
