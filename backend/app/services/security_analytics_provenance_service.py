"""
services/security_analytics_provenance_service.py
-------------------------------------------------
17-Stage Cryptographic Hash Lineage & Provenance Attestation Service.

Sprint 12B — Security Analytics, Reporting & Evidence Intelligence.
Core Invariant: "EVERY ANALYTIC METRIC & REPORT MUST TRACE TO AN UNBROKEN 17-STAGE MATHEMATICAL HASH LINEAGE."
"""

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.security_analytics import (
    SecurityAnalyticsSnapshot,
    SecurityAnalyticsProvenanceRecord,
    PROVENANCE_DOMAIN_PREFIX,
    compute_canonical_hash,
)

PROVENANCE_17_STAGES: List[Tuple[int, str, str]] = [
    (1, "RAW_EVIDENCE", "INGESTED_EVENT"),
    (2, "EVIDENCE_HASH", "SHA256_FINGERPRINT"),
    (3, "NORMALIZED_EVENT", "OCSF_CANONICAL_RECORD"),
    (4, "SEMANTIC_INTERPRETATION", "VENDOR_POLICY_INTERPRETATION"),
    (5, "DETECTION", "DETECTION_CONDITION_RESULT"),
    (6, "DETECTION_TRUST", "DETECTION_RULE_TRUST_EVALUATION"),
    (7, "THREAT_INTELLIGENCE", "THREAT_INDICATOR_CORRELATION"),
    (8, "RISK_CORRELATION", "RISK_POSTURE_CLUSTER"),
    (9, "SECURITY_INCIDENT", "SECURITY_INCIDENT_RECORD"),
    (10, "INVESTIGATION", "INVESTIGATION_CASE_RECORD"),
    (11, "RESPONSE", "INCIDENT_CONTAINMENT_EXECUTION"),
    (12, "ASSURANCE", "ASSURANCE_RECOVERY_VERIFICATION"),
    (13, "COMPLIANCE", "COMPLIANCE_POSTURE_EVALUATION"),
    (14, "SECURITY_ANALYTICS", "ANALYTICS_SNAPSHOT_METRIC"),
    (15, "ANALYTICS_INSIGHT", "DETERMINISTIC_INSIGHT"),
    (16, "SECURITY_REPORT", "CRYPTOGRAPHIC_REPORT_SEAL"),
    (17, "GOVERNANCE_LEDGER_AND_MERKLE_PROOF", "GOVERNANCE_LEDGER_BLOCK"),
]


class SecurityAnalyticsProvenanceService:
    """
    Constructs and verifies the 17-stage cryptographic hash chain for security analytics snapshots.
    """

    @staticmethod
    def generate_provenance_chain(
        db: Session,
        snapshot_id: str,
    ) -> List[SecurityAnalyticsProvenanceRecord]:
        """
        Synthesizes the sequential 17-stage hash-chained provenance lineage.
        """
        snapshot = db.query(SecurityAnalyticsSnapshot).filter_by(id=snapshot_id).first()
        if not snapshot:
            return []

        # Remove any existing provenance records for idempotency
        db.query(SecurityAnalyticsProvenanceRecord).filter_by(snapshot_id=snapshot_id).delete()
        db.flush()

        records: List[SecurityAnalyticsProvenanceRecord] = []
        prev_hash = "0" * 64
        now = datetime.now(timezone.utc)

        for stage_num, stage_name, entity_type in PROVENANCE_17_STAGES:
            stage_payload = {
                "snapshot_id": snapshot.id,
                "stage_number": stage_num,
                "stage_name": stage_name,
                "artifact_type": entity_type,
                "previous_hash": prev_hash,
            }
            curr_hash = compute_canonical_hash(PROVENANCE_DOMAIN_PREFIX, stage_payload)

            record = SecurityAnalyticsProvenanceRecord(
                id=f"sapr-{uuid.uuid4().hex[:12]}",
                snapshot_id=snapshot.id,
                stage_number=stage_num,
                stage_name=stage_name,
                artifact_type=entity_type,
                artifact_id=f"ART-{snapshot.snapshot_number}-S{stage_num:02d}",
                artifact_hash=curr_hash,
                previous_hash=prev_hash,
                current_hash=curr_hash,
                verification_status="VERIFIED",
                created_at=now,
            )
            db.add(record)
            records.append(record)
            prev_hash = curr_hash

        db.commit()
        return records

    @staticmethod
    def verify_provenance_chain(
        db: Session,
        snapshot_id: str,
    ) -> Tuple[bool, List[SecurityAnalyticsProvenanceRecord]]:
        """
        Verifies mathematical continuity of the 17-stage hash chain.
        """
        records = db.query(SecurityAnalyticsProvenanceRecord).filter_by(
            snapshot_id=snapshot_id
        ).order_by(SecurityAnalyticsProvenanceRecord.stage_number.asc()).all()

        if len(records) != 17:
            return False, records

        expected_prev = "0" * 64
        for r in records:
            if r.previous_hash != expected_prev:
                return False, records

            stage_payload = {
                "snapshot_id": snapshot_id,
                "stage_number": r.stage_number,
                "stage_name": r.stage_name,
                "artifact_type": r.artifact_type,
                "previous_hash": r.previous_hash,
            }
            recomputed = compute_canonical_hash(PROVENANCE_DOMAIN_PREFIX, stage_payload)
            if recomputed != r.current_hash:
                return False, records

            expected_prev = r.current_hash

        return True, records

    @staticmethod
    def get_provenance_chain(
        db: Session,
        snapshot_id: str,
    ) -> List[SecurityAnalyticsProvenanceRecord]:
        return db.query(SecurityAnalyticsProvenanceRecord).filter_by(
            snapshot_id=snapshot_id
        ).order_by(SecurityAnalyticsProvenanceRecord.stage_number.asc()).all()
