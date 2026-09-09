"""
services/compliance_gap_service.py
----------------------------------
Deterministic Compliance Gap Detection, Fingerprint Deduplication & Remediation Tracking.

Sprint 11A — Compliance Intelligence, Security Control Governance & Evidence-Backed Compliance Assurance.

Core Invariant: "COMPLIANCE MUST BE EVIDENCE-BACKED, EXPLAINABLE, HUMAN-GOVERNED, AND CRYPTOGRAPHICALLY VERIFIABLE."
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.compliance_intelligence import (
    ComplianceGap,
    ComplianceRequirement,
    SecurityControl,
    FrameworkControlMapping,
    ControlEffectivenessEvaluation,
    COMPLIANCE_GAP_DOMAIN_PREFIX,
    calculate_compliance_hash,
    utcnow,
)
from app.services.governance_ledger_service import GovernanceLedgerService

logger = logging.getLogger("sentinel.services.compliance_gap")


class ComplianceGapService:
    """Service for deterministic compliance gap detection, deduplication, and resolution tracking."""

    @staticmethod
    def compute_gap_fingerprint(
        requirement_id: str,
        control_id: str,
        gap_category: str,
        root_cause_rule: str,
    ) -> str:
        """Computes deterministic SHA-256 fingerprint for deduplicating recurring compliance gaps."""
        payload = f"{requirement_id}|{control_id}|{gap_category}|{root_cause_rule}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def record_gap(
        cls,
        db: Session,
        framework_requirement_id: Optional[str],
        security_control_id: Optional[str],
        gap_title: str,
        gap_category: str,
        severity: str,
        root_cause_rule: str,
        description: str,
    ) -> ComplianceGap:
        """
        Records or updates a deduplicated compliance gap using its SHA-256 fingerprint.
        """
        fingerprint = cls.compute_gap_fingerprint(
            requirement_id=framework_requirement_id or "NONE",
            control_id=security_control_id or "NONE",
            gap_category=gap_category,
            root_cause_rule=root_cause_rule,
        )

        existing_gap = (
            db.query(ComplianceGap)
            .filter(
                ComplianceGap.deduplication_fingerprint == fingerprint,
                ComplianceGap.gap_status.in_(["OPEN", "ACKNOWLEDGED", "UNDER_REVIEW", "REMEDIATING"]),
            )
            .first()
        )

        now = utcnow()

        if existing_gap:
            existing_gap.severity = severity
            existing_gap.description = description
            existing_gap.root_cause = root_cause_rule
            db.flush()
            logger.info(f"Updated existing active gap {existing_gap.id} (fingerprint: {fingerprint[:10]}...)")
            return existing_gap

        gap_number = f"CGP-{now.strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"

        gap_payload = {
            "gap_number": gap_number,
            "fingerprint": fingerprint,
            "requirement_id": framework_requirement_id,
            "control_id": security_control_id,
            "gap_category": gap_category,
            "severity": severity,
            "root_cause_rule": root_cause_rule,
            "detected_at": now.isoformat(),
        }
        gap_hash = calculate_compliance_hash(COMPLIANCE_GAP_DOMAIN_PREFIX, gap_payload)

        new_gap = ComplianceGap(
            gap_number=gap_number,
            framework_requirement_id=framework_requirement_id,
            security_control_id=security_control_id,
            gap_category=gap_category,
            severity=severity,
            gap_status="OPEN",
            description=description,
            root_cause=root_cause_rule,
            detected_at=now,
            deduplication_fingerprint=fingerprint,
            gap_hash=gap_hash,
        )
        db.add(new_gap)
        db.flush()

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="COMPLIANCE_GAP_DETECTED",
                actor_id=None,
                actor_username="SYSTEM",
                payload={
                    "entity_type": "COMPLIANCE_GAP",
                    "entity_id": new_gap.id,
                    "gap_number": gap_number,
                    "gap_fingerprint": fingerprint,
                    "severity": severity,
                    "gap_hash": gap_hash,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to log gap to ledger: {e}")

        logger.info(f"Detected compliance gap {gap_number}: {gap_title}")
        return new_gap

    @classmethod
    def scan_framework_gaps(
        cls,
        db: Session,
        framework_id: Optional[str] = None,
    ) -> List[ComplianceGap]:
        """
        Scans framework requirements and mapped controls to detect and record compliance gaps.
        """
        query = db.query(FrameworkControlMapping)
        if framework_id:
            query = query.join(ComplianceRequirement).filter(ComplianceRequirement.framework_id == framework_id)

        mappings = query.all()
        detected_gaps: List[ComplianceGap] = []

        for mapping in mappings:
            req = mapping.requirement
            ctrl = mapping.control
            if not req or not ctrl:
                continue

            latest_eval = (
                db.query(ControlEffectivenessEvaluation)
                .filter(ControlEffectivenessEvaluation.security_control_id == ctrl.id)
                .order_by(desc(ControlEffectivenessEvaluation.evaluated_at))
                .first()
            )

            if not latest_eval:
                gap = cls.record_gap(
                    db=db,
                    framework_requirement_id=req.id,
                    security_control_id=ctrl.id,
                    gap_title=f"Unassessed Control: {ctrl.control_code}",
                    gap_category="MISSING_CONTROL",
                    severity="HIGH" if req.verification_required else "MEDIUM",
                    root_cause_rule="CONTROL_NEVER_EVALUATED",
                    description=f"Control {ctrl.control_code} mapped to {req.requirement_code} has no evaluation.",
                )
                detected_gaps.append(gap)
                continue

            if latest_eval.integrity_score == 0.0:
                gap = cls.record_gap(
                    db=db,
                    framework_requirement_id=req.id,
                    security_control_id=ctrl.id,
                    gap_title=f"Cryptographic Failure: {ctrl.control_code}",
                    gap_category="CRYPTOGRAPHIC_FAILURE",
                    severity="CRITICAL",
                    root_cause_rule="CRYPTOGRAPHIC_INTEGRITY_DOMINANCE",
                    description=f"Control {ctrl.control_code} failed cryptographic verification.",
                )
                detected_gaps.append(gap)

            if latest_eval.evidence_coverage == 0.0:
                gap = cls.record_gap(
                    db=db,
                    framework_requirement_id=req.id,
                    security_control_id=ctrl.id,
                    gap_title=f"Missing Evidence: {ctrl.control_code}",
                    gap_category="INSUFFICIENT_EVIDENCE",
                    severity="HIGH" if req.verification_required else "MEDIUM",
                    root_cause_rule="MISSING_EVIDENCE_COVERAGE",
                    description=f"No verified evidence bound to {ctrl.control_code} for {req.requirement_code}.",
                )
                detected_gaps.append(gap)

        return detected_gaps

    @classmethod
    def resolve_gap(
        cls,
        db: Session,
        gap_id: str,
        resolver_user_id: Optional[str] = None,
        resolver_username: str = "SYSTEM",
        resolution_summary: str = "",
        resolution_evidence_id: Optional[str] = None,
    ) -> ComplianceGap:
        """
        Resolves an active compliance gap.
        """
        gap = (
            db.query(ComplianceGap)
            .filter((ComplianceGap.id == gap_id) | (ComplianceGap.gap_number == gap_id))
            .first()
        )
        if not gap:
            raise ValueError(f"Compliance gap {gap_id} not found.")

        gap.gap_status = "VERIFIED_RESOLVED"
        gap.resolved_at = utcnow()
        gap.resolution_evidence_id = resolution_evidence_id

        db.flush()

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="COMPLIANCE_GAP_RESOLVED",
                actor_id=resolver_user_id,
                actor_username=resolver_username,
                payload={
                    "entity_type": "COMPLIANCE_GAP",
                    "entity_id": gap.id,
                    "gap_number": gap.gap_number,
                    "resolution_summary": resolution_summary,
                },
            )
        except Exception as e:
            logger.warning(f"Ledger append failed: {e}")

        logger.info(f"Resolved compliance gap {gap.gap_number} by {resolver_username}")
        return gap
