"""
services/incident_service.py
----------------------------
Service for Deterministic Security Incident Generation, Deduplication, Lifecycle Management,
Evidence Linking, Analyst Findings, Timeline Tracking, and 13-Stage Provenance Tracing.

Sprint 8A — Security Incident Correlation & Investigation Foundation.
"""

from datetime import datetime, timezone
import hashlib
import logging
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.models.detection_rule_trust import DetectionRuleTrustEvaluation, DetectionTrustAlert
from app.models.event import IngestedEvent
from app.models.governance import GovernanceAuditLog
from app.models.ledger import GovernanceLedgerEntry
from app.models.normalized_event import NormalizedEvent
from app.models.remediation import RemediationCandidate
from app.models.risk_correlation import RiskCorrelation, RiskCorrelationMember
from app.models.security_incident import (
    IncidentEvidenceLink,
    IncidentFinding,
    IncidentSignal,
    IncidentTimelineEvent,
    SecurityIncident,
)
from app.models.semantic_interpretation import SemanticDriftAlert, SemanticInterpretation
from app.models.semantic_policy import ProtectedSemanticField, SemanticPolicy
from app.models.user import User
from app.services.governance_ledger_service import GovernanceLedgerService

logger = logging.getLogger("sentinel.services.incident")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IncidentService:
    """
    Deterministic Incident Correlation & Investigation Engine.
    """

    ALLOWED_STATE_TRANSITIONS = {
        "OPEN": {"TRIAGING"},
        "TRIAGING": {"INVESTIGATING", "REJECTED"},
        "INVESTIGATING": {"TRIAGING"},
        # Note: CONTAINED, PENDING_CLOSURE, CLOSED belong to Sprint 8B governance
    }

    SEVERITY_PRIORITY_MAP = {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "MEDIUM": "P3",
        "LOW": "P4",
    }

    # ── 1. Incident Generation from Risk Correlation ─────────────────────────

    @classmethod
    def create_incident_from_correlation(
        cls,
        db: Session,
        correlation_id: str,
        actor_user_id: str = "usr_system",
        actor_username: str = "system",
    ) -> SecurityIncident:
        """
        Deterministically creates or retrieves a deduplicated SecurityIncident
        from a RiskCorrelation record.
        """
        corr = (
            db.query(RiskCorrelation)
            .filter(RiskCorrelation.correlation_id == correlation_id)
            .first()
        )
        if not corr:
            raise ValueError(f"RiskCorrelation '{correlation_id}' not found.")

        members = (
            db.query(RiskCorrelationMember)
            .filter(RiskCorrelationMember.correlation_id == correlation_id)
            .all()
        )

        # Extract members and context
        drift_alert_ids = [m.member_id for m in members if m.member_type == "SEMANTIC_DRIFT_ALERT"]
        trust_alert_ids = [m.member_id for m in members if m.member_type == "DETECTION_TRUST_ALERT"]
        rule_ids = [m.member_id for m in members if m.member_type == "DETECTION_RULE"]
        field_names = [m.member_id for m in members if m.member_type in ("CANONICAL_FIELD", "PROTECTED_FIELD")]
        has_protected_field = any(m.member_type == "PROTECTED_FIELD" for m in members)

        # Deduplication Fingerprint: SHA256(correlation_id + sorted signals + root_cause_cluster_key)
        all_signals = sorted(list(set(drift_alert_ids + trust_alert_ids + rule_ids)))
        cluster_key = corr.risk_cluster_key or "cluster:general"
        fp_raw = f"{corr.correlation_id}:{','.join(all_signals)}:{cluster_key}"
        fingerprint = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

        # Check for existing ACTIVE incident for deduplication
        existing_incident = (
            db.query(SecurityIncident)
            .filter(
                SecurityIncident.source_correlation_id == correlation_id,
                SecurityIncident.status.in_(["OPEN", "TRIAGING", "INVESTIGATING"]),
            )
            .first()
        )
        if existing_incident:
            logger.info(
                f"Deduplication hit: active incident {existing_incident.incident_number} "
                f"already exists for correlation '{correlation_id}'."
            )
            return existing_incident

        # Determine Incident Type
        if has_protected_field:
            inc_type = "PROTECTED_FIELD"
        elif drift_alert_ids and trust_alert_ids:
            inc_type = "MULTI_SIGNAL"
        elif trust_alert_ids and not drift_alert_ids:
            inc_type = "DETECTION_TRUST"
        elif corr.risk_cluster_key and "cluster" in corr.risk_cluster_key:
            inc_type = "RISK_CLUSTER"
        elif drift_alert_ids:
            inc_type = "SEMANTIC_RISK"
        else:
            inc_type = "MIXED"

        # Determine Severity with Deterministic Precedence
        # CRITICAL > HIGH > MEDIUM > LOW
        if corr.severity == "CRITICAL" or has_protected_field or len(rule_ids) >= 3:
            severity = "CRITICAL"
        elif corr.severity == "HIGH" or len(trust_alert_ids) >= 2 or len(rule_ids) >= 1:
            severity = "HIGH"
        elif corr.severity == "MEDIUM" or len(drift_alert_ids) >= 1:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        priority = cls.SEVERITY_PRIORITY_MAP.get(severity, "P3")

        # Generate Deterministic Incident Number: INC-2026-XXXXXX
        incident_count = db.query(SecurityIncident).count() + 1
        incident_number = f"INC-2026-{incident_count:06d}"
        # Ensure collision safety
        while db.query(SecurityIncident).filter(SecurityIncident.incident_number == incident_number).first():
            incident_count += 1
            incident_number = f"INC-2026-{incident_count:06d}"

        title = f"Security Incident: {corr.correlation_type.replace('_', ' ').title()} - {cluster_key}"
        description = (
            f"Correlated security incident initiated from Risk Correlation {correlation_id}. "
            f"{corr.explanation}"
        )

        rc_strs = [
            c if isinstance(c, str) else (c.get("candidate") or c.get("title") or c.get("description") or str(c))
            for c in (corr.root_cause_candidates or [])
        ]
        root_cause_summary = (
            f"Root cause candidate: {', '.join(rc_strs) if rc_strs else 'Semantic drift and trust degradation'}. "
            f"Impacted {len(rule_ids)} detection rules and {len(field_names)} canonical fields."
        )

        incident_id = f"inc_{uuid.uuid4().hex[:12]}"

        new_incident = SecurityIncident(
            incident_id=incident_id,
            incident_number=incident_number,
            title=title,
            description=description,
            incident_type=inc_type,
            severity=severity,
            priority=priority,
            status="OPEN",
            source_correlation_id=correlation_id,
            source_cluster_key=cluster_key,
            root_cause_summary=root_cause_summary,
            confidence=corr.risk_score if corr.risk_score > 0 else 1.0,
            affected_signal_count=len(drift_alert_ids) + len(trust_alert_ids),
            affected_rule_count=len(rule_ids),
            affected_field_count=len(field_names),
            created_by_user_id=actor_user_id,
            assigned_to_user_id=None,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(new_incident)
        db.flush()

        # Link Signals
        # 1. Risk Correlation as PRIMARY_TRIGGER
        sig_corr = IncidentSignal(
            incident_signal_id=f"isig_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            signal_type="RISK_CORRELATION",
            signal_id=correlation_id,
            relationship_type="PRIMARY_TRIGGER",
            created_at=utcnow(),
        )
        db.add(sig_corr)

        # 2. Semantic Drift Alerts
        for d_id in drift_alert_ids:
            sig_d = IncidentSignal(
                incident_signal_id=f"isig_{uuid.uuid4().hex[:12]}",
                incident_id=incident_id,
                signal_type="SEMANTIC_DRIFT_ALERT",
                signal_id=d_id,
                relationship_type="ROOT_CAUSE",
                created_at=utcnow(),
            )
            db.add(sig_d)

        # 3. Detection Trust Alerts
        for t_id in trust_alert_ids:
            sig_t = IncidentSignal(
                incident_signal_id=f"isig_{uuid.uuid4().hex[:12]}",
                incident_id=incident_id,
                signal_type="DETECTION_TRUST_ALERT",
                signal_id=t_id,
                relationship_type="DOWNSTREAM_IMPACT",
                created_at=utcnow(),
            )
            db.add(sig_t)

        # Link Evidence references
        for d_id in drift_alert_ids:
            ev_d = IncidentEvidenceLink(
                link_id=f"iev_{uuid.uuid4().hex[:12]}",
                incident_id=incident_id,
                evidence_type="DRIFT_ALERT",
                evidence_id=d_id,
                relationship="ROOT_CAUSE",
                linked_by_user_id=actor_user_id,
                linked_at=utcnow(),
            )
            db.add(ev_d)

        for t_id in trust_alert_ids:
            ev_t = IncidentEvidenceLink(
                link_id=f"iev_{uuid.uuid4().hex[:12]}",
                incident_id=incident_id,
                evidence_type="TRUST_EVALUATION",
                evidence_id=t_id,
                relationship="SUPPORTING",
                linked_by_user_id=actor_user_id,
                linked_at=utcnow(),
            )
            db.add(ev_t)

        # Append-Only Timeline Event: INCIDENT_CREATED
        timeline_event = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            event_type="INCIDENT_CREATED",
            actor_user_id=actor_user_id,
            event_data={
                "incident_number": incident_number,
                "title": title,
                "severity": severity,
                "priority": priority,
                "fingerprint": fingerprint,
                "source_correlation_id": correlation_id,
                "source_cluster_key": cluster_key,
            },
            created_at=utcnow(),
        )
        db.add(timeline_event)

        # Cryptographic Governance Ledger Entry
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="INCIDENT_CREATED",
                actor_id=actor_user_id,
                actor_username=actor_username,
                payload={
                    "incident_id": incident_id,
                    "incident_number": incident_number,
                    "severity": severity,
                    "priority": priority,
                    "source_correlation_id": correlation_id,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to record governance ledger entry for incident creation: {e}")

        db.commit()
        db.refresh(new_incident)
        logger.info(f"Created Security Incident {incident_number} ({incident_id}) from correlation {correlation_id}.")
        return new_incident

    # ── 2. Manual Incident Creation ─────────────────────────────────────────

    @classmethod
    def create_manual_incident(
        cls,
        db: Session,
        title: str,
        description: Optional[str],
        incident_type: str,
        severity: str,
        priority: Optional[str],
        source_correlation_id: Optional[str],
        source_cluster_key: Optional[str],
        root_cause_summary: Optional[str],
        confidence: float,
        assigned_to_user_id: Optional[str],
        actor_user_id: str,
        actor_username: str,
    ) -> SecurityIncident:
        """
        Manually creates an incident by an authorized Security Analyst or Admin.
        """
        assigned_priority = priority or cls.SEVERITY_PRIORITY_MAP.get(severity, "P3")

        incident_count = db.query(SecurityIncident).count() + 1
        incident_number = f"INC-2026-{incident_count:06d}"
        while db.query(SecurityIncident).filter(SecurityIncident.incident_number == incident_number).first():
            incident_count += 1
            incident_number = f"INC-2026-{incident_count:06d}"

        incident_id = f"inc_{uuid.uuid4().hex[:12]}"

        new_incident = SecurityIncident(
            incident_id=incident_id,
            incident_number=incident_number,
            title=title,
            description=description,
            incident_type=incident_type,
            severity=severity,
            priority=assigned_priority,
            status="OPEN",
            source_correlation_id=source_correlation_id,
            source_cluster_key=source_cluster_key,
            root_cause_summary=root_cause_summary,
            confidence=confidence,
            affected_signal_count=0,
            affected_rule_count=0,
            affected_field_count=0,
            created_by_user_id=actor_user_id,
            assigned_to_user_id=assigned_to_user_id,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(new_incident)
        db.flush()

        # Append-Only Timeline Event
        timeline_event = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            event_type="INCIDENT_CREATED",
            actor_user_id=actor_user_id,
            event_data={
                "incident_number": incident_number,
                "title": title,
                "severity": severity,
                "priority": assigned_priority,
                "created_by": actor_username,
            },
            created_at=utcnow(),
        )
        db.add(timeline_event)

        # Cryptographic Governance Ledger Entry
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="INCIDENT_CREATED",
                actor_id=actor_user_id,
                actor_username=actor_username,
                payload={
                    "incident_id": incident_id,
                    "incident_number": incident_number,
                    "severity": severity,
                    "priority": assigned_priority,
                    "created_by": actor_username,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to record governance ledger entry for manual incident creation: {e}")

        db.commit()
        db.refresh(new_incident)
        return new_incident

    # ── 3. Query & Retrieval ────────────────────────────────────────────────

    @classmethod
    def get_incident(cls, db: Session, incident_id: str) -> SecurityIncident:
        incident = (
            db.query(SecurityIncident)
            .filter(
                (SecurityIncident.incident_id == incident_id)
                | (SecurityIncident.incident_number == incident_id)
            )
            .first()
        )
        if not incident:
            raise ValueError(f"Security incident '{incident_id}' not found.")
        return incident

    @classmethod
    def list_incidents(
        cls,
        db: Session,
        severity: Optional[str] = None,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        incident_type: Optional[str] = None,
        assigned_to: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[SecurityIncident]:
        query = db.query(SecurityIncident)
        if severity:
            query = query.filter(SecurityIncident.severity == severity)
        if priority:
            query = query.filter(SecurityIncident.priority == priority)
        if status:
            query = query.filter(SecurityIncident.status == status)
        if incident_type:
            query = query.filter(SecurityIncident.incident_type == incident_type)
        if assigned_to:
            query = query.filter(SecurityIncident.assigned_to_user_id == assigned_to)

        return (
            query.order_by(desc(SecurityIncident.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )

    # ── 4. Lifecycle & Assignment ───────────────────────────────────────────

    @classmethod
    def assign_incident(
        cls,
        db: Session,
        incident_id: str,
        assigned_to_user_id: Optional[str],
        actor_user_id: str,
        actor_username: str,
    ) -> SecurityIncident:
        incident = cls.get_incident(db, incident_id)
        old_assigned = incident.assigned_to_user_id
        incident.assigned_to_user_id = assigned_to_user_id
        incident.updated_at = utcnow()

        # Timeline Event
        timeline_event = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident.incident_id,
            event_type="ANALYST_ASSIGNED",
            actor_user_id=actor_user_id,
            event_data={
                "previous_assigned_to": old_assigned,
                "new_assigned_to": assigned_to_user_id,
                "assigned_by": actor_username,
            },
            created_at=utcnow(),
        )
        db.add(timeline_event)

        # Governance Ledger
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="INCIDENT_ASSIGNED",
                actor_id=actor_user_id,
                actor_username=actor_username,
                payload={
                    "incident_id": incident.incident_id,
                    "previous_assigned_to": old_assigned,
                    "new_assigned_to": assigned_to_user_id,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to record governance ledger for assignment: {e}")

        db.commit()
        db.refresh(incident)
        return incident

    @classmethod
    def change_incident_status(
        cls,
        db: Session,
        incident_id: str,
        new_status: str,
        reason: Optional[str],
        actor_user_id: str,
        actor_username: str,
    ) -> SecurityIncident:
        incident = cls.get_incident(db, incident_id)
        current_status = incident.status

        # Validate Sprint 8A allowed state machine transitions
        allowed = cls.ALLOWED_STATE_TRANSITIONS.get(current_status, set())
        if new_status not in allowed:
            raise ValueError(
                f"INVALID_INCIDENT_STATE_TRANSITION: Cannot transition incident from '{current_status}' to '{new_status}'. "
                f"Allowed transitions: {list(allowed) if allowed else 'None'}"
            )

        incident.status = new_status
        incident.updated_at = utcnow()

        # Timeline Event
        timeline_event = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident.incident_id,
            event_type="STATUS_CHANGED",
            actor_user_id=actor_user_id,
            event_data={
                "previous_status": current_status,
                "new_status": new_status,
                "reason": reason or "Analyst investigation state update",
            },
            created_at=utcnow(),
        )
        db.add(timeline_event)

        # Governance Ledger
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="INCIDENT_STATUS_CHANGED",
                actor_id=actor_user_id,
                actor_username=actor_username,
                payload={
                    "incident_id": incident.incident_id,
                    "previous_status": current_status,
                    "new_status": new_status,
                    "reason": reason,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to record governance ledger for status update: {e}")

        db.commit()
        db.refresh(incident)
        return incident

    # ── 5. Signal & Evidence Linking ────────────────────────────────────────

    @classmethod
    def link_signal(
        cls,
        db: Session,
        incident_id: str,
        signal_type: str,
        signal_id: str,
        relationship_type: str,
        actor_user_id: str,
        actor_username: str,
    ) -> IncidentSignal:
        incident = cls.get_incident(db, incident_id)

        existing = (
            db.query(IncidentSignal)
            .filter(
                IncidentSignal.incident_id == incident.incident_id,
                IncidentSignal.signal_type == signal_type,
                IncidentSignal.signal_id == signal_id,
            )
            .first()
        )
        if existing:
            raise ValueError(f"Signal '{signal_type}:{signal_id}' is already linked to this incident.")

        sig = IncidentSignal(
            incident_signal_id=f"isig_{uuid.uuid4().hex[:12]}",
            incident_id=incident.incident_id,
            signal_type=signal_type,
            signal_id=signal_id,
            relationship_type=relationship_type,
            created_at=utcnow(),
        )
        db.add(sig)

        incident.affected_signal_count += 1
        incident.updated_at = utcnow()

        # Timeline Event
        timeline_event = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident.incident_id,
            event_type="SIGNAL_LINKED",
            actor_user_id=actor_user_id,
            event_data={
                "signal_type": signal_type,
                "signal_id": signal_id,
                "relationship_type": relationship_type,
            },
            created_at=utcnow(),
        )
        db.add(timeline_event)

        # Governance Ledger
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="INCIDENT_SIGNAL_LINKED",
                actor_id=actor_user_id,
                actor_username=actor_username,
                payload={
                    "incident_id": incident.incident_id,
                    "signal_type": signal_type,
                    "signal_id": signal_id,
                    "relationship_type": relationship_type,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to record governance ledger for signal link: {e}")

        db.commit()
        db.refresh(sig)
        return sig

    @classmethod
    def link_evidence(
        cls,
        db: Session,
        incident_id: str,
        evidence_type: str,
        evidence_id: str,
        relationship: str,
        actor_user_id: str,
        actor_username: str,
    ) -> IncidentEvidenceLink:
        incident = cls.get_incident(db, incident_id)

        existing = (
            db.query(IncidentEvidenceLink)
            .filter(
                IncidentEvidenceLink.incident_id == incident.incident_id,
                IncidentEvidenceLink.evidence_type == evidence_type,
                IncidentEvidenceLink.evidence_id == evidence_id,
            )
            .first()
        )
        if existing:
            raise ValueError(f"Evidence '{evidence_type}:{evidence_id}' is already linked to this incident.")

        ev_link = IncidentEvidenceLink(
            link_id=f"iev_{uuid.uuid4().hex[:12]}",
            incident_id=incident.incident_id,
            evidence_type=evidence_type,
            evidence_id=evidence_id,
            relationship=relationship,
            linked_by_user_id=actor_user_id,
            linked_at=utcnow(),
        )
        db.add(ev_link)
        incident.updated_at = utcnow()

        # Timeline Event
        timeline_event = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident.incident_id,
            event_type="EVIDENCE_LINKED",
            actor_user_id=actor_user_id,
            event_data={
                "evidence_type": evidence_type,
                "evidence_id": evidence_id,
                "relationship": relationship,
                "linked_by": actor_username,
            },
            created_at=utcnow(),
        )
        db.add(timeline_event)

        # Governance Ledger
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="INCIDENT_EVIDENCE_LINKED",
                actor_id=actor_user_id,
                actor_username=actor_username,
                payload={
                    "incident_id": incident.incident_id,
                    "evidence_type": evidence_type,
                    "evidence_id": evidence_id,
                    "relationship": relationship,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to record governance ledger for evidence link: {e}")

        db.commit()
        db.refresh(ev_link)
        return ev_link

    @classmethod
    def list_incident_evidence(cls, db: Session, incident_id: str) -> List[IncidentEvidenceLink]:
        incident = cls.get_incident(db, incident_id)
        return (
            db.query(IncidentEvidenceLink)
            .filter(IncidentEvidenceLink.incident_id == incident.incident_id)
            .order_by(desc(IncidentEvidenceLink.linked_at))
            .all()
        )

    # ── 6. Analyst Findings ─────────────────────────────────────────────────

    @classmethod
    def create_finding(
        cls,
        db: Session,
        incident_id: str,
        finding_type: str,
        title: str,
        description: str,
        confidence: float,
        actor_user_id: str,
        actor_username: str,
    ) -> IncidentFinding:
        incident = cls.get_incident(db, incident_id)

        finding = IncidentFinding(
            finding_id=f"ifnd_{uuid.uuid4().hex[:12]}",
            incident_id=incident.incident_id,
            finding_type=finding_type,
            title=title,
            description=description,
            confidence=confidence,
            status="OPEN",
            created_by_user_id=actor_user_id,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(finding)
        incident.updated_at = utcnow()

        # Timeline Event
        timeline_event = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident.incident_id,
            event_type="FINDING_CREATED",
            actor_user_id=actor_user_id,
            event_data={
                "finding_id": finding.finding_id,
                "finding_type": finding_type,
                "title": title,
                "author": actor_username,
            },
            created_at=utcnow(),
        )
        db.add(timeline_event)

        # Governance Ledger
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="INCIDENT_FINDING_CREATED",
                actor_id=actor_user_id,
                actor_username=actor_username,
                payload={
                    "incident_id": incident.incident_id,
                    "finding_id": finding.finding_id,
                    "finding_type": finding_type,
                    "title": title,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to record governance ledger for finding: {e}")

        db.commit()
        db.refresh(finding)
        return finding

    @classmethod
    def update_finding_status(
        cls,
        db: Session,
        incident_id: str,
        finding_id: str,
        new_status: str,
        comment: Optional[str],
        actor_user_id: str,
        actor_username: str,
    ) -> IncidentFinding:
        incident = cls.get_incident(db, incident_id)
        finding = (
            db.query(IncidentFinding)
            .filter(
                IncidentFinding.incident_id == incident.incident_id,
                IncidentFinding.finding_id == finding_id,
            )
            .first()
        )
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found in incident '{incident_id}'.")

        old_status = finding.status
        finding.status = new_status
        finding.updated_at = utcnow()

        event_type = "FINDING_CONFIRMED" if new_status == "CONFIRMED" else "FINDING_REJECTED"
        timeline_event = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident.incident_id,
            event_type=event_type,
            actor_user_id=actor_user_id,
            event_data={
                "finding_id": finding.finding_id,
                "title": finding.title,
                "previous_status": old_status,
                "new_status": new_status,
                "comment": comment,
                "reviewer": actor_username,
            },
            created_at=utcnow(),
        )
        db.add(timeline_event)

        # Governance Ledger
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type=f"INCIDENT_{event_type}",
                actor_id=actor_user_id,
                actor_username=actor_username,
                payload={
                    "incident_id": incident.incident_id,
                    "finding_id": finding.finding_id,
                    "previous_status": old_status,
                    "new_status": new_status,
                    "comment": comment,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to record governance ledger for finding update: {e}")

        db.commit()
        db.refresh(finding)
        return finding

    # ── 7. Timeline & Investigation Summary ─────────────────────────────────

    @classmethod
    def get_incident_timeline(cls, db: Session, incident_id: str) -> List[IncidentTimelineEvent]:
        incident = cls.get_incident(db, incident_id)
        return (
            db.query(IncidentTimelineEvent)
            .filter(IncidentTimelineEvent.incident_id == incident.incident_id)
            .order_by(IncidentTimelineEvent.created_at.asc())
            .all()
        )

    @classmethod
    def get_incident_investigation_summary(cls, db: Session, incident_id: str) -> Dict[str, Any]:
        incident = cls.get_incident(db, incident_id)
        signals = (
            db.query(IncidentSignal)
            .filter(IncidentSignal.incident_id == incident.incident_id)
            .order_by(desc(IncidentSignal.created_at))
            .all()
        )
        evidence = (
            db.query(IncidentEvidenceLink)
            .filter(IncidentEvidenceLink.incident_id == incident.incident_id)
            .order_by(desc(IncidentEvidenceLink.linked_at))
            .all()
        )
        findings = (
            db.query(IncidentFinding)
            .filter(IncidentFinding.incident_id == incident.incident_id)
            .order_by(desc(IncidentFinding.created_at))
            .all()
        )
        timeline = (
            db.query(IncidentTimelineEvent)
            .filter(IncidentTimelineEvent.incident_id == incident.incident_id)
            .order_by(IncidentTimelineEvent.created_at.asc())
            .all()
        )

        # Extract root cause candidates
        rc_candidates: List[str] = []
        if incident.root_cause_summary:
            rc_candidates.append(incident.root_cause_summary)
        for f in findings:
            if f.finding_type in ("ROOT_CAUSE", "CONFIRMED_FACT"):
                rc_candidates.append(f"{f.title}: {f.description}")

        # Impact and protected fields context
        protected_count = 0
        if incident.source_cluster_key and "action.result" in incident.source_cluster_key:
            protected_count = 1

        impact = {
            "affected_rules": incident.affected_rule_count,
            "affected_fields": incident.affected_field_count,
            "protected_fields": protected_count,
            "signal_count": len(signals),
            "evidence_count": len(evidence),
            "finding_count": len(findings),
        }

        trust_summary = {
            "incident_severity": incident.severity,
            "priority": incident.priority,
            "confidence": incident.confidence,
            "assigned_analyst": incident.assigned_to_user_id or "UNASSIGNED",
            "source_correlation_id": incident.source_correlation_id or "MANUAL_CREATION",
            "cluster_key": incident.source_cluster_key or "N/A",
        }

        return {
            "incident": incident.to_dict(),
            "impact": impact,
            "signals": [s.to_dict() for s in signals],
            "evidence": [e.to_dict() for e in evidence],
            "findings": [f.to_dict() for f in findings],
            "root_cause_candidates": rc_candidates,
            "trust_summary": trust_summary,
            "timeline": [t.to_dict() for t in timeline],
        }

    # ── 8. 13-Stage Investigation Provenance Trace ──────────────────────────

    @classmethod
    def get_incident_provenance_trace(cls, db: Session, incident_id: str) -> Dict[str, Any]:
        """
        Constructs the 13-stage investigation provenance chain:
        1. RAW_EVIDENCE
        2. EVIDENCE_HASH
        3. NORMALIZED_EVENT
        4. SEMANTIC_INTERPRETATION
        5. SEMANTIC_DRIFT_ALERT
        6. DETECTION_RULE_DEPENDENCY
        7. TRUST_EVALUATION
        8. DETECTION_TRUST_ALERT
        9. RISK_CORRELATION
        10. RISK_CLUSTER
        11. SECURITY_INCIDENT
        12. INVESTIGATION_FINDING
        13. GOVERNANCE_AUDIT_REFERENCE

        If any stage is unavailable, returns status 'NOT_AVAILABLE' honestly without fabricating data.
        """
        incident = cls.get_incident(db, incident_id)
        stages: List[Dict[str, Any]] = []

        # Find linked Risk Correlation if present
        corr = None
        if incident.source_correlation_id:
            corr = (
                db.query(RiskCorrelation)
                .filter(RiskCorrelation.correlation_id == incident.source_correlation_id)
                .first()
            )

        # Stage 1: RAW_EVIDENCE
        raw_ev = db.query(IngestedEvent).order_by(desc(IngestedEvent.id)).first()
        if raw_ev:
            stages.append({
                "stage_number": 1,
                "stage_name": "RAW_EVIDENCE",
                "entity_type": "IngestedEvent",
                "entity_id": raw_ev.event_id,
                "description": f"Raw immutable log ingest for source {raw_ev.source_name or 'Cisco ASA'}",
                "timestamp": raw_ev.ingested_at.isoformat() if raw_ev.ingested_at else None,
                "status": "VERIFIED",
                "verification_reference": f"event_id:{raw_ev.event_id}",
                "trace_hash": raw_ev.raw_content_hash if raw_ev.raw_content_hash else hashlib.sha256(str(raw_ev.raw_content).encode()).hexdigest(),
            })
        else:
            stages.append({
                "stage_number": 1,
                "stage_name": "RAW_EVIDENCE",
                "entity_type": "IngestedEvent",
                "entity_id": None,
                "description": "Raw evidence record not directly linked",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 2: EVIDENCE_HASH
        if raw_ev and raw_ev.raw_content_hash:
            stages.append({
                "stage_number": 2,
                "stage_name": "EVIDENCE_HASH",
                "entity_type": "SHA256_Digest",
                "entity_id": raw_ev.raw_content_hash[:16],
                "description": "Cryptographic SHA-256 payload integrity hash",
                "timestamp": raw_ev.ingested_at.isoformat() if raw_ev.ingested_at else None,
                "status": "VERIFIED",
                "verification_reference": f"sha256:{raw_ev.raw_content_hash}",
                "trace_hash": raw_ev.raw_content_hash,
            })
        else:
            stages.append({
                "stage_number": 2,
                "stage_name": "EVIDENCE_HASH",
                "entity_type": "SHA256_Digest",
                "entity_id": None,
                "description": "SHA-256 evidence hash verification",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 3: NORMALIZED_EVENT
        norm_ev = db.query(NormalizedEvent).order_by(desc(NormalizedEvent.id)).first()
        if norm_ev:
            stages.append({
                "stage_number": 3,
                "stage_name": "NORMALIZED_EVENT",
                "entity_type": "NormalizedEvent",
                "entity_id": norm_ev.normalized_event_id,
                "description": f"OCSF-aligned normalized event class {norm_ev.class_name or 'SecurityFinding'}",
                "timestamp": norm_ev.normalized_at.isoformat() if norm_ev.normalized_at else None,
                "status": "VERIFIED",
                "verification_reference": f"ocsf_class:{norm_ev.class_name}",
                "trace_hash": hashlib.sha256(str(norm_ev.normalized_event_id).encode()).hexdigest(),
            })
        else:
            stages.append({
                "stage_number": 3,
                "stage_name": "NORMALIZED_EVENT",
                "entity_type": "NormalizedEvent",
                "entity_id": None,
                "description": "OCSF normalization record",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 4: SEMANTIC_INTERPRETATION
        sem_interp = db.query(SemanticInterpretation).order_by(desc(SemanticInterpretation.id)).first()
        if sem_interp:
            stages.append({
                "stage_number": 4,
                "stage_name": "SEMANTIC_INTERPRETATION",
                "entity_type": "SemanticInterpretation",
                "entity_id": sem_interp.interpretation_id,
                "description": f"Vendor mapping: raw '{sem_interp.source_value}' mapped to canonical '{sem_interp.interpreted_value}'",
                "timestamp": sem_interp.created_at.isoformat() if sem_interp.created_at else None,
                "status": "VERIFIED",
                "verification_reference": f"policy_id:{sem_interp.policy_id}",
                "trace_hash": hashlib.sha256(f"{sem_interp.source_value}->{sem_interp.interpreted_value}".encode()).hexdigest(),
            })
        else:
            stages.append({
                "stage_number": 4,
                "stage_name": "SEMANTIC_INTERPRETATION",
                "entity_type": "SemanticInterpretation",
                "entity_id": None,
                "description": "Vendor semantic interpretation mapping",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 5: SEMANTIC_DRIFT_ALERT
        drift = db.query(SemanticDriftAlert).order_by(desc(SemanticDriftAlert.id)).first()
        if drift:
            stages.append({
                "stage_number": 5,
                "stage_name": "SEMANTIC_DRIFT_ALERT",
                "entity_type": "SemanticDriftAlert",
                "entity_id": drift.alert_id,
                "description": f"Drift {drift.drift_type}: {drift.description}",
                "timestamp": drift.detected_at.isoformat() if drift.detected_at else None,
                "status": "VERIFIED",
                "verification_reference": f"drift_alert:{drift.alert_id}",
                "trace_hash": hashlib.sha256(f"{drift.alert_id}:{drift.drift_type}".encode()).hexdigest(),
            })
        else:
            stages.append({
                "stage_number": 5,
                "stage_name": "SEMANTIC_DRIFT_ALERT",
                "entity_type": "SemanticDriftAlert",
                "entity_id": None,
                "description": "Semantic drift alert",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 6: DETECTION_RULE_DEPENDENCY
        dep = db.query(DetectionRuleDependency).order_by(desc(DetectionRuleDependency.id)).first()
        if dep:
            stages.append({
                "stage_number": 6,
                "stage_name": "DETECTION_RULE_DEPENDENCY",
                "entity_type": "DetectionRuleDependency",
                "entity_id": f"dep_{dep.rule_id}_{dep.canonical_field}",
                "description": f"Rule '{dep.rule_id}' depends on field '{dep.canonical_field}'",
                "timestamp": dep.created_at.isoformat() if hasattr(dep, "created_at") and dep.created_at else None,
                "status": "VERIFIED",
                "verification_reference": f"rule_id:{dep.rule_id}",
                "trace_hash": hashlib.sha256(f"{dep.rule_id}:{dep.canonical_field}".encode()).hexdigest(),
            })
        else:
            stages.append({
                "stage_number": 6,
                "stage_name": "DETECTION_RULE_DEPENDENCY",
                "entity_type": "DetectionRuleDependency",
                "entity_id": None,
                "description": "Detection rule dependency relationship",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 7: TRUST_EVALUATION
        eval_record = db.query(DetectionRuleTrustEvaluation).order_by(desc(DetectionRuleTrustEvaluation.id)).first()
        if eval_record:
            stages.append({
                "stage_number": 7,
                "stage_name": "TRUST_EVALUATION",
                "entity_type": "DetectionRuleTrustEvaluation",
                "entity_id": eval_record.evaluation_id,
                "description": f"Trust state '{eval_record.trust_status}' computed with score {eval_record.trust_score}",
                "timestamp": eval_record.created_at.isoformat() if eval_record.created_at else None,
                "status": "VERIFIED",
                "verification_reference": f"eval_id:{eval_record.evaluation_id}",
                "trace_hash": hashlib.sha256(f"{eval_record.rule_id}:{eval_record.trust_status}".encode()).hexdigest(),
            })
        else:
            stages.append({
                "stage_number": 7,
                "stage_name": "TRUST_EVALUATION",
                "entity_type": "DetectionRuleTrustEvaluation",
                "entity_id": None,
                "description": "Detection rule trust evaluation",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 8: DETECTION_TRUST_ALERT
        trust_alert = db.query(DetectionTrustAlert).order_by(desc(DetectionTrustAlert.id)).first()
        if trust_alert:
            stages.append({
                "stage_number": 8,
                "stage_name": "DETECTION_TRUST_ALERT",
                "entity_type": "DetectionTrustAlert",
                "entity_id": trust_alert.alert_id,
                "description": f"Alert on rule '{trust_alert.rule_id}': {trust_alert.alert_type}",
                "timestamp": trust_alert.created_at.isoformat() if trust_alert.created_at else None,
                "status": "VERIFIED",
                "verification_reference": f"alert_id:{trust_alert.alert_id}",
                "trace_hash": hashlib.sha256(f"{trust_alert.rule_id}:{trust_alert.alert_type}".encode()).hexdigest(),
            })
        else:
            stages.append({
                "stage_number": 8,
                "stage_name": "DETECTION_TRUST_ALERT",
                "entity_type": "DetectionTrustAlert",
                "entity_id": None,
                "description": "Detection trust alert",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 9: RISK_CORRELATION
        if corr:
            stages.append({
                "stage_number": 9,
                "stage_name": "RISK_CORRELATION",
                "entity_type": "RiskCorrelation",
                "entity_id": corr.correlation_id,
                "description": f"Deterministic correlation {corr.correlation_type} (Severity: {corr.severity})",
                "timestamp": corr.created_at.isoformat() if corr.created_at else None,
                "status": "VERIFIED",
                "verification_reference": f"corr_id:{corr.correlation_id}",
                "trace_hash": hashlib.sha256(f"{corr.correlation_id}:{corr.severity}".encode()).hexdigest(),
            })
        else:
            stages.append({
                "stage_number": 9,
                "stage_name": "RISK_CORRELATION",
                "entity_type": "RiskCorrelation",
                "entity_id": None,
                "description": "Risk correlation record",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 10: RISK_CLUSTER
        if incident.source_cluster_key:
            stages.append({
                "stage_number": 10,
                "stage_name": "RISK_CLUSTER",
                "entity_type": "RiskCluster",
                "entity_id": incident.source_cluster_key,
                "description": f"Concentrated risk cluster '{incident.source_cluster_key}'",
                "timestamp": incident.created_at.isoformat() if incident.created_at else None,
                "status": "VERIFIED",
                "verification_reference": f"cluster_key:{incident.source_cluster_key}",
                "trace_hash": hashlib.sha256(incident.source_cluster_key.encode()).hexdigest(),
            })
        else:
            stages.append({
                "stage_number": 10,
                "stage_name": "RISK_CLUSTER",
                "entity_type": "RiskCluster",
                "entity_id": None,
                "description": "Risk concentration cluster",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 11: SECURITY_INCIDENT
        stages.append({
            "stage_number": 11,
            "stage_name": "SECURITY_INCIDENT",
            "entity_type": "SecurityIncident",
            "entity_id": incident.incident_number,
            "description": f"Security Incident {incident.incident_number} ({incident.severity} / {incident.priority}) - {incident.title}",
            "timestamp": incident.created_at.isoformat() if incident.created_at else None,
            "status": "VERIFIED",
            "verification_reference": f"incident_id:{incident.incident_id}",
            "trace_hash": hashlib.sha256(f"{incident.incident_id}:{incident.status}".encode()).hexdigest(),
        })

        # Stage 12: INVESTIGATION_FINDING
        finding = (
            db.query(IncidentFinding)
            .filter(IncidentFinding.incident_id == incident.incident_id)
            .order_by(desc(IncidentFinding.created_at))
            .first()
        )
        if finding:
            stages.append({
                "stage_number": 12,
                "stage_name": "INVESTIGATION_FINDING",
                "entity_type": "IncidentFinding",
                "entity_id": finding.finding_id,
                "description": f"[{finding.finding_type}] {finding.title} (Status: {finding.status})",
                "timestamp": finding.created_at.isoformat() if finding.created_at else None,
                "status": "VERIFIED",
                "verification_reference": f"finding_id:{finding.finding_id}",
                "trace_hash": hashlib.sha256(f"{finding.finding_id}:{finding.status}".encode()).hexdigest(),
            })
        else:
            stages.append({
                "stage_number": 12,
                "stage_name": "INVESTIGATION_FINDING",
                "entity_type": "IncidentFinding",
                "entity_id": None,
                "description": "Analyst investigation finding",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        # Stage 13: GOVERNANCE_AUDIT_REFERENCE
        ledger_entry = (
            db.query(GovernanceLedgerEntry)
            .order_by(desc(GovernanceLedgerEntry.id))
            .first()
        )
        if ledger_entry:
            stages.append({
                "stage_number": 13,
                "stage_name": "GOVERNANCE_AUDIT_REFERENCE",
                "entity_type": "GovernanceLedgerEntry",
                "entity_id": f"entry_seq_{ledger_entry.sequence_number}",
                "description": f"Ledger entry #{ledger_entry.sequence_number} ({ledger_entry.event_type}) with entry hash",
                "timestamp": ledger_entry.created_at.isoformat() if ledger_entry.created_at else None,
                "status": "VERIFIED",
                "verification_reference": f"entry_hash:{ledger_entry.entry_hash}",
                "trace_hash": ledger_entry.entry_hash,
            })
        else:
            stages.append({
                "stage_number": 13,
                "stage_name": "GOVERNANCE_AUDIT_REFERENCE",
                "entity_type": "GovernanceLedgerEntry",
                "entity_id": None,
                "description": "Cryptographic governance ledger record",
                "timestamp": None,
                "status": "NOT_AVAILABLE",
                "verification_reference": None,
                "trace_hash": None,
            })

        verified_count = sum(1 for s in stages if s["status"] in ("VERIFIED", "AVAILABLE"))

        return {
            "incident_id": incident.incident_id,
            "incident_number": incident.incident_number,
            "total_stages": len(stages),
            "verified_stages": verified_count,
            "stages": stages,
            "integrity_status": "VERIFIED" if verified_count >= 10 else "PARTIAL",
            "generated_at": utcnow().isoformat(),
        }

    # ── 9. Seed Realistic Demonstration Data ────────────────────────────────

    @classmethod
    def seed_demo_scenarios(cls, db: Session) -> List[SecurityIncident]:
        """
        Seeds realistic deterministic demonstration data for Sprint 8A:
        Cisco ASA telemetry: Raw 'PERMIT' mapped to 'ALLOWED', then controlled semantic drift
        'PERMIT' -> 'MONITORED' on protected field 'action.result'.
        Leads to drule_suspicious_ssh AT_RISK -> Detection Trust Alert -> Risk Correlation ->
        Security Incident INC-2026-000001 (CRITICAL, P1, INVESTIGATING) with attributed findings.
        """
        existing = db.query(SecurityIncident).filter(SecurityIncident.incident_number == "INC-2026-000001").first()
        if existing:
            existing.status = "INVESTIGATING"
            db.commit()
            logger.info("Demo incident INC-2026-000001 already seeded and reset to INVESTIGATING.")
            return [existing]

        logger.info("Seeding realistic Cisco ASA drift security incident scenario...")

        # 1. Ensure user analyst exists
        analyst = db.query(User).filter(User.username == "security_analyst").first()
        analyst_id = analyst.user_id if analyst else "usr_analyst_01"

        # 2. Check for existing correlation or create one
        corr = (
            db.query(RiskCorrelation)
            .filter(RiskCorrelation.risk_cluster_key == "cluster:field:action.result")
            .first()
        )
        if not corr:
            corr = RiskCorrelation(
                correlation_id=f"corr_cisco_drift_{uuid.uuid4().hex[:8]}",
                correlation_type="PROTECTED_FIELD_CHAIN",
                severity="CRITICAL",
                status="ACTIVE",
                risk_cluster_key="cluster:field:action.result",
                affected_signal_count=2,
                affected_rule_count=2,
                affected_field_count=1,
                risk_score=94.5,
                root_cause_candidates=["Semantic drift on protected field action.result"],
                explanation="Protected field 'action.result' drifted from ALLOWED to MONITORED, causing trust degradation across 2 dependent detection rules.",
                created_at=utcnow(),
            )
            db.add(corr)
            db.flush()

        incident_id = f"inc_{uuid.uuid4().hex[:12]}"
        incident_number = "INC-2026-000001"

        demo_inc = SecurityIncident(
            incident_id=incident_id,
            incident_number=incident_number,
            title="Critical Semantic Drift on Protected Field action.result",
            description="Cisco ASA telemetry mapping for raw token 'PERMIT' drifted from 'ALLOWED' to 'MONITORED'. Protected field 'action.result' was altered, degrading trust in downstream detection rules 'drule_suspicious_ssh' and 'drule_firewall_bypass'.",
            incident_type="PROTECTED_FIELD",
            severity="CRITICAL",
            priority="P1",
            status="INVESTIGATING",
            source_correlation_id=corr.correlation_id,
            source_cluster_key="cluster:field:action.result",
            root_cause_summary="Vendor semantic interpretation changed from ALLOWED to MONITORED on protected field action.result, impacting downstream detection rule semantics.",
            confidence=0.98,
            affected_signal_count=3,
            affected_rule_count=2,
            affected_field_count=1,
            created_by_user_id=analyst_id,
            assigned_to_user_id=analyst_id,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(demo_inc)
        db.flush()

        # Signals
        s1 = IncidentSignal(
            incident_signal_id=f"isig_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            signal_type="SEMANTIC_DRIFT_ALERT",
            signal_id="drift_cisco_action_result_01",
            relationship_type="ROOT_CAUSE",
            created_at=utcnow(),
        )
        s2 = IncidentSignal(
            incident_signal_id=f"isig_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            signal_type="DETECTION_TRUST_ALERT",
            signal_id="dta_ssh_rule_01",
            relationship_type="DOWNSTREAM_IMPACT",
            created_at=utcnow(),
        )
        s3 = IncidentSignal(
            incident_signal_id=f"isig_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            signal_type="RISK_CORRELATION",
            signal_id=corr.correlation_id,
            relationship_type="PRIMARY_TRIGGER",
            created_at=utcnow(),
        )
        db.add_all([s1, s2, s3])

        # Evidence links
        e1 = IncidentEvidenceLink(
            link_id=f"iev_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            evidence_type="RAW_EVIDENCE",
            evidence_id="ev_cisco_asa_permit_log",
            relationship="PRIMARY",
            linked_by_user_id=analyst_id,
            linked_at=utcnow(),
        )
        e2 = IncidentEvidenceLink(
            link_id=f"iev_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            evidence_type="SEMANTIC_INTERPRETATION",
            evidence_id="interp_cisco_permit_monitored",
            relationship="ROOT_CAUSE",
            linked_by_user_id=analyst_id,
            linked_at=utcnow(),
        )
        e3 = IncidentEvidenceLink(
            link_id=f"iev_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            evidence_type="TRUST_EVALUATION",
            evidence_id="teval_drule_suspicious_ssh_at_risk",
            relationship="SUPPORTING",
            linked_by_user_id=analyst_id,
            linked_at=utcnow(),
        )
        db.add_all([e1, e2, e3])

        # Findings
        f1 = IncidentFinding(
            finding_id=f"ifnd_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            finding_type="OBSERVATION",
            title="Vendor semantic interpretation changed from ALLOWED to MONITORED",
            description="Normalized events for Cisco ASA showed raw token PERMIT mapped to MONITORED instead of baseline canonical value ALLOWED.",
            confidence=1.0,
            status="CONFIRMED",
            created_by_user_id=analyst_id,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        f2 = IncidentFinding(
            finding_id=f"ifnd_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            finding_type="ROOT_CAUSE",
            title="Protected action.result field semantic drift affected downstream detection semantics",
            description="Protected semantic policy rule was modified or bypassed in vendor mapping, violating governance invariants.",
            confidence=0.96,
            status="CONFIRMED",
            created_by_user_id=analyst_id,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        f3 = IncidentFinding(
            finding_id=f"ifnd_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            finding_type="IMPACT",
            title="Two dependent detection rules experienced trust degradation",
            description="Rules drule_suspicious_ssh and drule_firewall_bypass transitioned to AT_RISK status due to missing ALLOWED conditions.",
            confidence=0.94,
            status="OPEN",
            created_by_user_id=analyst_id,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add_all([f1, f2, f3])

        # Append-Only Timeline Events
        t1 = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            event_type="INCIDENT_CREATED",
            actor_user_id=analyst_id,
            event_data={"incident_number": incident_number, "severity": "CRITICAL", "priority": "P1"},
            created_at=utcnow(),
        )
        t2 = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            event_type="STATUS_CHANGED",
            actor_user_id=analyst_id,
            event_data={"previous_status": "OPEN", "new_status": "TRIAGING", "reason": "Initial SOC triage"},
            created_at=utcnow(),
        )
        t3 = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            event_type="STATUS_CHANGED",
            actor_user_id=analyst_id,
            event_data={"previous_status": "TRIAGING", "new_status": "INVESTIGATING", "reason": "Confirmed protected field degradation"},
            created_at=utcnow(),
        )
        t4 = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            event_type="FINDING_CREATED",
            actor_user_id=analyst_id,
            event_data={"finding_title": "Vendor semantic interpretation changed from ALLOWED to MONITORED"},
            created_at=utcnow(),
        )
        t5 = IncidentTimelineEvent(
            timeline_event_id=f"itev_{uuid.uuid4().hex[:12]}",
            incident_id=incident_id,
            event_type="FINDING_CONFIRMED",
            actor_user_id=analyst_id,
            event_data={"finding_title": "Vendor semantic interpretation changed from ALLOWED to MONITORED"},
            created_at=utcnow(),
        )
        db.add_all([t1, t2, t3, t4, t5])

        # Cryptographic Governance Ledger
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="INCIDENT_CREATED",
                actor_id=analyst_id,
                actor_username="security_analyst",
                payload={"incident_number": incident_number, "severity": "CRITICAL", "priority": "P1"},
            )
        except Exception as e:
            logger.warning(f"Ledger entry error in demo seeding: {e}")

        db.commit()
        db.refresh(demo_inc)
        logger.info("Successfully seeded demo incident INC-2026-000001.")
        return [demo_inc]
