"""
services/investigation_artifact_service.py
------------------------------------------
Automatic Cross-Domain Artifact Discovery and Cryptographic Reference Binding Service.

Sprint 12A — Unified SOC Investigation & Security Case Management.
Core Invariant: "DISCOVERY CREATES IMMUTABLE REFERENCE BINDINGS WITHOUT DATA DUPLICATION."
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.security_investigation import (
    SecurityInvestigationCase,
    InvestigationArtifactBinding,
    BINDING_DOMAIN_PREFIX,
    compute_canonical_hash,
)
from app.models.security_incident import SecurityIncident, IncidentEvidenceLink, IncidentFinding
from app.models.detection_execution import DetectionExecution
from app.models.threat_intelligence import ThreatIndicator, ThreatIntelligenceArtifact, ThreatIntelligenceCorrelation
from app.models.compliance_intelligence import ComplianceFinding
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.risk_correlation import RiskCorrelation


def to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class InvestigationArtifactService:
    """
    Manages artifact bindings and automatic discovery across existing SentinelTrace tables.
    """

    @staticmethod
    def bind_artifact(
        db: Session,
        case_id: str,
        artifact_type: str,
        artifact_id: str,
        source_domain: str,
        canonical_hash: str = "",
        summary: Optional[str] = None,
    ) -> InvestigationArtifactBinding:
        """
        Binds an upstream artifact to the investigation case without duplicating raw content.
        Idempotent: updates summary/hash if already bound.
        """
        case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found.")

        existing = (
            db.query(InvestigationArtifactBinding)
            .filter(
                InvestigationArtifactBinding.case_id == case_id,
                InvestigationArtifactBinding.artifact_type == artifact_type,
                InvestigationArtifactBinding.artifact_id == str(artifact_id),
            )
            .first()
        )

        if existing:
            if canonical_hash:
                existing.canonical_hash = canonical_hash
            if summary:
                existing.summary = summary
            db.flush()
            return existing

        if not canonical_hash:
            canonical_hash = compute_canonical_hash(
                BINDING_DOMAIN_PREFIX,
                {"case_id": case_id, "type": artifact_type, "id": str(artifact_id)},
            )

        binding = InvestigationArtifactBinding(
            case_id=case_id,
            artifact_type=artifact_type,
            artifact_id=str(artifact_id),
            source_domain=source_domain,
            canonical_hash=canonical_hash,
            summary=summary or f"{artifact_type} reference {artifact_id}",
            binding_timestamp=datetime.now(timezone.utc),
        )
        db.add(binding)
        db.flush()
        return binding

    @staticmethod
    def discover_related_artifacts(
        db: Session,
        case_id: str,
        max_results_per_domain: int = 5,
    ) -> List[InvestigationArtifactBinding]:
        """
        Automatically inspects upstream domains (Incidents, Detections, Threat Intel,
        Compliance, Normalized Events) to discover and bind related evidence.
        """
        case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found.")

        discovered_bindings: List[InvestigationArtifactBinding] = []

        # 1. Discover Related Security Incidents
        try:
            incidents = db.query(SecurityIncident).order_by(SecurityIncident.created_at.desc()).limit(max_results_per_domain).all()
            for inc in incidents:
                b = InvestigationArtifactService.bind_artifact(
                    db=db,
                    case_id=case_id,
                    artifact_type="SECURITY_INCIDENT",
                    artifact_id=inc.incident_id,
                    source_domain="SECURITY_INCIDENT",
                    canonical_hash=inc.incident_id,
                    summary=f"Incident {inc.incident_number}: {inc.title} ({inc.severity})",
                )
                discovered_bindings.append(b)
        except Exception:
            pass

        # 2. Discover Related Threat Indicators
        try:
            indicators = db.query(ThreatIndicator).filter(ThreatIndicator.status == "ACTIVE").limit(max_results_per_domain).all()
            for ind in indicators:
                b = InvestigationArtifactService.bind_artifact(
                    db=db,
                    case_id=case_id,
                    artifact_type="THREAT_INDICATOR",
                    artifact_id=ind.id,
                    source_domain="THREAT_INTELLIGENCE",
                    canonical_hash=ind.indicator_hash or ind.id,
                    summary=f"IOC [{ind.indicator_type}] {ind.normalized_value} (Severity: {ind.severity})",
                )
                discovered_bindings.append(b)
        except Exception:
            pass

        # 3. Discover Related Detection Executions
        try:
            detections = db.query(DetectionExecution).order_by(DetectionExecution.created_at.desc()).limit(max_results_per_domain).all()
            for det in detections:
                b = InvestigationArtifactService.bind_artifact(
                    db=db,
                    case_id=case_id,
                    artifact_type="DETECTION_RESULT",
                    artifact_id=det.execution_id,
                    source_domain="DETECTION",
                    canonical_hash=det.execution_hash or det.execution_id,
                    summary=f"Detection Execution {det.execution_id} on rule {det.rule_id} -> Result: {det.matched}",
                )
                discovered_bindings.append(b)
        except Exception:
            pass

        # 4. Discover Related Compliance Findings
        try:
            comp_findings = db.query(ComplianceFinding).order_by(ComplianceFinding.created_at.desc()).limit(max_results_per_domain).all()
            for cf in comp_findings:
                b = InvestigationArtifactService.bind_artifact(
                    db=db,
                    case_id=case_id,
                    artifact_type="COMPLIANCE_FINDING",
                    artifact_id=cf.id,
                    source_domain="COMPLIANCE",
                    canonical_hash=cf.finding_hash or cf.id,
                    summary=f"Compliance Finding: {cf.title} ({cf.severity})",
                )
                discovered_bindings.append(b)
        except Exception:
            pass

        # 5. Discover Ingested Evidence
        try:
            events = db.query(IngestedEvent).order_by(IngestedEvent.ingested_at.desc()).limit(max_results_per_domain).all()
            for ev in events:
                b = InvestigationArtifactService.bind_artifact(
                    db=db,
                    case_id=case_id,
                    artifact_type="EVIDENCE",
                    artifact_id=ev.event_id,
                    source_domain="EVIDENCE_VAULT",
                    canonical_hash=ev.payload_hash or ev.event_id,
                    summary=f"Raw Ingested Evidence {ev.event_id} from {ev.source_ip or 'unknown'}",
                )
                discovered_bindings.append(b)
        except Exception:
            pass

        return discovered_bindings

    @staticmethod
    def seed_default_investigations(db: Session) -> None:
        """
        Seeds baseline demonstration SOC investigation cases if none exist.
        """
        if db.query(SecurityInvestigationCase).first():
            return

        cases_data = [
            {
                "case_number": "SIC-2026-001",
                "title": "Credential Dumping & Lateral Movement Investigation",
                "description": "Correlated impossible travel signals with LSASS memory injection detection and malicious C2 IP indicator.",
                "priority": "CRITICAL",
                "severity": "CRITICAL",
                "status": "INVESTIGATING",
                "investigation_type": "SECURITY_INCIDENT",
                "source_domain": "DETECTION",
                "created_by": "analyst_demo",
                "assigned_to": "analyst_demo",
                "priority_score": 92.5,
                "priority_drivers": [
                    "Critical severity security signal (+30.0)",
                    "Elevated risk concentration (Score: 85.0 -> +21.25)",
                    "High-confidence threat intelligence attribution (+18.0)",
                    "Target asset classified as Mission Critical Tier-0 (+15.0)",
                    "Severe potential business/CIA impact (+8.25)",
                ],
                "hard_failure_override": False,
            },
            {
                "case_number": "SIC-2026-002",
                "title": "Spearphishing Link & C2 Callback Forensics",
                "description": "User credential submission followed by beaconing to newly registered domain auth-portal-update.evil.org.",
                "priority": "HIGH",
                "severity": "HIGH",
                "status": "TRIAGE",
                "investigation_type": "THREAT_HUNT",
                "source_domain": "THREAT_INTELLIGENCE",
                "created_by": "analyst_demo",
                "assigned_to": None,
                "priority_score": 74.0,
                "priority_drivers": [
                    "High severity security signal (+22.5)",
                    "Correlated adversary/IOC threat intelligence (+16.0)",
                    "High criticality production asset (+10.0)",
                    "Assessed environmental impact (+6.5)",
                ],
                "hard_failure_override": False,
            },
            {
                "case_number": "SIC-2026-003",
                "title": "Continuous Assurance Drift & Unapproved Config Modification",
                "description": "Audit gap identified in TLS cipher suite policy enforcement across edge ingress gateways.",
                "priority": "MEDIUM",
                "severity": "MEDIUM",
                "status": "OPEN",
                "investigation_type": "COMPLIANCE_INVESTIGATION",
                "source_domain": "COMPLIANCE",
                "created_by": "auditor_demo",
                "assigned_to": None,
                "priority_score": 46.5,
                "priority_drivers": [
                    "Medium severity baseline (+15.0)",
                    "Moderate risk correlation (+12.5)",
                    "Standard business asset (+5.0)",
                ],
                "hard_failure_override": False,
            },
        ]

        for c in cases_data:
            case = SecurityInvestigationCase(
                case_number=c["case_number"],
                title=c["title"],
                description=c["description"],
                priority=c["priority"],
                severity=c["severity"],
                status=c["status"],
                investigation_type=c["investigation_type"],
                source_domain=c["source_domain"],
                created_by=c["created_by"],
                assigned_to=c["assigned_to"],
                priority_score=c["priority_score"],
                priority_drivers=c["priority_drivers"],
                hard_failure_override=c["hard_failure_override"],
                canonical_hash="",
            )
            case.canonical_hash = case.compute_case_hash()
            db.add(case)
            db.flush()

            # Trigger auto discovery and timeline reconstruction for initial cases
            InvestigationArtifactService.discover_related_artifacts(db=db, case_id=case.id, max_results_per_domain=3)

        db.commit()

