"""
models/security_investigation.py
---------------------------------
SQLAlchemy ORM models for Unified SOC Investigation & Security Case Management.

Sprint 12A — Unified SOC Investigation & Security Case Management.
Core Invariant: "EVERY SECURITY INVESTIGATION MUST BE TRACEABLE FROM THE ANALYST QUESTION BACK TO CRYPTOGRAPHICALLY VERIFIABLE EVIDENCE."

Zero-Trust Rules:
- UNKNOWN != SAFE
- IOC MATCH != CONFIRMED ATTACK
- ALERT != INCIDENT
- INCIDENT != ROOT CAUSE
- CORRELATION != CAUSATION
- CASE CLOSED != SECURITY RECOVERED
- ANALYST ACTION != VERIFIED FACT
- CRYPTOGRAPHIC FAILURE STRICTLY FORCES CRITICAL PRIORITY
"""

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship as orm_relationship
from sqlalchemy.types import JSON

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


INVESTIGATION_DOMAIN_PREFIX = "SENTINELTRACE_INVESTIGATION_CASE_V1"
BINDING_DOMAIN_PREFIX = "SENTINELTRACE_INVESTIGATION_BINDING_V1"
HYPOTHESIS_DOMAIN_PREFIX = "SENTINELTRACE_INVESTIGATION_HYPOTHESIS_V1"
FINDING_DOMAIN_PREFIX = "SENTINELTRACE_INVESTIGATION_FINDING_V1"
TIMELINE_DOMAIN_PREFIX = "SENTINELTRACE_INVESTIGATION_TIMELINE_V1"
IMPACT_DOMAIN_PREFIX = "SENTINELTRACE_INVESTIGATION_IMPACT_V1"
RESOLUTION_DOMAIN_PREFIX = "SENTINELTRACE_INVESTIGATION_RESOLUTION_V1"
PROVENANCE_DOMAIN_PREFIX = "SENTINELTRACE_INVESTIGATION_PROVENANCE_V1"


def compute_canonical_hash(prefix: str, payload: Dict[str, Any]) -> str:
    """Deterministic SHA-256 computation over canonical JSON."""
    raw = prefix + ":" + json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SecurityInvestigationCase(Base):
    """
    Central SOC investigation case entity that unifies evidence, normalization,
    detections, risks, incidents, compliance, threat intel, and assurance into a single governed case.
    """

    __tablename__ = "security_investigation_cases"
    __table_args__ = (
        Index("ix_sic_case_number", "case_number", unique=True),
        Index("ix_sic_status", "status"),
        Index("ix_sic_priority", "priority"),
        Index("ix_sic_severity", "severity"),
        Index("ix_sic_investigation_type", "investigation_type"),
        Index("ix_sic_source_domain", "source_domain"),
        Index("ix_sic_assigned_to", "assigned_to"),
        Index("ix_sic_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sic-{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the investigation case",
    )
    case_number = Column(
        String(32),
        nullable=False,
        unique=True,
        comment="Human-readable case identifier e.g. SIC-2026-001",
    )
    title = Column(
        String(255),
        nullable=False,
        comment="Title / summary of the SOC investigation",
    )
    description = Column(
        Text,
        nullable=False,
        comment="Detailed case description or investigative hypothesis",
    )
    priority = Column(
        String(32),
        nullable=False,
        default="MEDIUM",
        comment="CRITICAL, HIGH, MEDIUM, LOW",
    )
    severity = Column(
        String(32),
        nullable=False,
        default="MEDIUM",
        comment="CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL",
    )
    status = Column(
        String(32),
        nullable=False,
        default="OPEN",
        comment="OPEN, TRIAGE, INVESTIGATING, AWAITING_REVIEW, RESOLVED, CLOSED",
    )
    investigation_type = Column(
        String(64),
        nullable=False,
        default="SECURITY_INCIDENT",
        comment="SECURITY_INCIDENT, THREAT_HUNT, ANOMALOUS_BEHAVIOR, COMPLIANCE_INVESTIGATION, EVIDENCE_FORENSICS, DATA_EXFILTRATION, CREDENTIAL_ACCESS, PROACTIVE_ANALYSIS",
    )
    source_domain = Column(
        String(64),
        nullable=False,
        default="DETECTION",
        comment="DETECTION, THREAT_INTELLIGENCE, RISK, INCIDENT, COMPLIANCE, EVIDENCE, MANUAL",
    )
    created_by = Column(
        String(64),
        nullable=False,
        default="SYSTEM",
        comment="User ID who initiated the investigation",
    )
    assigned_to = Column(
        String(64),
        nullable=True,
        comment="User ID of assigned lead investigator",
    )
    opened_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        comment="Timestamp when investigation case was opened",
    )
    closed_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when case was formally resolved and closed",
    )
    resolution = Column(
        String(64),
        nullable=True,
        comment="TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_ACTIVITY, SECURITY_INCIDENT, INCONCLUSIVE, INSUFFICIENT_EVIDENCE",
    )
    resolution_notes = Column(
        Text,
        nullable=True,
        comment="Final analyst resolution summary and closing remarks",
    )
    priority_score = Column(
        Float,
        nullable=False,
        default=50.0,
        comment="Deterministic priority score (0.0 to 100.0)",
    )
    priority_drivers = Column(
        JSON,
        nullable=False,
        default=list,
        comment="Itemized explainability drivers for the calculated priority score",
    )
    hard_failure_override = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if cryptographic integrity failure forced priority to CRITICAL",
    )
    canonical_hash = Column(
        String(64),
        nullable=False,
        default="",
        comment="SHA-256 hash sealing initial case state",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    # Relationships
    artifact_bindings = orm_relationship("InvestigationArtifactBinding", back_populates="case", cascade="all, delete-orphan")
    hypotheses = orm_relationship("InvestigationHypothesis", back_populates="case", cascade="all, delete-orphan")
    findings = orm_relationship("InvestigationFinding", back_populates="case", cascade="all, delete-orphan")
    timeline_events = orm_relationship("InvestigationTimelineEvent", back_populates="case", cascade="all, delete-orphan")
    impact_assessments = orm_relationship("InvestigationImpactAssessment", back_populates="case", cascade="all, delete-orphan")
    reviews = orm_relationship("InvestigationReview", back_populates="case", cascade="all, delete-orphan")
    resolutions = orm_relationship("InvestigationCaseResolution", back_populates="case", cascade="all, delete-orphan")
    provenance_records = orm_relationship("InvestigationProvenanceRecord", back_populates="case", cascade="all, delete-orphan")

    def compute_case_hash(self) -> str:
        payload = {
            "id": self.id,
            "case_number": self.case_number,
            "title": self.title,
            "priority": self.priority,
            "severity": self.severity,
            "investigation_type": self.investigation_type,
            "source_domain": self.source_domain,
            "created_by": self.created_by,
            "opened_at": self.opened_at.isoformat() if self.opened_at else "",
        }
        return compute_canonical_hash(INVESTIGATION_DOMAIN_PREFIX, payload)


class InvestigationArtifactBinding(Base):
    """
    Immutable reference binding pointing to existing platform artifacts across domains.
    Stores cryptographic hashes and references WITHOUT duplicating raw artifact data.
    """

    __tablename__ = "investigation_artifact_bindings"
    __table_args__ = (
        Index("ix_iab_case_id", "case_id"),
        Index("ix_iab_artifact_type", "artifact_type"),
        Index("ix_iab_artifact_id", "artifact_id"),
        Index("ix_iab_source_domain", "source_domain"),
        UniqueConstraint("case_id", "artifact_type", "artifact_id", name="uq_case_artifact_binding"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"iab-{uuid.uuid4().hex[:12]}",
    )
    case_id = Column(
        String(64),
        ForeignKey("sentinel.security_investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    artifact_type = Column(
        String(64),
        nullable=False,
        comment="EVIDENCE, NORMALIZED_EVENT, SEMANTIC_INTERPRETATION, DETECTION_RULE, DETECTION_RESULT, RISK_CORRELATION, SECURITY_INCIDENT, THREAT_INDICATOR, THREAT_ACTOR, THREAT_CAMPAIGN, COMPLIANCE_FINDING, REMEDIATION_CASE, SCENARIO_EXECUTION",
    )
    artifact_id = Column(
        String(128),
        nullable=False,
        comment="Primary key or unique identifier of the bound upstream artifact",
    )
    source_domain = Column(
        String(64),
        nullable=False,
        comment="Subsystem domain that produced the artifact",
    )
    canonical_hash = Column(
        String(64),
        nullable=False,
        default="",
        comment="SHA-256 cryptographic seal of the referenced artifact",
    )
    summary = Column(
        Text,
        nullable=True,
        comment="Human-readable context or title of the bound artifact",
    )
    binding_timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        comment="When the artifact was bound to this investigation",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    case = orm_relationship("SecurityInvestigationCase", back_populates="artifact_bindings")


class InvestigationHypothesis(Base):
    """
    Hypothesis formulated by analyst or deterministic rule correlation.
    Undergoes verification throughout the investigation lifecycle.
    """

    __tablename__ = "investigation_hypotheses"
    __table_args__ = (
        Index("ix_ih_case_id", "case_id"),
        Index("ix_ih_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"ih-{uuid.uuid4().hex[:12]}",
    )
    case_id = Column(
        String(64),
        ForeignKey("sentinel.security_investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    hypothesis_title = Column(
        String(255),
        nullable=False,
        comment="Brief hypothesis title (e.g. Credential Dumping via LSASS Injection)",
    )
    hypothesis_statement = Column(
        Text,
        nullable=False,
        comment="Detailed statement and proposed explanation of activity",
    )
    confidence_score = Column(
        Float,
        nullable=False,
        default=0.5,
        comment="Deterministic confidence score (0.00 to 1.00)",
    )
    status = Column(
        String(32),
        nullable=False,
        default="PROPOSED",
        comment="PROPOSED, UNDER_INVESTIGATION, SUPPORTED, REFUTED, INCONCLUSIVE",
    )
    deductions_json = Column(
        JSON,
        nullable=False,
        default=list,
        comment="Itemized confidence deductions explainability array",
    )
    supporting_evidence_ids = Column(
        JSON,
        nullable=False,
        default=list,
        comment="Array of bound artifact IDs supporting or refuting this hypothesis",
    )
    analyst_notes = Column(
        Text,
        nullable=True,
        comment="Analyst reasoning and investigative observations",
    )
    created_by = Column(
        String(64),
        nullable=False,
        default="SYSTEM",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    # Relationships
    case = orm_relationship("SecurityInvestigationCase", back_populates="hypotheses")


class InvestigationFinding(Base):
    """
    Structured factual findings and observations established during the investigation.
    """

    __tablename__ = "investigation_findings"
    __table_args__ = (
        Index("ix_if_case_id", "case_id"),
        Index("ix_if_finding_type", "finding_type"),
        Index("ix_if_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"if-{uuid.uuid4().hex[:12]}",
    )
    case_id = Column(
        String(64),
        ForeignKey("sentinel.security_investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    finding_type = Column(
        String(64),
        nullable=False,
        default="OBSERVATION",
        comment="OBSERVATION, CONFIRMED_COMPROMISE, POLICY_VIOLATION, FALSE_ALARM, BENIGN_ANOMALY, INSUFFICIENT_TELEMETRY",
    )
    confidence_score = Column(
        Float,
        nullable=False,
        default=0.8,
        comment="Confidence in this finding (0.00 to 1.00)",
    )
    evidence_summary = Column(
        Text,
        nullable=False,
        comment="Summary of telemetry and evidence underpinning the finding",
    )
    analyst_conclusion = Column(
        Text,
        nullable=False,
        comment="Explainable conclusion reached by the investigating analyst",
    )
    status = Column(
        String(32),
        nullable=False,
        default="CONFIRMED",
        comment="DRAFT, CONFIRMED, DISMISSED",
    )
    mitre_technique_id = Column(
        String(32),
        nullable=True,
        comment="Optional MITRE ATT&CK technique reference (e.g. T1078.001)",
    )
    created_by = Column(
        String(64),
        nullable=False,
        default="SYSTEM",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    # Relationships
    case = orm_relationship("SecurityInvestigationCase", back_populates="findings")


class InvestigationTimelineEvent(Base):
    """
    Chronological investigation reconstruction.
    Preserves original source timestamps across multiple upstream domains.
    """

    __tablename__ = "investigation_timeline_events"
    __table_args__ = (
        Index("ix_ite_case_id", "case_id"),
        Index("ix_ite_timestamp", "timestamp"),
        Index("ix_ite_event_type", "event_type"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"ite-{uuid.uuid4().hex[:12]}",
    )
    case_id = Column(
        String(64),
        ForeignKey("sentinel.security_investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    timestamp = Column(
        DateTime(timezone=True),
        nullable=False,
        comment="Original UTC timestamp of the underlying telemetry / event",
    )
    event_type = Column(
        String(64),
        nullable=False,
        comment="EVIDENCE_INGESTED, NORMALIZED_EVENT, SEMANTIC_INTERPRETATION, DETECTION_TRIGGERED, IOC_MATCHED, RISK_ESCALATION, INCIDENT_OPENED, ANALYST_ACTION, HYPOTHESIS_UPDATED, FINDING_RECORDED, CASE_OPENED, REVIEW_REQUESTED, RESOLUTION_SEALED",
    )
    source_domain = Column(
        String(64),
        nullable=False,
        comment="Source domain of the chronological event",
    )
    artifact_reference = Column(
        String(128),
        nullable=False,
        comment="Identifier or reference of the associated artifact",
    )
    description = Column(
        Text,
        nullable=False,
        comment="Chronological narrative description of the event",
    )
    hash_reference = Column(
        String(64),
        nullable=False,
        default="",
        comment="SHA-256 hash of the referenced entity",
    )
    sequence_order = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Chronological ordering index",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    case = orm_relationship("SecurityInvestigationCase", back_populates="timeline_events")


class InvestigationImpactAssessment(Base):
    """
    Multi-dimensional CIA, Business, and Compliance impact assessment.
    """

    __tablename__ = "investigation_impact_assessments"
    __table_args__ = (
        Index("ix_iia_case_id", "case_id"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"iia-{uuid.uuid4().hex[:12]}",
    )
    case_id = Column(
        String(64),
        ForeignKey("sentinel.security_investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    confidentiality_impact = Column(
        String(32),
        nullable=False,
        default="NONE",
        comment="NONE, LOW, MODERATE, HIGH, CRITICAL",
    )
    integrity_impact = Column(
        String(32),
        nullable=False,
        default="NONE",
        comment="NONE, LOW, MODERATE, HIGH, CRITICAL",
    )
    availability_impact = Column(
        String(32),
        nullable=False,
        default="NONE",
        comment="NONE, LOW, MODERATE, HIGH, CRITICAL",
    )
    business_impact = Column(
        String(32),
        nullable=False,
        default="NONE",
        comment="NONE, LOW, MODERATE, HIGH, CRITICAL",
    )
    compliance_impact = Column(
        String(32),
        nullable=False,
        default="NONE",
        comment="NONE, LOW, MODERATE, HIGH, CRITICAL",
    )
    overall_impact = Column(
        String(32),
        nullable=False,
        default="LOW",
        comment="LOW, MODERATE, HIGH, CRITICAL",
    )
    impact_score = Column(
        Float,
        nullable=False,
        default=20.0,
        comment="Deterministic impact score (0.0 to 100.0)",
    )
    assessment_notes = Column(
        Text,
        nullable=False,
        default="",
        comment="Detailed impact analysis and justification",
    )
    assessed_by = Column(
        String(64),
        nullable=False,
        default="SYSTEM",
    )
    assessment_hash = Column(
        String(64),
        nullable=False,
        default="",
        comment="SHA-256 cryptographic seal of impact assessment",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    # Relationships
    case = orm_relationship("SecurityInvestigationCase", back_populates="impact_assessments")

    def compute_impact_hash(self) -> str:
        payload = {
            "case_id": self.case_id,
            "confidentiality": self.confidentiality_impact,
            "integrity": self.integrity_impact,
            "availability": self.availability_impact,
            "business": self.business_impact,
            "compliance": self.compliance_impact,
            "overall_impact": self.overall_impact,
            "impact_score": self.impact_score,
        }
        return compute_canonical_hash(IMPACT_DOMAIN_PREFIX, payload)


class InvestigationReview(Base):
    """
    Maker-Checker governance review request for case resolution.
    Prohibits self-approval by the proposing investigator.
    """

    __tablename__ = "investigation_reviews"
    __table_args__ = (
        Index("ix_ir_case_id", "case_id"),
        Index("ix_ir_decision", "decision"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"ir-{uuid.uuid4().hex[:12]}",
    )
    case_id = Column(
        String(64),
        ForeignKey("sentinel.security_investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    proposed_by_user_id = Column(
        String(64),
        nullable=False,
        comment="Investigator proposing case resolution",
    )
    proposed_resolution = Column(
        String(64),
        nullable=False,
        comment="TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_ACTIVITY, SECURITY_INCIDENT, INCONCLUSIVE, INSUFFICIENT_EVIDENCE",
    )
    proposed_notes = Column(
        Text,
        nullable=True,
        comment="Proposer's rationale and evidence references",
    )
    reviewer_user_id = Column(
        String(64),
        nullable=True,
        comment="Independent reviewer who evaluated the proposed resolution",
    )
    decision = Column(
        String(32),
        nullable=False,
        default="PENDING",
        comment="PENDING, APPROVED, CHANGES_REQUESTED, REJECTED",
    )
    review_notes = Column(
        Text,
        nullable=True,
        comment="Reviewer remarks or required adjustments",
    )
    reviewed_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )
    governance_hash = Column(
        String(64),
        nullable=False,
        default="",
        comment="SHA-256 seal over review decision",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    case = orm_relationship("SecurityInvestigationCase", back_populates="reviews")


class InvestigationCaseResolution(Base):
    """
    Final sealed resolution record for the investigation case.
    Bound to Governance Ledger and Merkle proofs.
    """

    __tablename__ = "investigation_case_resolutions"
    __table_args__ = (
        Index("ix_icr_case_id", "case_id"),
        Index("ix_icr_resolution_type", "resolution_type"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"icr-{uuid.uuid4().hex[:12]}",
    )
    case_id = Column(
        String(64),
        ForeignKey("sentinel.security_investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    resolution_type = Column(
        String(64),
        nullable=False,
        comment="TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_ACTIVITY, SECURITY_INCIDENT, INCONCLUSIVE, INSUFFICIENT_EVIDENCE",
    )
    summary = Column(
        Text,
        nullable=False,
        comment="Comprehensive resolution executive summary",
    )
    containment_verified = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if containment actions were verified and effective",
    )
    root_cause_summary = Column(
        Text,
        nullable=True,
        comment="Established root cause or explanation of activity",
    )
    resolved_by = Column(
        String(64),
        nullable=False,
        comment="Investigator who proposed the resolution",
    )
    reviewer_id = Column(
        String(64),
        nullable=False,
        comment="Independent reviewer who approved the resolution",
    )
    resolution_hash = Column(
        String(64),
        nullable=False,
        default="",
        comment="SHA-256 seal of final resolution artifact",
    )
    ledger_reference = Column(
        String(128),
        nullable=True,
        comment="Governance ledger block hash/reference",
    )
    merkle_reference = Column(
        String(128),
        nullable=True,
        comment="Merkle proof batch reference",
    )
    resolved_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    case = orm_relationship("SecurityInvestigationCase", back_populates="resolutions")

    def compute_resolution_hash(self) -> str:
        payload = {
            "case_id": self.case_id,
            "resolution_type": self.resolution_type,
            "summary": self.summary,
            "containment_verified": self.containment_verified,
            "resolved_by": self.resolved_by,
            "reviewer_id": self.reviewer_id,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else "",
        }
        return compute_canonical_hash(RESOLUTION_DOMAIN_PREFIX, payload)


class InvestigationProvenanceRecord(Base):
    """
    18-stage cryptographic hash-chained provenance lineage for the investigation.
    """

    __tablename__ = "investigation_provenance_records"
    __table_args__ = (
        Index("ix_ipr_case_id", "case_id"),
        Index("ix_ipr_stage", "provenance_stage"),
        Index("ix_ipr_order", "stage_order"),
        UniqueConstraint("case_id", "stage_order", name="uq_case_provenance_stage_order"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"ipr-{uuid.uuid4().hex[:12]}",
    )
    case_id = Column(
        String(64),
        ForeignKey("sentinel.security_investigation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    provenance_stage = Column(
        String(64),
        nullable=False,
        comment="Stage identifier (1 to 18)",
    )
    stage_order = Column(
        Integer,
        nullable=False,
        comment="Sequential 1-based order index (1..18)",
    )
    entity_type = Column(
        String(64),
        nullable=False,
        comment="Entity type verified at this stage",
    )
    entity_reference = Column(
        String(128),
        nullable=False,
        comment="Entity ID or identifier reference",
    )
    previous_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of preceding stage",
    )
    current_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of current stage",
    )
    ledger_reference = Column(
        String(128),
        nullable=True,
        comment="Governance ledger block hash/reference",
    )
    merkle_reference = Column(
        String(128),
        nullable=True,
        comment="Merkle root / proof reference",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    case = orm_relationship("SecurityInvestigationCase", back_populates="provenance_records")
