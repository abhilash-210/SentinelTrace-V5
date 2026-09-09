"""
models/compliance_intelligence.py
---------------------------------
SQLAlchemy ORM models for Compliance Intelligence, Security Control Governance,
Evidence-Backed Compliance Assurance, and 22-Stage Lineage Provenance.

Sprint 11A — Compliance Intelligence, Security Control Governance & Evidence-Backed Compliance Assurance.
Core Invariant: "COMPLIANCE MUST BE EVIDENCE-BACKED, EXPLAINABLE, HUMAN-GOVERNED, AND CRYPTOGRAPHICALLY VERIFIABLE."
Zero Trust Compliance Axioms:
- UNKNOWN CONTROL != COMPLIANT
- CONTROL EXISTS != CONTROL EFFECTIVE
- EVIDENCE EXISTS != CONTROL VERIFIED
- CONTROL IMPLEMENTED != CONTROL OPERATIONAL
- CONTROL OPERATIONAL != CONTROL COMPLIANT
- HIGH NUMERICAL SCORE != TRUST WITHOUT EXPLANATION
- MISSING EVIDENCE != PASS
- STALE EVIDENCE != CURRENT ASSURANCE
- UNVERIFIED CONTROL != VERIFIED CONTROL
- COMPLIANCE CLAIM != COMPLIANCE PROOF
- INCIDENT RESOLVED != CONTROL EFFECTIVENESS RESTORED
- RECOVERY VERIFIED != AUTOMATIC COMPLIANCE RESTORATION
- CRYPTOGRAPHIC FAILURE ALWAYS DOMINATES NUMERICAL COMPLIANCE SCORES
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


CONTROL_EVIDENCE_BINDING_DOMAIN_PREFIX = "SENTINELTRACE_CONTROL_EVIDENCE_BINDING_V1"
CONTROL_EFFECTIVENESS_DOMAIN_PREFIX = "SENTINELTRACE_CONTROL_EFFECTIVENESS_V1"
COMPLIANCE_GAP_DOMAIN_PREFIX = "SENTINELTRACE_COMPLIANCE_GAP_V1"
COMPLIANCE_FINDING_DOMAIN_PREFIX = "SENTINELTRACE_COMPLIANCE_FINDING_V1"
COMPLIANCE_POSTURE_DOMAIN_PREFIX = "SENTINELTRACE_COMPLIANCE_POSTURE_V1"
COMPLIANCE_REVIEW_DOMAIN_PREFIX = "SENTINELTRACE_COMPLIANCE_REVIEW_V1"
COMPLIANCE_PROVENANCE_DOMAIN_PREFIX = "SENTINELTRACE_COMPLIANCE_PROVENANCE_V1"


def calculate_compliance_hash(domain_prefix: str, payload: Any) -> str:
    """Deterministic canonical JSON SHA-256 hash calculation for compliance intelligence."""
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    combined = f"{domain_prefix}{canonical_json}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


class ComplianceFramework(Base):
    """Represents a compliance/security framework registered in SentinelTrace."""

    __tablename__ = "compliance_frameworks"
    __table_args__ = (
        Index("ix_compliance_frameworks_code", "framework_code", unique=True),
        Index("ix_compliance_frameworks_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"cfw_{uuid.uuid4().hex[:16]}",
    )
    framework_code = Column(String(64), unique=True, nullable=False)
    framework_name = Column(String(255), nullable=False)
    framework_version = Column(String(32), nullable=False, default="1.0")
    description = Column(Text, nullable=False)
    framework_category = Column(String(64), nullable=False, default="SECURITY_BASELINE")
    status = Column(String(32), nullable=False, default="ACTIVE")  # ACTIVE, DEPRECATED, RETIRED
    publisher = Column(String(255), nullable=False, default="SentinelTrace Architecture")
    effective_date = Column(DateTime(timezone=True), nullable=True)
    retired_at = Column(DateTime(timezone=True), nullable=True)
    metadata_json = Column(JSON, nullable=False, default=dict)
    created_by_user_id = Column(String(64), nullable=False, default="SYSTEM")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    requirements = orm_relationship(
        "ComplianceRequirement",
        back_populates="framework",
        cascade="all, delete-orphan",
        order_by="ComplianceRequirement.requirement_code",
    )
    posture_evaluations = orm_relationship(
        "CompliancePostureEvaluation",
        back_populates="framework",
        cascade="all, delete-orphan",
        order_by="desc(CompliancePostureEvaluation.created_at)",
    )


class ComplianceRequirement(Base):
    """Represents an individual requirement within a framework."""

    __tablename__ = "compliance_requirements"
    __table_args__ = (
        UniqueConstraint("framework_id", "requirement_code", name="uq_framework_requirement_code"),
        Index("ix_compliance_requirements_fw_code", "framework_id", "requirement_code"),
        Index("ix_compliance_requirements_status", "status"),
        CheckConstraint("importance_weight > 0", name="chk_req_importance_weight_positive"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"creq_{uuid.uuid4().hex[:16]}",
    )
    framework_id = Column(
        String(64),
        ForeignKey("sentinel.compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    requirement_code = Column(String(64), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    requirement_category = Column(String(64), nullable=False, default="TECHNICAL")
    importance_weight = Column(Float, nullable=False, default=1.0)
    verification_required = Column(Boolean, nullable=False, default=True)
    evidence_freshness_days = Column(Integer, nullable=False, default=30)
    status = Column(String(32), nullable=False, default="ACTIVE")  # ACTIVE, DEPRECATED, RETIRED
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    framework = orm_relationship("ComplianceFramework", back_populates="requirements")
    control_mappings = orm_relationship(
        "FrameworkControlMapping",
        back_populates="requirement",
        cascade="all, delete-orphan",
    )
    gaps = orm_relationship("ComplianceGap", back_populates="requirement")
    findings = orm_relationship("ComplianceFinding", back_populates="requirement")


class SecurityControl(Base):
    """Represents an operational security control."""

    __tablename__ = "security_controls"
    __table_args__ = (
        Index("ix_security_controls_code", "control_code", unique=True),
        Index("ix_security_controls_domain", "control_domain"),
        Index("ix_security_controls_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"sctl_{uuid.uuid4().hex[:16]}",
    )
    control_code = Column(String(64), unique=True, nullable=False)
    control_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    control_domain = Column(String(64), nullable=False)
    control_owner = Column(String(64), nullable=False, default="SecOps")
    control_type = Column(String(32), nullable=False, default="DETECTIVE")  # PREVENTIVE, DETECTIVE, CORRECTIVE, GOVERNANCE, ASSURANCE
    criticality = Column(String(32), nullable=False, default="HIGH")  # CRITICAL, HIGH, MEDIUM, LOW
    expected_state = Column(String(64), nullable=False, default="OPERATIONAL")
    verification_frequency = Column(String(32), nullable=False, default="CONTINUOUS")
    status = Column(String(32), nullable=False, default="ACTIVE")  # ACTIVE, DEPRECATED, RETIRED
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    requirement_mappings = orm_relationship(
        "FrameworkControlMapping",
        back_populates="control",
        cascade="all, delete-orphan",
    )
    evidence_bindings = orm_relationship(
        "ControlEvidenceBinding",
        back_populates="control",
        cascade="all, delete-orphan",
    )
    evaluations = orm_relationship(
        "ControlEffectivenessEvaluation",
        back_populates="control",
        cascade="all, delete-orphan",
        order_by="desc(ControlEffectivenessEvaluation.evaluated_at)",
    )
    gaps = orm_relationship("ComplianceGap", back_populates="control")
    findings = orm_relationship("ComplianceFinding", back_populates="control")


class FrameworkControlMapping(Base):
    """Maps framework requirements to SentinelTrace operational controls."""

    __tablename__ = "framework_control_mappings"
    __table_args__ = (
        UniqueConstraint("framework_requirement_id", "security_control_id", name="uq_requirement_control_mapping"),
        Index("ix_fcm_req_ctrl", "framework_requirement_id", "security_control_id"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"fcm_{uuid.uuid4().hex[:16]}",
    )
    framework_requirement_id = Column(
        String(64),
        ForeignKey("sentinel.compliance_requirements.id", ondelete="CASCADE"),
        nullable=False,
    )
    security_control_id = Column(
        String(64),
        ForeignKey("sentinel.security_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    mapping_strength = Column(String(32), nullable=False, default="PRIMARY")  # PRIMARY, SUPPORTING, PARTIAL
    mapping_rationale = Column(Text, nullable=False, default="")
    mandatory = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    requirement = orm_relationship("ComplianceRequirement", back_populates="control_mappings")
    control = orm_relationship("SecurityControl", back_populates="requirement_mappings")


class ControlEvidenceBinding(Base):
    """References immutable evidence supporting a control evaluation."""

    __tablename__ = "control_evidence_bindings"
    __table_args__ = (
        Index("ix_ceb_ctrl_evidence", "security_control_id", "evidence_type", "evidence_id"),
        Index("ix_ceb_binding_hash", "binding_hash"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"ceb_{uuid.uuid4().hex[:16]}",
    )
    security_control_id = Column(
        String(64),
        ForeignKey("sentinel.security_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_type = Column(String(64), nullable=False)
    evidence_id = Column(String(128), nullable=False)
    evidence_hash = Column(String(64), nullable=False)
    source_stage = Column(String(64), nullable=False)
    observed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    binding_reason = Column(Text, nullable=False, default="")
    binding_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    control = orm_relationship("SecurityControl", back_populates="evidence_bindings")


class ControlEffectivenessEvaluation(Base):
    """Stores deterministic evaluation of control effectiveness."""

    __tablename__ = "control_effectiveness_evaluations"
    __table_args__ = (
        Index("ix_cee_eval_number", "evaluation_number", unique=True),
        Index("ix_cee_ctrl_status", "security_control_id", "evaluation_status"),
        Index("ix_cee_eval_hash", "evaluation_hash"),
        CheckConstraint("effectiveness_score >= 0.0 AND effectiveness_score <= 100.0", name="chk_cee_eff_score_range"),
        CheckConstraint("confidence_score >= 0.0 AND confidence_score <= 100.0", name="chk_cee_conf_score_range"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"cee_{uuid.uuid4().hex[:16]}",
    )
    evaluation_number = Column(String(32), unique=True, nullable=False)  # CEV-YYYY-NNN
    security_control_id = Column(
        String(64),
        ForeignKey("sentinel.security_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    evaluation_status = Column(String(32), nullable=False, default="EFFECTIVE")  # EFFECTIVE, PARTIALLY_EFFECTIVE, INEFFECTIVE, AT_RISK, UNKNOWN
    effectiveness_score = Column(Float, nullable=False, default=100.0)
    confidence_score = Column(Float, nullable=False, default=100.0)
    evidence_coverage = Column(Float, nullable=False, default=100.0)
    freshness_score = Column(Float, nullable=False, default=100.0)
    operational_score = Column(Float, nullable=False, default=100.0)
    integrity_score = Column(Float, nullable=False, default=100.0)
    deductions_json = Column(JSON, nullable=False, default=list)
    reasoning_json = Column(JSON, nullable=False, default=dict)
    evaluation_hash = Column(String(64), nullable=False)
    evaluated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    evaluated_by = Column(String(64), nullable=False, default="SYSTEM")

    control = orm_relationship("SecurityControl", back_populates="evaluations")


class ComplianceGap(Base):
    """Represents a deterministically detected compliance gap."""

    __tablename__ = "compliance_gaps"
    __table_args__ = (
        Index("ix_compliance_gaps_number", "gap_number", unique=True),
        Index("ix_compliance_gaps_fingerprint", "deduplication_fingerprint"),
        Index("ix_compliance_gaps_status_sev", "gap_status", "severity"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"cgp_{uuid.uuid4().hex[:16]}",
    )
    gap_number = Column(String(32), unique=True, nullable=False)  # CGP-YYYY-NNN
    framework_requirement_id = Column(
        String(64),
        ForeignKey("sentinel.compliance_requirements.id", ondelete="SET NULL"),
        nullable=True,
    )
    security_control_id = Column(
        String(64),
        ForeignKey("sentinel.security_controls.id", ondelete="SET NULL"),
        nullable=True,
    )
    gap_category = Column(String(64), nullable=False)  # MISSING_CONTROL, INSUFFICIENT_EVIDENCE, STALE_EVIDENCE, CONTROL_INEFFECTIVE, CONTROL_DEGRADED, VERIFICATION_MISSING, CRYPTOGRAPHIC_FAILURE, UNKNOWN
    severity = Column(String(32), nullable=False, default="MEDIUM")  # CRITICAL, HIGH, MEDIUM, LOW
    gap_status = Column(String(32), nullable=False, default="OPEN")  # OPEN, ACKNOWLEDGED, UNDER_REVIEW, REMEDIATING, VERIFIED_RESOLVED, CLOSED
    description = Column(Text, nullable=False)
    root_cause = Column(Text, nullable=False)
    detected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolution_evidence_id = Column(String(128), nullable=True)
    deduplication_fingerprint = Column(String(64), nullable=False)
    gap_hash = Column(String(64), nullable=False)

    requirement = orm_relationship("ComplianceRequirement", back_populates="gaps")
    control = orm_relationship("SecurityControl", back_populates="gaps")


class ComplianceFinding(Base):
    """Stores structured auditor or reviewer compliance observations."""

    __tablename__ = "compliance_findings"
    __table_args__ = (
        Index("ix_compliance_findings_number", "finding_number", unique=True),
        Index("ix_compliance_findings_status", "status"),
        Index("ix_compliance_findings_hash", "finding_hash"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"cfn_{uuid.uuid4().hex[:16]}",
    )
    finding_number = Column(String(32), unique=True, nullable=False)  # CFN-YYYY-NNN
    framework_requirement_id = Column(
        String(64),
        ForeignKey("sentinel.compliance_requirements.id", ondelete="SET NULL"),
        nullable=True,
    )
    security_control_id = Column(
        String(64),
        ForeignKey("sentinel.security_controls.id", ondelete="SET NULL"),
        nullable=True,
    )
    finding_type = Column(String(64), nullable=False, default="OBSERVATION")  # OBSERVATION, DEFICIENCY, NON_COMPLIANCE, COMMENDATION
    statement = Column(Text, nullable=False)
    evidence_summary = Column(Text, nullable=False)
    confidence = Column(String(32), nullable=False, default="HIGH")  # LOW, MEDIUM, HIGH, CONFIRMED
    status = Column(String(32), nullable=False, default="DRAFT")  # DRAFT, PENDING_REVIEW, VALIDATED, REJECTED
    created_by_user_id = Column(String(64), nullable=False)
    reviewed_by_user_id = Column(String(64), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    finding_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    requirement = orm_relationship("ComplianceRequirement", back_populates="findings")
    control = orm_relationship("SecurityControl", back_populates="findings")


class CompliancePostureEvaluation(Base):
    """Represents a framework-level compliance posture evaluation."""

    __tablename__ = "compliance_posture_evaluations"
    __table_args__ = (
        Index("ix_cpe_number", "evaluation_number", unique=True),
        Index("ix_cpe_fw_status", "framework_id", "posture_status"),
        Index("ix_cpe_eval_hash", "evaluation_hash"),
        CheckConstraint("overall_score >= 0.0 AND overall_score <= 100.0", name="chk_cpe_overall_score_range"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"cpe_{uuid.uuid4().hex[:16]}",
    )
    evaluation_number = Column(String(32), unique=True, nullable=False)  # CPE-YYYY-NNN
    framework_id = Column(
        String(64),
        ForeignKey("sentinel.compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    overall_score = Column(Float, nullable=False, default=100.0)
    posture_status = Column(String(32), nullable=False, default="COMPLIANT")  # COMPLIANT, SUBSTANTIALLY_COMPLIANT, PARTIALLY_COMPLIANT, NON_COMPLIANT, CRITICAL, UNKNOWN
    requirements_total = Column(Integer, nullable=False, default=0)
    requirements_effective = Column(Integer, nullable=False, default=0)
    requirements_partial = Column(Integer, nullable=False, default=0)
    requirements_failed = Column(Integer, nullable=False, default=0)
    requirements_unknown = Column(Integer, nullable=False, default=0)
    critical_gaps = Column(Integer, nullable=False, default=0)
    high_gaps = Column(Integer, nullable=False, default=0)
    hard_failure_override = Column(Boolean, nullable=False, default=False)
    override_reason = Column(Text, nullable=True)
    evaluation_reasoning_json = Column(JSON, nullable=False, default=dict)
    evaluation_hash = Column(String(64), nullable=False)
    created_by_user_id = Column(String(64), nullable=False, default="SYSTEM")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    framework = orm_relationship("ComplianceFramework", back_populates="posture_evaluations")
    reviews = orm_relationship(
        "ComplianceReview",
        back_populates="posture_evaluation",
        cascade="all, delete-orphan",
        order_by="desc(ComplianceReview.reviewed_at)",
    )
    provenance_records = orm_relationship(
        "ComplianceProvenanceRecord",
        back_populates="posture_evaluation",
        cascade="all, delete-orphan",
        order_by="ComplianceProvenanceRecord.stage_number",
    )


class ComplianceReview(Base):
    """Human governance record over compliance posture evaluations."""

    __tablename__ = "compliance_reviews"
    __table_args__ = (
        Index("ix_compliance_reviews_cpe_id", "compliance_posture_evaluation_id"),
        Index("ix_compliance_reviews_reviewer", "reviewer_user_id"),
        Index("ix_compliance_reviews_hash", "review_hash"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"crv_{uuid.uuid4().hex[:16]}",
    )
    compliance_posture_evaluation_id = Column(
        String(64),
        ForeignKey("sentinel.compliance_posture_evaluations.id", ondelete="CASCADE"),
        nullable=False,
    )
    review_action = Column(String(32), nullable=False)  # APPROVE, REJECT, REQUEST_REASSESSMENT
    review_comment = Column(Text, nullable=False, default="")
    reviewer_user_id = Column(String(64), nullable=False)
    review_hash = Column(String(64), nullable=False)
    reviewed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    posture_evaluation = orm_relationship("CompliancePostureEvaluation", back_populates="reviews")


class ComplianceProvenanceRecord(Base):
    """Stores immutable provenance metadata for 22-stage compliance lineage."""

    __tablename__ = "compliance_provenance_records"
    __table_args__ = (
        Index("ix_cpr_posture_stage", "posture_evaluation_id", "stage_number"),
        Index("ix_cpr_stage_hash", "stage_hash"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"cpr_{uuid.uuid4().hex[:16]}",
    )
    posture_evaluation_id = Column(
        String(64),
        ForeignKey("sentinel.compliance_posture_evaluations.id", ondelete="CASCADE"),
        nullable=False,
    )
    stage_number = Column(Integer, nullable=False)  # 1 to 22
    stage_name = Column(String(128), nullable=False)
    artifact_type = Column(String(64), nullable=False)
    artifact_id = Column(String(128), nullable=False)
    artifact_hash = Column(String(64), nullable=True)
    previous_stage_hash = Column(String(64), nullable=True)
    stage_hash = Column(String(64), nullable=False)
    integrity_status = Column(String(32), nullable=False, default="VERIFIED")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    posture_evaluation = orm_relationship("CompliancePostureEvaluation", back_populates="provenance_records")
