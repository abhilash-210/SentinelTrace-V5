"""
models/assurance_remediation.py
---------------------------------
SQLAlchemy ORM models for Continuous Assurance Remediation, Root Cause Analysis,
Deterministic Remediation Recommendations, Remediation Plans, Maker-Checker Approvals,
Execution Attestations, Recovery Verifications, and Final Recovery Records.

Sprint 9B — Continuous Assurance Governance, Remediation & Recovery Verification.
Core Invariant: "ASSURANCE DEGRADATION MUST NOT BE SILENT. REMEDIATION MUST BE GOVERNED. RECOVERY MUST BE VERIFIED."
Zero Trust Rule: "UNKNOWN != RECOVERED", "INCONCLUSIVE != VERIFIED"
"""

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
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
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship as orm_relationship
from sqlalchemy.types import JSON

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def calculate_sha256(domain_prefix: str, payload: Any) -> str:
    """Deterministic canonical JSON SHA-256 hash calculation."""
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    combined = f"{domain_prefix}:{canonical_json}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


class AssuranceRemediationCase(Base):
    """
    Represents a governed remediation case created from an assurance degradation.
    Enforces deterministic state transitions:
    OPEN -> ANALYZING -> REMEDIATION_PLANNED -> PENDING_REVIEW -> AUTHORIZED -> EXECUTING -> VERIFICATION_PENDING -> RECOVERED
    """

    __tablename__ = "assurance_remediation_cases"
    __table_args__ = (
        Index("ix_arc_case_number", "case_number", unique=True),
        Index("ix_arc_status_severity", "status", "severity"),
        Index("ix_arc_domain", "affected_domain"),
        Index("ix_arc_dedup_fp", "deduplication_fingerprint"),
        Index("ix_arc_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"arc-{uuid.uuid4().hex[:12]}",
        comment="Unique remediation case identifier",
    )
    case_number = Column(
        String(64),
        unique=True,
        nullable=False,
        comment="Deterministic case number, e.g. ARC-2026-001",
    )
    platform_assurance_evaluation_id = Column(
        String(64),
        nullable=True,
        comment="Triggering platform assurance evaluation reference",
    )
    assurance_alert_id = Column(
        String(64),
        nullable=True,
        comment="Triggering assurance alert reference",
    )
    affected_domain = Column(
        String(64),
        nullable=False,
        comment="Affected domain: EVIDENCE_ASSURANCE, NORMALIZATION_ASSURANCE, SEMANTIC_ASSURANCE, DETECTION_ASSURANCE, RISK_ASSURANCE, INCIDENT_RESPONSE_ASSURANCE, CRYPTOGRAPHIC_ASSURANCE",
    )
    title = Column(
        String(255),
        nullable=False,
        comment="Case title",
    )
    description = Column(
        Text,
        nullable=False,
        default="",
        comment="Detailed case description",
    )
    root_cause_category = Column(
        String(64),
        nullable=True,
        comment="Root cause category if identified",
    )
    root_cause_description = Column(
        Text,
        nullable=True,
        comment="Root cause description summary",
    )
    severity = Column(
        String(32),
        nullable=False,
        default="MEDIUM",
        comment="Severity: LOW, MEDIUM, HIGH, CRITICAL",
    )
    priority = Column(
        String(32),
        nullable=False,
        default="P2",
        comment="Priority: P1, P2, P3, P4",
    )
    status = Column(
        String(32),
        nullable=False,
        default="OPEN",
        comment="Status: OPEN, ANALYZING, REMEDIATION_PLANNED, PENDING_REVIEW, AUTHORIZED, EXECUTING, VERIFICATION_PENDING, RECOVERED, REJECTED, CANCELLED, RECOVERY_FAILED, PARTIALLY_RECOVERED",
    )
    created_by_user_id = Column(
        String(64),
        nullable=False,
        default="SYSTEM",
        comment="User ID who created case",
    )
    assigned_to_user_id = Column(
        String(64),
        nullable=True,
        comment="Assigned remediation owner user ID",
    )
    opened_at = Column(
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
    resolved_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )
    deduplication_fingerprint = Column(
        String(64),
        nullable=False,
        comment="SHA-256 fingerprint for active duplicate prevention",
    )
    timeline = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="Append-only structured timeline events array",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    # Relationships
    root_cause_analyses = orm_relationship("AssuranceRootCauseAnalysis", back_populates="remediation_case", cascade="all, delete-orphan")
    recommendations = orm_relationship("AssuranceRemediationRecommendation", back_populates="remediation_case", cascade="all, delete-orphan")
    plans = orm_relationship("AssuranceRemediationPlan", back_populates="remediation_case", cascade="all, delete-orphan")
    executions = orm_relationship("AssuranceRemediationExecution", back_populates="remediation_case", cascade="all, delete-orphan")
    verifications = orm_relationship("AssuranceRecoveryVerification", back_populates="remediation_case", cascade="all, delete-orphan")
    recovery_records = orm_relationship("AssuranceRecoveryRecord", back_populates="remediation_case", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "case_number": self.case_number,
            "platform_assurance_evaluation_id": self.platform_assurance_evaluation_id,
            "assurance_alert_id": self.assurance_alert_id,
            "affected_domain": self.affected_domain,
            "title": self.title,
            "description": self.description,
            "root_cause_category": self.root_cause_category,
            "root_cause_description": self.root_cause_description,
            "severity": self.severity,
            "priority": self.priority,
            "status": self.status,
            "created_by_user_id": self.created_by_user_id,
            "assigned_to_user_id": self.assigned_to_user_id,
            "opened_at": self.opened_at.isoformat() if self.opened_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "deduplication_fingerprint": self.deduplication_fingerprint,
            "timeline": self.timeline or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AssuranceRootCauseAnalysis(Base):
    """
    Stores structured root cause analysis and causality hypotheses.
    Enforces that UNKNOWN root cause is never treated as safe.
    """

    __tablename__ = "assurance_root_cause_analyses"
    __table_args__ = (
        Index("ix_arca_case_id", "remediation_case_id"),
        Index("ix_arca_category", "root_cause_category"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"arca-{uuid.uuid4().hex[:12]}",
        comment="Unique root cause analysis identifier",
    )
    remediation_case_id = Column(
        String(64),
        ForeignKey("sentinel.assurance_remediation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    analysis_version = Column(
        Integer,
        nullable=False,
        default=1,
    )
    root_cause_category = Column(
        String(64),
        nullable=False,
        comment="DATA_INGESTION_FAILURE, NORMALIZATION_FAILURE, SEMANTIC_POLICY_FAILURE, DETECTION_RULE_FAILURE, RISK_CORRELATION_FAILURE, INCIDENT_RESPONSE_PIPELINE_FAILURE, CRYPTOGRAPHIC_INTEGRITY_FAILURE, TELEMETRY_GAP, CONFIGURATION_DRIFT, DEPENDENCY_FAILURE, UNKNOWN",
    )
    root_cause_key = Column(
        String(128),
        nullable=False,
        comment="Deterministic classification key, e.g. RCA_CRYPTO_HASH_MISMATCH",
    )
    hypothesis = Column(
        Text,
        nullable=False,
        comment="Detailed hypothesis explaining observed degradation",
    )
    evidence_summary = Column(
        Text,
        nullable=False,
        comment="Summary of telemetry/evidence supporting the hypothesis",
    )
    confidence = Column(
        String(32),
        nullable=False,
        default="MEDIUM",
        comment="Confidence rating: LOW, MEDIUM, HIGH, CONFIRMED",
    )
    analysis_status = Column(
        String(32),
        nullable=False,
        default="DRAFT",
        comment="Status: DRAFT, SUBMITTED, CONFIRMED, REJECTED",
    )
    created_by_user_id = Column(
        String(64),
        nullable=False,
        comment="Author user ID",
    )
    reviewed_by_user_id = Column(
        String(64),
        nullable=True,
        comment="Reviewer user ID (required for CONFIRMED state)",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    reviewed_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    remediation_case = orm_relationship("AssuranceRemediationCase", back_populates="root_cause_analyses")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "remediation_case_id": self.remediation_case_id,
            "analysis_version": self.analysis_version,
            "root_cause_category": self.root_cause_category,
            "root_cause_key": self.root_cause_key,
            "hypothesis": self.hypothesis,
            "evidence_summary": self.evidence_summary,
            "confidence": self.confidence,
            "analysis_status": self.analysis_status,
            "created_by_user_id": self.created_by_user_id,
            "reviewed_by_user_id": self.reviewed_by_user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
        }


class AssuranceRemediationRecommendation(Base):
    """
    Deterministic system-generated remediation recommendations.
    Advisory only; never modifies infrastructure autonomously.
    """

    __tablename__ = "assurance_remediation_recommendations"
    __table_args__ = (
        Index("ix_arr_case_id", "remediation_case_id"),
        Index("ix_arr_rec_type", "recommendation_type"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"arr-{uuid.uuid4().hex[:12]}",
        comment="Unique recommendation identifier",
    )
    remediation_case_id = Column(
        String(64),
        ForeignKey("sentinel.assurance_remediation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    recommendation_type = Column(
        String(64),
        nullable=False,
        comment="Type: RETRY_DATA_PIPELINE, RESTORE_TELEMETRY, REVALIDATE_NORMALIZATION, REVIEW_SEMANTIC_POLICY, DISABLE_UNTRUSTED_RULE, REPAIR_RULE_DEPENDENCY, RECALCULATE_RISK_CORRELATION, INVESTIGATE_INCIDENT_PIPELINE, VERIFY_LEDGER_INTEGRITY, REBUILD_MERKLE_BATCH, REVIEW_CONFIGURATION, ESCALATE_TO_ADMIN, MANUAL_INVESTIGATION",
    )
    recommendation_title = Column(
        String(255),
        nullable=False,
        comment="Recommendation title",
    )
    recommended_actions = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="Ordered list of concrete recommended action steps",
    )
    reasoning = Column(
        Text,
        nullable=False,
        comment="Deterministic explainable justification",
    )
    confidence_score = Column(
        Float,
        nullable=False,
        comment="Explainable confidence between 0.00 and 1.00",
    )
    risk_score = Column(
        Float,
        nullable=False,
        default=0.0,
        comment="Estimated operational risk score (0.00 to 100.00)",
    )
    requires_dual_control = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether independent dual-control approval is required",
    )
    priority = Column(
        String(32),
        nullable=False,
        default="P2",
        comment="Priority: P1, P2, P3, P4",
    )
    deterministic_inputs = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Inputs snapshot used to deterministically generate recommendation",
    )
    recommendation_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash seal",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    remediation_case = orm_relationship("AssuranceRemediationCase", back_populates="recommendations")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "remediation_case_id": self.remediation_case_id,
            "recommendation_type": self.recommendation_type,
            "recommendation_title": self.recommendation_title,
            "recommended_actions": self.recommended_actions or [],
            "reasoning": self.reasoning,
            "confidence_score": self.confidence_score,
            "risk_score": self.risk_score,
            "requires_dual_control": self.requires_dual_control,
            "priority": self.priority,
            "deterministic_inputs": self.deterministic_inputs or {},
            "recommendation_hash": self.recommendation_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AssuranceRemediationPlan(Base):
    """
    Human-authored remediation plan governed by Maker-Checker authorization lifecycle.
    Lifecycle: DRAFT -> PENDING_REVIEW -> APPROVED -> AUTHORIZED_FOR_EXECUTION
    """

    __tablename__ = "assurance_remediation_plans"
    __table_args__ = (
        Index("ix_arp_case_id", "remediation_case_id"),
        Index("ix_arp_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"arp-{uuid.uuid4().hex[:12]}",
        comment="Unique remediation plan identifier",
    )
    remediation_case_id = Column(
        String(64),
        ForeignKey("sentinel.assurance_remediation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    plan_version = Column(
        Integer,
        nullable=False,
        default=1,
    )
    title = Column(
        String(255),
        nullable=False,
        comment="Plan title",
    )
    description = Column(
        Text,
        nullable=False,
        comment="Detailed plan description",
    )
    proposed_actions = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="Ordered list of human-executed remediation action steps",
    )
    expected_outcome = Column(
        Text,
        nullable=False,
        comment="Expected post-remediation assurance recovery outcome",
    )
    rollback_strategy = Column(
        Text,
        nullable=False,
        comment="Deterministic rollback procedure if recovery fails",
    )
    estimated_risk = Column(
        String(32),
        nullable=False,
        default="LOW",
        comment="Estimated risk: LOW, MEDIUM, HIGH, CRITICAL",
    )
    requires_dual_control = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether independent dual-control approval is strictly required",
    )
    status = Column(
        String(32),
        nullable=False,
        default="DRAFT",
        comment="Status: DRAFT, PENDING_REVIEW, APPROVED, AUTHORIZED_FOR_EXECUTION, REJECTED, CHANGES_REQUESTED, CANCELLED",
    )
    proposed_by_user_id = Column(
        String(64),
        nullable=False,
        comment="Proposer user ID (cannot approve their own plan)",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    submitted_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    remediation_case = orm_relationship("AssuranceRemediationCase", back_populates="plans")
    approvals = orm_relationship("AssuranceRemediationApproval", back_populates="remediation_plan", cascade="all, delete-orphan")
    executions = orm_relationship("AssuranceRemediationExecution", back_populates="remediation_plan", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "remediation_case_id": self.remediation_case_id,
            "plan_version": self.plan_version,
            "title": self.title,
            "description": self.description,
            "proposed_actions": self.proposed_actions or [],
            "expected_outcome": self.expected_outcome,
            "rollback_strategy": self.rollback_strategy,
            "estimated_risk": self.estimated_risk,
            "requires_dual_control": self.requires_dual_control,
            "status": self.status,
            "proposed_by_user_id": self.proposed_by_user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
        }


class AssuranceRemediationApproval(Base):
    """
    Independent Maker-Checker review of remediation plans.
    Strict Invariant: proposed_by_user_id != reviewer_user_id.
    """

    __tablename__ = "assurance_remediation_approvals"
    __table_args__ = (
        Index("ix_ara_plan_id", "remediation_plan_id"),
        Index("ix_ara_reviewer", "reviewer_user_id"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"ara-{uuid.uuid4().hex[:12]}",
        comment="Unique approval identifier",
    )
    remediation_plan_id = Column(
        String(64),
        ForeignKey("sentinel.assurance_remediation_plans.id", ondelete="CASCADE"),
        nullable=False,
    )
    reviewer_user_id = Column(
        String(64),
        nullable=False,
        comment="Reviewer user ID",
    )
    decision = Column(
        String(32),
        nullable=False,
        comment="Decision: APPROVE, REJECT, REQUEST_CHANGES",
    )
    review_notes = Column(
        Text,
        nullable=False,
        default="",
        comment="Review notes explaining decision",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    remediation_plan = orm_relationship("AssuranceRemediationPlan", back_populates="approvals")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "remediation_plan_id": self.remediation_plan_id,
            "reviewer_user_id": self.reviewer_user_id,
            "decision": self.decision,
            "review_notes": self.review_notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AssuranceRemediationExecution(Base):
    """
    Records human-attested remediation execution.
    SentinelTrace does not autonomously modify external infrastructure.
    Immutable once completed.
    """

    __tablename__ = "assurance_remediation_executions"
    __table_args__ = (
        Index("ix_are_case_id", "remediation_case_id"),
        Index("ix_are_plan_id", "remediation_plan_id"),
        Index("ix_are_status", "execution_status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"are-{uuid.uuid4().hex[:12]}",
        comment="Unique execution record identifier",
    )
    remediation_case_id = Column(
        String(64),
        ForeignKey("sentinel.assurance_remediation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    remediation_plan_id = Column(
        String(64),
        ForeignKey("sentinel.assurance_remediation_plans.id", ondelete="CASCADE"),
        nullable=False,
    )
    execution_reference = Column(
        String(128),
        nullable=False,
        comment="Unique execution reference or operation identifier",
    )
    external_ticket_id = Column(
        String(128),
        nullable=True,
        comment="External ticket or change management ID (e.g. CHG-2026-981)",
    )
    execution_summary = Column(
        Text,
        nullable=False,
        comment="Summary of actions executed by human operator",
    )
    executed_actions = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of specific executed action items",
    )
    executed_by_user_id = Column(
        String(64),
        nullable=False,
        comment="User ID who executed remediation",
    )
    started_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )
    execution_status = Column(
        String(32),
        nullable=False,
        default="COMPLETED",
        comment="Status: NOT_STARTED, IN_PROGRESS, COMPLETED, FAILED, ROLLED_BACK",
    )
    execution_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 seal of canonical execution payload",
    )
    attestation = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Structured human attestation metadata",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    remediation_case = orm_relationship("AssuranceRemediationCase", back_populates="executions")
    remediation_plan = orm_relationship("AssuranceRemediationPlan", back_populates="executions")
    verifications = orm_relationship("AssuranceRecoveryVerification", back_populates="execution", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "remediation_case_id": self.remediation_case_id,
            "remediation_plan_id": self.remediation_plan_id,
            "execution_reference": self.execution_reference,
            "external_ticket_id": self.external_ticket_id,
            "execution_summary": self.execution_summary,
            "executed_actions": self.executed_actions or [],
            "executed_by_user_id": self.executed_by_user_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "execution_status": self.execution_status,
            "execution_hash": self.execution_hash,
            "attestation": self.attestation or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AssuranceRecoveryVerification(Base):
    """
    Stores independent post-remediation verification.
    Critical Rule: INCONCLUSIVE != RECOVERED, FAILED != RECOVERED.
    Only VERIFIED allows progression towards RECOVERED.
    """

    __tablename__ = "assurance_recovery_verifications"
    __table_args__ = (
        Index("ix_arv_case_id", "remediation_case_id"),
        Index("ix_arv_execution_id", "execution_id"),
        Index("ix_arv_status", "verification_status"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"arv-{uuid.uuid4().hex[:12]}",
        comment="Unique verification identifier",
    )
    remediation_case_id = Column(
        String(64),
        ForeignKey("sentinel.assurance_remediation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    execution_id = Column(
        String(64),
        ForeignKey("sentinel.assurance_remediation_executions.id", ondelete="CASCADE"),
        nullable=False,
    )
    verification_status = Column(
        String(32),
        nullable=False,
        default="PENDING",
        comment="Status: PENDING, VERIFIED, FAILED, INCONCLUSIVE",
    )
    verification_method = Column(
        String(64),
        nullable=False,
        default="AUTOMATED_RE_EVALUATION",
        comment="Verification method",
    )
    verification_evidence = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Telemetry and metric evidence proving or disproving recovery",
    )
    pre_remediation_score = Column(
        Float,
        nullable=False,
        comment="Score before remediation",
    )
    post_remediation_score = Column(
        Float,
        nullable=False,
        comment="Score after remediation re-evaluation",
    )
    score_delta = Column(
        Float,
        nullable=False,
        comment="post_score - pre_score",
    )
    domain_status_before = Column(
        String(32),
        nullable=False,
        comment="Domain status before remediation",
    )
    domain_status_after = Column(
        String(32),
        nullable=False,
        comment="Domain status after remediation re-evaluation",
    )
    verified_by_user_id = Column(
        String(64),
        nullable=False,
        comment="User ID who conducted or triggered verification",
    )
    verification_reasoning = Column(
        Text,
        nullable=False,
        comment="Explainable verification justification",
    )
    verification_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 seal of verification evidence",
    )
    verified_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    remediation_case = orm_relationship("AssuranceRemediationCase", back_populates="verifications")
    execution = orm_relationship("AssuranceRemediationExecution", back_populates="verifications")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "remediation_case_id": self.remediation_case_id,
            "execution_id": self.execution_id,
            "verification_status": self.verification_status,
            "verification_method": self.verification_method,
            "verification_evidence": self.verification_evidence or {},
            "pre_remediation_score": self.pre_remediation_score,
            "post_remediation_score": self.post_remediation_score,
            "score_delta": self.score_delta,
            "domain_status_before": self.domain_status_before,
            "domain_status_after": self.domain_status_after,
            "verified_by_user_id": self.verified_by_user_id,
            "verification_reasoning": self.verification_reasoning,
            "verification_hash": self.verification_hash,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }


class AssuranceRecoveryRecord(Base):
    """
    Immutable final recovery decision.
    Binds pre-evaluation and post-evaluation IDs cryptographically.
    """

    __tablename__ = "assurance_recovery_records"
    __table_args__ = (
        Index("ix_arrd_case_id", "remediation_case_id"),
        Index("ix_arrd_status", "recovery_status"),
        Index("ix_arrd_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        String(64),
        primary_key=True,
        default=lambda: f"arrd-{uuid.uuid4().hex[:12]}",
        comment="Unique recovery record identifier",
    )
    remediation_case_id = Column(
        String(64),
        ForeignKey("sentinel.assurance_remediation_cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    previous_assurance_evaluation_id = Column(
        String(64),
        nullable=False,
        comment="Pre-remediation PlatformAssuranceEvaluation identifier",
    )
    new_assurance_evaluation_id = Column(
        String(64),
        nullable=False,
        comment="Post-remediation PlatformAssuranceEvaluation identifier",
    )
    recovery_status = Column(
        String(32),
        nullable=False,
        comment="Status: RECOVERED, PARTIALLY_RECOVERED, NOT_RECOVERED, UNKNOWN",
    )
    recovery_confidence = Column(
        Float,
        nullable=False,
        comment="Explainable recovery confidence rating (0.00 to 1.00)",
    )
    score_before = Column(
        Float,
        nullable=False,
        comment="Platform score before remediation",
    )
    score_after = Column(
        Float,
        nullable=False,
        comment="Platform score after remediation",
    )
    score_delta = Column(
        Float,
        nullable=False,
        comment="Score improvement (score_after - score_before)",
    )
    recovered_domains = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of domains verified as recovered",
    )
    remaining_degraded_domains = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
        comment="List of domains that remain degraded (prevents silent closure)",
    )
    recovery_reasoning = Column(
        Text,
        nullable=False,
        comment="Deterministic recovery reasoning and checklist validation summary",
    )
    recovery_hash = Column(
        String(64),
        nullable=False,
        comment="Cryptographic SHA-256 seal of the recovery decision payload",
    )
    confirmed_by_user_id = Column(
        String(64),
        nullable=False,
        comment="User ID who confirmed recovery",
    )
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    remediation_case = orm_relationship("AssuranceRemediationCase", back_populates="recovery_records")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "remediation_case_id": self.remediation_case_id,
            "previous_assurance_evaluation_id": self.previous_assurance_evaluation_id,
            "new_assurance_evaluation_id": self.new_assurance_evaluation_id,
            "recovery_status": self.recovery_status,
            "recovery_confidence": self.recovery_confidence,
            "score_before": self.score_before,
            "score_after": self.score_after,
            "score_delta": self.score_delta,
            "recovered_domains": self.recovered_domains or [],
            "remaining_degraded_domains": self.remaining_degraded_domains or [],
            "recovery_reasoning": self.recovery_reasoning,
            "recovery_hash": self.recovery_hash,
            "confirmed_by_user_id": self.confirmed_by_user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
