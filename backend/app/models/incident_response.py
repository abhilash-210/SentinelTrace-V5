"""
models/incident_response.py
---------------------------
SQLAlchemy ORM models for Incident Response Playbooks, Playbook Actions,
Deterministic Response Recommendations, Containment Requests, Dual-Control Approvals,
Execution Attestations, and Response Verifications.

Sprint 8B — Incident Response Governance, Containment Decision Engine & Human Authorization.
Core Principle: "SENTINELTRACE RECOMMENDS. HUMANS AUTHORIZE."
"""

from datetime import datetime, timezone
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


class IncidentResponsePlaybook(Base):
    """
    Defines deterministic response playbooks based on incident category, root causes,
    and severity thresholds.
    """

    __tablename__ = "incident_response_playbooks"
    __table_args__ = (
        Index("ix_irp_playbook_id", "playbook_id", unique=True),
        Index("ix_irp_category", "incident_category"),
        Index("ix_irp_min_severity", "minimum_severity"),
        Index("ix_irp_status", "status"),
        Index("ix_irp_is_active", "is_active"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    playbook_id = Column(
        String(64),
        unique=True,
        nullable=False,
        comment="Deterministic playbook identifier (e.g. PLAYBOOK_CREDENTIAL_COMPROMISE)",
    )

    name = Column(
        String(255),
        nullable=False,
        comment="Descriptive playbook name",
    )

    description = Column(
        Text,
        nullable=False,
        comment="Detailed explanation of playbook objectives and containment boundaries",
    )

    incident_category = Column(
        String(64),
        nullable=False,
        comment="Target incident category (e.g. CREDENTIAL_COMPROMISE, MALWARE, NETWORK_INTRUSION, TRUST_FAILURE, GENERIC)",
    )

    minimum_severity = Column(
        String(32),
        nullable=False,
        default="LOW",
        comment="Minimum incident severity threshold for matching: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    status = Column(
        String(32),
        nullable=False,
        default="ACTIVE",
        comment="Status: 'ACTIVE', 'DRAFT', 'SUPERSEDED', 'DEPRECATED'",
    )

    version = Column(
        String(32),
        nullable=False,
        default="1.0.0",
        comment="Playbook version string",
    )

    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether the playbook is active for recommendation generation",
    )

    created_by_user_id = Column(
        String(64),
        nullable=False,
        default="SYSTEM",
        comment="User ID who authored the playbook",
    )

    playbook_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash of playbook definition",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC creation timestamp",
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
        comment="UTC last updated timestamp",
    )

    # Relationships
    actions = orm_relationship(
        "IncidentPlaybookAction",
        back_populates="playbook",
        cascade="all, delete-orphan",
        order_by="IncidentPlaybookAction.sequence_number.asc()",
    )

    recommendations = orm_relationship(
        "IncidentResponseRecommendation",
        back_populates="playbook",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "incident_category": self.incident_category,
            "minimum_severity": self.minimum_severity,
            "status": self.status,
            "version": self.version,
            "is_active": self.is_active,
            "created_by_user_id": self.created_by_user_id,
            "playbook_hash": self.playbook_hash,
            "actions_count": len(self.actions) if self.actions else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class IncidentPlaybookAction(Base):
    """
    Structured ordered action belonging to an incident response playbook.
    """

    __tablename__ = "incident_playbook_actions"
    __table_args__ = (
        Index("ix_ipa_playbook_id", "playbook_id"),
        Index("ix_ipa_action_key", "action_key"),
        Index("ix_ipa_action_type", "action_type"),
        Index("ix_ipa_impact_level", "impact_level"),
        Index("ix_ipa_seq", "playbook_id", "sequence_number"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    action_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"pact_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the playbook action",
    )

    playbook_id = Column(
        String(64),
        ForeignKey("sentinel.incident_response_playbooks.playbook_id", ondelete="CASCADE"),
        nullable=False,
        comment="Parent playbook identifier",
    )

    action_key = Column(
        String(64),
        nullable=False,
        comment="Unique action identifier within playbook (e.g. PRESERVE_EVIDENCE, ISOLATE_ENDPOINT)",
    )

    action_name = Column(
        String(255),
        nullable=False,
        comment="Human-readable action title",
    )

    description = Column(
        Text,
        nullable=False,
        comment="Detailed instruction for executing or verifying the action",
    )

    sequence_number = Column(
        Integer,
        nullable=False,
        default=1,
        comment="Execution order sequence within the playbook",
    )

    action_type = Column(
        String(64),
        nullable=False,
        comment="Controlled type: 'PRESERVE_EVIDENCE', 'INVESTIGATE', 'CONTAIN', 'BLOCK', 'ISOLATE', 'DISABLE_ACCOUNT', 'RESET_CREDENTIALS', 'ERADICATE', 'RECOVER', 'VERIFY', 'ESCALATE', 'GOVERNANCE_REVIEW'",
    )

    impact_level = Column(
        String(32),
        nullable=False,
        default="LOW_IMPACT",
        comment="Impact classification: 'LOW_IMPACT', 'MEDIUM_IMPACT', 'HIGH_IMPACT', 'CRITICAL_IMPACT'",
    )

    requires_dual_control = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Whether independent dual-control approval is required before execution",
    )

    is_mandatory = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether this action is mandatory for playbook completion",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC creation timestamp",
    )

    playbook = orm_relationship("IncidentResponsePlaybook", back_populates="actions")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action_id": self.action_id,
            "playbook_id": self.playbook_id,
            "action_key": self.action_key,
            "action_name": self.action_name,
            "description": self.description,
            "sequence_number": self.sequence_number,
            "action_type": self.action_type,
            "impact_level": self.impact_level,
            "requires_dual_control": self.requires_dual_control,
            "is_mandatory": self.is_mandatory,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class IncidentResponseRecommendation(Base):
    """
    Deterministic response recommendation generated from incident context, matched playbook,
    and risk parameters.
    Recommendations are immutable snapshots: if context changes, a new recommendation is generated.
    """

    __tablename__ = "incident_response_recommendations"
    __table_args__ = (
        Index("ix_irr_recommendation_id", "recommendation_id", unique=True),
        Index("ix_irr_incident_id", "incident_id"),
        Index("ix_irr_playbook_id", "playbook_id"),
        Index("ix_irr_action_key", "action_key"),
        Index("ix_irr_priority", "priority"),
        Index("ix_irr_status", "status"),
        Index("ix_irr_impact_level", "impact_level"),
        Index("ix_irr_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    recommendation_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"rec_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the recommendation",
    )

    incident_id = Column(
        String(64),
        ForeignKey("sentinel.security_incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        comment="Target incident identifier",
    )

    playbook_id = Column(
        String(64),
        ForeignKey("sentinel.incident_response_playbooks.playbook_id", ondelete="SET NULL"),
        nullable=True,
        comment="Matched playbook identifier",
    )

    action_key = Column(
        String(64),
        nullable=False,
        comment="Action key (e.g. ISOLATE_ENDPOINT, DISABLE_ACCOUNT)",
    )

    action_type = Column(
        String(64),
        nullable=False,
        comment="Controlled action type",
    )

    priority = Column(
        String(32),
        nullable=False,
        default="P2",
        comment="Priority tier: 'P1', 'P2', 'P3', 'P4'",
    )

    impact_level = Column(
        String(32),
        nullable=False,
        default="LOW_IMPACT",
        comment="Impact level: 'LOW_IMPACT', 'MEDIUM_IMPACT', 'HIGH_IMPACT', 'CRITICAL_IMPACT'",
    )

    confidence_score = Column(
        Float,
        nullable=False,
        default=1.0,
        comment="Deterministic confidence rating (0.0 to 1.0)",
    )

    reasoning = Column(
        Text,
        nullable=False,
        comment="Detailed explainable human-readable justification for this recommended action",
    )

    risk_context = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Structured context snapshot: incident severity, risk score, trust state, affected fields",
    )

    status = Column(
        String(32),
        nullable=False,
        default="RECOMMENDED",
        comment="Recommendation status: 'RECOMMENDED', 'PROPOSED', 'DISMISSED', 'EXPIRED'",
    )

    recommendation_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash using domain SENTINELTRACE_RESPONSE_RECOMMENDATION_V1",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC creation timestamp",
    )

    # Relationships
    playbook = orm_relationship("IncidentResponsePlaybook", back_populates="recommendations")
    containment_requests = orm_relationship("IncidentContainmentRequest", back_populates="recommendation")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "recommendation_id": self.recommendation_id,
            "incident_id": self.incident_id,
            "playbook_id": self.playbook_id,
            "action_key": self.action_key,
            "action_type": self.action_type,
            "priority": self.priority,
            "impact_level": self.impact_level,
            "confidence_score": self.confidence_score,
            "reasoning": self.reasoning,
            "risk_context": self.risk_context,
            "status": self.status,
            "recommendation_hash": self.recommendation_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class IncidentContainmentRequest(Base):
    """
    Central governance entity for proposed containment actions.
    Tracks strict state machine:
    DRAFT -> PROPOSED -> PENDING_REVIEW -> APPROVED / REJECTED -> EXECUTION_PENDING -> EXECUTION_ATTESTED -> VERIFICATION_PENDING -> VERIFIED / VERIFICATION_FAILED / CANCELLED.
    """

    __tablename__ = "incident_containment_requests"
    __table_args__ = (
        Index("ix_icr_request_id", "request_id", unique=True),
        Index("ix_icr_incident_id", "incident_id"),
        Index("ix_icr_recommendation_id", "recommendation_id"),
        Index("ix_icr_status", "status"),
        Index("ix_icr_impact_level", "impact_level"),
        Index("ix_icr_proposed_by", "proposed_by_user_id"),
        Index("ix_icr_reviewed_by", "reviewed_by_user_id"),
        Index("ix_icr_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    request_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"req_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for containment request",
    )

    incident_id = Column(
        String(64),
        ForeignKey("sentinel.security_incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        comment="Target incident identifier",
    )

    recommendation_id = Column(
        String(64),
        ForeignKey("sentinel.incident_response_recommendations.recommendation_id", ondelete="SET NULL"),
        nullable=True,
        comment="Originating recommendation identifier (if generated from recommendation)",
    )

    action_type = Column(
        String(64),
        nullable=False,
        comment="Action type: 'ISOLATE_ENDPOINT', 'DISABLE_ACCOUNT', 'BLOCK_NETWORK', 'PRESERVE_EVIDENCE', etc.",
    )

    action_description = Column(
        Text,
        nullable=False,
        comment="Detailed description of the containment action to be executed",
    )

    impact_level = Column(
        String(32),
        nullable=False,
        default="HIGH_IMPACT",
        comment="Impact level: 'LOW_IMPACT', 'MEDIUM_IMPACT', 'HIGH_IMPACT', 'CRITICAL_IMPACT'",
    )

    risk_justification = Column(
        Text,
        nullable=False,
        comment="Analyst justification explaining why this containment is necessary",
    )

    proposed_by_user_id = Column(
        String(64),
        nullable=False,
        comment="Analyst user ID who authored the proposal (Maker)",
    )

    reviewed_by_user_id = Column(
        String(64),
        nullable=True,
        comment="Independent reviewer user ID (Checker)",
    )

    approved_by_user_id = Column(
        String(64),
        nullable=True,
        comment="User ID who granted final authorization",
    )

    status = Column(
        String(32),
        nullable=False,
        default="DRAFT",
        comment="Lifecycle: 'DRAFT', 'PROPOSED', 'PENDING_REVIEW', 'APPROVED', 'REJECTED', 'EXECUTION_PENDING', 'EXECUTION_ATTESTED', 'VERIFICATION_PENDING', 'VERIFIED', 'VERIFICATION_FAILED', 'CANCELLED'",
    )

    proposed_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when request was submitted for review",
    )

    reviewed_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when decision was rendered",
    )

    approved_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when approval was granted",
    )

    execution_attested_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when execution was attested",
    )

    verification_completed_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when verification was completed",
    )

    request_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash using domain SENTINELTRACE_CONTAINMENT_REQUEST_V1",
    )

    governance_ledger_entry_id = Column(
        String(64),
        nullable=True,
        comment="Cryptographic Governance Ledger entry identifier",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC creation timestamp",
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
        comment="UTC last updated timestamp",
    )

    # Relationships
    recommendation = orm_relationship("IncidentResponseRecommendation", back_populates="containment_requests")
    approvals = orm_relationship(
        "IncidentResponseApproval",
        back_populates="containment_request",
        cascade="all, delete-orphan",
        order_by="IncidentResponseApproval.created_at.desc()",
    )
    executions = orm_relationship(
        "IncidentResponseExecution",
        back_populates="containment_request",
        cascade="all, delete-orphan",
        order_by="IncidentResponseExecution.attested_at.desc()",
    )
    verifications = orm_relationship(
        "IncidentResponseVerification",
        back_populates="containment_request",
        cascade="all, delete-orphan",
        order_by="IncidentResponseVerification.verified_at.desc()",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "request_id": self.request_id,
            "incident_id": self.incident_id,
            "recommendation_id": self.recommendation_id,
            "action_type": self.action_type,
            "action_description": self.action_description,
            "impact_level": self.impact_level,
            "risk_justification": self.risk_justification,
            "proposed_by_user_id": self.proposed_by_user_id,
            "reviewed_by_user_id": self.reviewed_by_user_id,
            "approved_by_user_id": self.approved_by_user_id,
            "status": self.status,
            "proposed_at": self.proposed_at.isoformat() if self.proposed_at else None,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "execution_attested_at": self.execution_attested_at.isoformat() if self.execution_attested_at else None,
            "verification_completed_at": self.verification_completed_at.isoformat() if self.verification_completed_at else None,
            "request_hash": self.request_hash,
            "governance_ledger_entry_id": self.governance_ledger_entry_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class IncidentResponseApproval(Base):
    """
    Immutable record of independent dual-control review decisions (Maker-Checker).
    """

    __tablename__ = "incident_response_approvals"
    __table_args__ = (
        Index("ix_ira_approval_id", "approval_id", unique=True),
        Index("ix_ira_request_id", "containment_request_id"),
        Index("ix_ira_decision", "decision"),
        Index("ix_ira_reviewer", "reviewer_user_id"),
        Index("ix_ira_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    approval_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"appr_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the review approval record",
    )

    containment_request_id = Column(
        String(64),
        ForeignKey("sentinel.incident_containment_requests.request_id", ondelete="CASCADE"),
        nullable=False,
        comment="Target containment request identifier",
    )

    decision = Column(
        String(32),
        nullable=False,
        comment="Review decision: 'APPROVE', 'REJECT', 'REQUEST_CHANGES'",
    )

    decision_reason = Column(
        Text,
        nullable=False,
        comment="Independent reviewer explanation and rationale",
    )

    reviewer_user_id = Column(
        String(64),
        nullable=False,
        comment="User ID of independent reviewer (Checker)",
    )

    approval_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash using domain SENTINELTRACE_RESPONSE_APPROVAL_V1",
    )

    governance_event_id = Column(
        String(64),
        nullable=True,
        comment="Cryptographic Governance Ledger or audit event reference",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC timestamp when review decision was recorded",
    )

    containment_request = orm_relationship("IncidentContainmentRequest", back_populates="approvals")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "approval_id": self.approval_id,
            "containment_request_id": self.containment_request_id,
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "reviewer_user_id": self.reviewer_user_id,
            "approval_hash": self.approval_hash,
            "governance_event_id": self.governance_event_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class IncidentResponseExecution(Base):
    """
    Immutable attestation of human containment execution performed in external infrastructure/EDR/IAM.
    """

    __tablename__ = "incident_response_executions"
    __table_args__ = (
        Index("ix_ire_execution_id", "execution_id", unique=True),
        Index("ix_ire_request_id", "containment_request_id"),
        Index("ix_ire_status", "execution_status"),
        Index("ix_ire_executed_by", "executed_by_user_id"),
        Index("ix_ire_attested_at", "attested_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    execution_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"exec_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the execution attestation",
    )

    containment_request_id = Column(
        String(64),
        ForeignKey("sentinel.incident_containment_requests.request_id", ondelete="CASCADE"),
        nullable=False,
        comment="Target containment request identifier",
    )

    execution_status = Column(
        String(32),
        nullable=False,
        default="EXECUTION_ATTESTED",
        comment="Status: 'EXECUTION_ATTESTED', 'EXECUTION_FAILED', 'NOT_EXECUTED'",
    )

    execution_notes = Column(
        Text,
        nullable=False,
        comment="Attestation notes describing operator execution details and telemetry",
    )

    executed_by_user_id = Column(
        String(64),
        nullable=False,
        comment="User ID of SOC operator who executed and attested the action",
    )

    execution_reference = Column(
        String(128),
        nullable=False,
        comment="External ticket or change reference (e.g. SOC-CHG-2026-001)",
    )

    attestation_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash using domain SENTINELTRACE_EXECUTION_ATTESTATION_V1",
    )

    attested_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC timestamp when execution was attested",
    )

    containment_request = orm_relationship("IncidentContainmentRequest", back_populates="executions")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "execution_id": self.execution_id,
            "containment_request_id": self.containment_request_id,
            "execution_status": self.execution_status,
            "execution_notes": self.execution_notes,
            "executed_by_user_id": self.executed_by_user_id,
            "execution_reference": self.execution_reference,
            "attestation_hash": self.attestation_hash,
            "attested_at": self.attested_at.isoformat() if self.attested_at else None,
        }


class IncidentResponseVerification(Base):
    """
    Immutable post-containment verification validating response effectiveness against telemetry.
    """

    __tablename__ = "incident_response_verifications"
    __table_args__ = (
        Index("ix_irv_verification_id", "verification_id", unique=True),
        Index("ix_irv_request_id", "containment_request_id"),
        Index("ix_irv_status", "verification_status"),
        Index("ix_irv_method", "verification_method"),
        Index("ix_irv_verified_by", "verified_by_user_id"),
        Index("ix_irv_verified_at", "verified_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    verification_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"ver_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the response verification",
    )

    containment_request_id = Column(
        String(64),
        ForeignKey("sentinel.incident_containment_requests.request_id", ondelete="CASCADE"),
        nullable=False,
        comment="Target containment request identifier",
    )

    verification_status = Column(
        String(32),
        nullable=False,
        default="VERIFIED",
        comment="Status: 'VERIFIED', 'FAILED', 'INCONCLUSIVE'",
    )

    verification_method = Column(
        String(64),
        nullable=False,
        comment="Method: 'LOG_REVIEW', 'NETWORK_TELEMETRY', 'ENDPOINT_TELEMETRY', 'AUTHENTICATION_AUDIT', 'MANUAL_CONFIRMATION'",
    )

    verification_evidence = Column(
        Text,
        nullable=False,
        comment="Technical observations and evidence confirming containment outcome",
    )

    verified_by_user_id = Column(
        String(64),
        nullable=False,
        comment="User ID of analyst who conducted the verification",
    )

    verification_notes = Column(
        Text,
        nullable=True,
        comment="Additional verification notes or follow-up remediation remarks",
    )

    verification_hash = Column(
        String(64),
        nullable=False,
        comment="Deterministic SHA-256 hash using domain SENTINELTRACE_RESPONSE_VERIFICATION_V1",
    )

    verified_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC timestamp when verification was recorded",
    )

    containment_request = orm_relationship("IncidentContainmentRequest", back_populates="verifications")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "verification_id": self.verification_id,
            "containment_request_id": self.containment_request_id,
            "verification_status": self.verification_status,
            "verification_method": self.verification_method,
            "verification_evidence": self.verification_evidence,
            "verified_by_user_id": self.verified_by_user_id,
            "verification_notes": self.verification_notes,
            "verification_hash": self.verification_hash,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }
