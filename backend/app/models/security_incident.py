"""
models/security_incident.py
----------------------------
SQLAlchemy ORM models for Security Incidents, Incident Signals,
Evidence Links, Analyst Findings, and Immutable Timeline Events.

Sprint 8A — Security Incident Correlation & Investigation Foundation.
Groups correlated security risks, detection trust alerts, semantic drift alerts,
and remediation candidates into formal security INCIDENTS without automated/black-box decisions.
"""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import (
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


class SecurityIncident(Base):
    """
    Formal security incident entity connecting correlated risks, trust alerts,
    semantic drift, and remediation candidates into an auditable investigation workspace.
    """

    __tablename__ = "security_incidents"
    __table_args__ = (
        Index("ix_sec_inc_incident_id", "incident_id", unique=True),
        Index("ix_sec_inc_incident_number", "incident_number", unique=True),
        Index("ix_sec_inc_type", "incident_type"),
        Index("ix_sec_inc_severity", "severity"),
        Index("ix_sec_inc_priority", "priority"),
        Index("ix_sec_inc_status", "status"),
        Index("ix_sec_inc_assigned", "assigned_to_user_id"),
        Index("ix_sec_inc_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    incident_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"inc_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the security incident",
    )

    incident_number = Column(
        String(64),
        unique=True,
        nullable=False,
        comment="Human-readable deterministic identifier (e.g. INC-2026-000001)",
    )

    title = Column(
        String(255),
        nullable=False,
        comment="Descriptive title of the incident",
    )

    description = Column(
        Text,
        nullable=True,
        comment="Detailed technical description and context of the incident",
    )

    incident_type = Column(
        String(64),
        nullable=False,
        comment="Classification: 'SEMANTIC_RISK', 'DETECTION_TRUST', 'MULTI_SIGNAL', 'PROTECTED_FIELD', 'RISK_CLUSTER', 'GOVERNANCE_ANOMALY', 'MIXED'",
    )

    severity = Column(
        String(32),
        nullable=False,
        comment="Severity: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'",
    )

    priority = Column(
        String(32),
        nullable=False,
        comment="Priority: 'P1', 'P2', 'P3', 'P4'",
    )

    status = Column(
        String(32),
        nullable=False,
        default="OPEN",
        comment="Lifecycle: 'OPEN', 'TRIAGING', 'INVESTIGATING', 'CONTAINED', 'PENDING_CLOSURE', 'CLOSED', 'REJECTED'",
    )

    source_correlation_id = Column(
        String(64),
        ForeignKey("sentinel.risk_correlations.correlation_id", ondelete="SET NULL"),
        nullable=True,
        comment="Foreign key referencing initiating risk correlation",
    )

    source_cluster_key = Column(
        String(128),
        nullable=True,
        comment="Identified risk cluster key (e.g. cluster:field:action.result)",
    )

    root_cause_summary = Column(
        Text,
        nullable=True,
        comment="Deterministic explanation of root cause and contributing factors",
    )

    confidence = Column(
        Float,
        nullable=False,
        default=1.0,
        comment="Deterministic confidence rating (0.0 to 1.0)",
    )

    affected_signal_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of contributing security signals",
    )

    affected_rule_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of degraded or invalid detection rules",
    )

    affected_field_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Count of affected canonical semantic fields",
    )

    created_by_user_id = Column(
        String(64),
        nullable=False,
        comment="User ID or SYSTEM entity that generated the incident",
    )

    assigned_to_user_id = Column(
        String(64),
        nullable=True,
        comment="Assigned Security Analyst user ID",
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
    signals = orm_relationship(
        "IncidentSignal",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentSignal.created_at.desc()",
    )

    evidence_links = orm_relationship(
        "IncidentEvidenceLink",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentEvidenceLink.linked_at.desc()",
    )

    findings = orm_relationship(
        "IncidentFinding",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentFinding.created_at.desc()",
    )

    timeline_events = orm_relationship(
        "IncidentTimelineEvent",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimelineEvent.created_at.asc()",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "incident_number": self.incident_number,
            "title": self.title,
            "description": self.description,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "priority": self.priority,
            "status": self.status,
            "source_correlation_id": self.source_correlation_id,
            "source_cluster_key": self.source_cluster_key,
            "root_cause_summary": self.root_cause_summary,
            "confidence": self.confidence,
            "affected_signal_count": self.affected_signal_count,
            "affected_rule_count": self.affected_rule_count,
            "affected_field_count": self.affected_field_count,
            "created_by_user_id": self.created_by_user_id,
            "assigned_to_user_id": self.assigned_to_user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class IncidentSignal(Base):
    """
    Explicitly records every security signal contributing to an incident.
    """

    __tablename__ = "incident_signals"
    __table_args__ = (
        Index("ix_inc_sig_incident_id", "incident_id"),
        Index("ix_inc_sig_signal_type", "signal_type"),
        Index("ix_inc_sig_signal_id", "signal_id"),
        Index("ix_inc_sig_created_at", "created_at"),
        UniqueConstraint(
            "incident_id",
            "signal_type",
            "signal_id",
            name="uq_incident_signal_unique",
        ),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    incident_signal_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"isig_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the signal link",
    )

    incident_id = Column(
        String(64),
        ForeignKey("sentinel.security_incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        comment="Incident foreign key",
    )

    signal_type = Column(
        String(64),
        nullable=False,
        comment="Enum: 'SEMANTIC_DRIFT_ALERT', 'DETECTION_TRUST_ALERT', 'RISK_CORRELATION', 'REMEDIATION_CANDIDATE', 'POSTURE_FINDING', 'GOVERNANCE_EVENT'",
    )

    signal_id = Column(
        String(128),
        nullable=False,
        comment="Target signal identifier (e.g. drift_..., dta_..., corr_...)",
    )

    relationship_type = Column(
        String(64),
        nullable=False,
        default="CONTRIBUTING_SIGNAL",
        comment="Enum: 'PRIMARY_TRIGGER', 'CONTRIBUTING_SIGNAL', 'ROOT_CAUSE', 'DOWNSTREAM_IMPACT', 'SUPPORTING_EVIDENCE'",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC link timestamp",
    )

    incident = orm_relationship("SecurityIncident", back_populates="signals")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "incident_signal_id": self.incident_signal_id,
            "incident_id": self.incident_id,
            "signal_type": self.signal_type,
            "signal_id": self.signal_id,
            "relationship_type": self.relationship_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class IncidentEvidenceLink(Base):
    """
    Links immutable upstream evidence to an investigation by reference without mutating evidence.
    """

    __tablename__ = "incident_evidence_links"
    __table_args__ = (
        Index("ix_inc_ev_incident_id", "incident_id"),
        Index("ix_inc_ev_evidence_type", "evidence_type"),
        Index("ix_inc_ev_evidence_id", "evidence_id"),
        Index("ix_inc_ev_linked_at", "linked_at"),
        UniqueConstraint(
            "incident_id",
            "evidence_type",
            "evidence_id",
            name="uq_incident_evidence_unique",
        ),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    link_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"iev_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the evidence link",
    )

    incident_id = Column(
        String(64),
        ForeignKey("sentinel.security_incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        comment="Incident foreign key",
    )

    evidence_type = Column(
        String(64),
        nullable=False,
        comment="Enum: 'RAW_EVIDENCE', 'NORMALIZED_EVENT', 'SEMANTIC_INTERPRETATION', 'DRIFT_ALERT', 'TRUST_EVALUATION', 'RISK_CORRELATION', 'MERKLE_BATCH'",
    )

    evidence_id = Column(
        String(128),
        nullable=False,
        comment="Reference ID of immutable evidence record",
    )

    relationship = Column(
        String(64),
        nullable=False,
        default="SUPPORTING",
        comment="Enum: 'PRIMARY', 'SUPPORTING', 'ROOT_CAUSE', 'FORENSIC_CONTEXT'",
    )

    linked_by_user_id = Column(
        String(64),
        nullable=False,
        comment="User ID of analyst who linked the evidence",
    )

    linked_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC timestamp when evidence was linked",
    )

    incident = orm_relationship("SecurityIncident", back_populates="evidence_links")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "link_id": self.link_id,
            "incident_id": self.incident_id,
            "evidence_type": self.evidence_type,
            "evidence_id": self.evidence_id,
            "relationship": self.relationship,
            "linked_by_user_id": self.linked_by_user_id,
            "linked_at": self.linked_at.isoformat() if self.linked_at else None,
        }


class IncidentFinding(Base):
    """
    Analyst investigation findings documenting verified facts, root causes, observations, or hypotheses.
    Preserves strict attribution and status progression.
    """

    __tablename__ = "incident_findings"
    __table_args__ = (
        Index("ix_inc_fnd_incident_id", "incident_id"),
        Index("ix_inc_fnd_type", "finding_type"),
        Index("ix_inc_fnd_status", "status"),
        Index("ix_inc_fnd_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    finding_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"ifnd_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the investigation finding",
    )

    incident_id = Column(
        String(64),
        ForeignKey("sentinel.security_incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        comment="Incident foreign key",
    )

    finding_type = Column(
        String(64),
        nullable=False,
        comment="Enum: 'OBSERVATION', 'ROOT_CAUSE', 'IMPACT', 'HYPOTHESIS', 'CONFIRMED_FACT'",
    )

    title = Column(
        String(255),
        nullable=False,
        comment="Summary title of the finding",
    )

    description = Column(
        Text,
        nullable=False,
        comment="Detailed analyst explanation and evidence grounding",
    )

    confidence = Column(
        Float,
        nullable=False,
        default=1.0,
        comment="Analyst confidence rating (0.0 to 1.0)",
    )

    status = Column(
        String(32),
        nullable=False,
        default="OPEN",
        comment="Enum: 'OPEN', 'CONFIRMED', 'REJECTED'",
    )

    created_by_user_id = Column(
        String(64),
        nullable=False,
        comment="Analyst user ID who authored the finding",
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
        comment="UTC last update timestamp",
    )

    incident = orm_relationship("SecurityIncident", back_populates="findings")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "incident_id": self.incident_id,
            "finding_type": self.finding_type,
            "title": self.title,
            "description": self.description,
            "confidence": self.confidence,
            "status": self.status,
            "created_by_user_id": self.created_by_user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class IncidentTimelineEvent(Base):
    """
    Append-only investigation timeline recording all incident lifecycle actions,
    evidence links, findings, and analyst assignments. Never updated.
    """

    __tablename__ = "incident_timeline_events"
    __table_args__ = (
        Index("ix_inc_tm_incident_id", "incident_id"),
        Index("ix_inc_tm_event_type", "event_type"),
        Index("ix_inc_tm_actor", "actor_user_id"),
        Index("ix_inc_tm_created_at", "created_at"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal surrogate primary key",
    )

    timeline_event_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"itev_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for the timeline event",
    )

    incident_id = Column(
        String(64),
        ForeignKey("sentinel.security_incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
        comment="Incident foreign key",
    )

    event_type = Column(
        String(64),
        nullable=False,
        comment="Enum: 'INCIDENT_CREATED', 'STATUS_CHANGED', 'SIGNAL_LINKED', 'EVIDENCE_LINKED', 'FINDING_CREATED', 'FINDING_CONFIRMED', 'FINDING_REJECTED', 'ANALYST_ASSIGNED', 'SEVERITY_CHANGED', 'ROOT_CAUSE_UPDATED'",
    )

    actor_user_id = Column(
        String(64),
        nullable=True,
        comment="User ID of acting analyst or NULL for system-generated events",
    )

    event_data = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Immutable structured payload for the event",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        nullable=False,
        comment="UTC immutable creation timestamp",
    )

    incident = orm_relationship("SecurityIncident", back_populates="timeline_events")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timeline_event_id": self.timeline_event_id,
            "incident_id": self.incident_id,
            "event_type": self.event_type,
            "actor_user_id": self.actor_user_id,
            "event_data": self.event_data,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
