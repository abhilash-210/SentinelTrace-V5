"""
models/detection_execution.py
------------------------------
SQLAlchemy ORM models for the Real-Time Detection Rule Execution Engine.

Sprint 7A — Real-Time Detection Rule Execution Engine.
Stores deterministic execution records of ACTIVE governed detection rules
evaluated against normalized security events.

Architectural Principles:
- Raw evidence and normalized events remain strictly immutable.
- Only ACTIVE governed detection rule versions execute.
- Detection executions create separate, auditable execution records.
- Execution idempotency is guaranteed via SHA-256 fingerprinting:
    SHA-256(rule_version_id + ":" + normalized_event_id + ":" + execution_engine_version)
- Every execution preserves end-to-end provenance and fine-grained condition explainability.
- No arbitrary code execution; evaluation is purely declarative via controlled DSL.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON

from app.database import Base


class DetectionExecution(Base):
    """
    Execution record representing the deterministic evaluation of a governed
    ACTIVE detection rule version against a specific normalized security event.
    """

    __tablename__ = "detection_executions"
    __table_args__ = (
        Index("ix_detection_executions_execution_id", "execution_id", unique=True),
        Index("ix_detection_executions_rule_id", "rule_id"),
        Index("ix_detection_executions_rule_version_id", "rule_version_id"),
        Index("ix_detection_executions_norm_event_id", "normalized_event_id"),
        Index("ix_detection_executions_status", "execution_status"),
        Index("ix_detection_executions_executed_at", "executed_at"),
        Index("ix_detection_executions_fingerprint", "execution_fingerprint", unique=True),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    execution_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"dexec_{uuid.uuid4().hex[:12]}",
        comment="Unique identifier for this detection execution record",
    )

    rule_id = Column(
        String(64),
        nullable=False,
        comment="Governed detection rule identifier (e.g. 'drule_fw_deny_scan')",
    )

    rule_version_id = Column(
        String(64),
        nullable=False,
        comment="Governed version snapshot identifier executed (e.g. 'drver_..._v1')",
    )

    rule_version_number = Column(
        Integer,
        nullable=False,
        comment="Monotonically increasing version number of the executed rule",
    )

    normalized_event_id = Column(
        String(64),
        nullable=False,
        comment="Target normalized security event identifier (e.g. 'norm_...')",
    )

    original_event_id = Column(
        String(64),
        nullable=False,
        comment="Provenance pointer to raw evidence in sentinel.ingested_events",
    )

    execution_status = Column(
        String(32),
        nullable=False,
        comment="Execution result status: 'MATCH', 'NO_MATCH', 'PARTIAL', 'ERROR'",
    )

    matched = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if rule conditions evaluated to a complete MATCH, False otherwise",
    )

    conditions_total = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Total number of discrete conditions evaluated in rule DSL",
    )

    conditions_matched = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of conditions that evaluated to TRUE",
    )

    conditions_missing = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of conditions where required telemetry fields were MISSING",
    )

    execution_fingerprint = Column(
        String(64),
        unique=True,
        nullable=False,
        comment="SHA-256 idempotency fingerprint: SHA-256(rule_version_id + ':' + normalized_event_id + ':' + engine_version)",
    )

    execution_details = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Structured payload containing evaluated DSL tree, timing, and resolved context",
    )

    execution_explanation = Column(
        Text,
        nullable=True,
        comment="Deterministic natural language explanation of the execution decision",
    )

    executed_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC timestamp when execution occurred",
    )

    execution_engine_version = Column(
        String(32),
        nullable=False,
        default="v5.7.0",
        comment="Version of the SentinelTrace Detection Rule Execution Engine",
    )

    # Relationships
    condition_results = relationship(
        "DetectionConditionResult",
        back_populates="execution",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert detection execution record to dictionary."""
        return {
            "id": self.id,
            "execution_id": self.execution_id,
            "rule_id": self.rule_id,
            "rule_version_id": self.rule_version_id,
            "rule_version_number": self.rule_version_number,
            "normalized_event_id": self.normalized_event_id,
            "original_event_id": self.original_event_id,
            "execution_status": self.execution_status,
            "matched": self.matched,
            "conditions_total": self.conditions_total,
            "conditions_matched": self.conditions_matched,
            "conditions_missing": self.conditions_missing,
            "execution_fingerprint": self.execution_fingerprint,
            "execution_details": self.execution_details or {},
            "execution_explanation": self.execution_explanation,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "execution_engine_version": self.execution_engine_version,
            "condition_results": [cr.to_dict() for cr in (self.condition_results or [])],
        }


class DetectionConditionResult(Base):
    """
    Fine-grained condition explainability record storing individual atomic condition
    evaluations for a detection execution.
    """

    __tablename__ = "detection_condition_results"
    __table_args__ = (
        Index("ix_detection_cond_results_execution_id", "execution_id"),
        Index("ix_detection_cond_results_field", "canonical_field"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Internal database surrogate key",
    )

    execution_id = Column(
        String(64),
        ForeignKey("sentinel.detection_executions.execution_id", ondelete="CASCADE"),
        nullable=False,
        comment="Parent execution identifier",
    )

    condition_index = Column(
        Integer,
        nullable=False,
        comment="0-indexed position of this condition in the rule DSL",
    )

    canonical_field = Column(
        String(100),
        nullable=False,
        comment="Canonical field evaluated (e.g. 'action.result', 'dst_endpoint.port')",
    )

    comparison_operator = Column(
        String(32),
        nullable=False,
        comment="Comparison operator: 'EQUALS', 'NOT_EQUALS', 'GREATER_THAN', etc.",
    )

    expected_value = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=True,
        comment="Expected target value specified in the rule DSL",
    )

    observed_value = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=True,
        comment="Actual resolved field value extracted from normalized event (or null if missing)",
    )

    field_resolved = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="True if field was successfully extracted, False if missing from telemetry",
    )

    condition_result = Column(
        String(32),
        nullable=False,
        comment="Result: 'TRUE', 'FALSE', 'MISSING', 'ERROR'",
    )

    explanation = Column(
        Text,
        nullable=True,
        comment="Detailed textual explainability line for this atomic condition",
    )

    # Relationships
    execution = relationship("DetectionExecution", back_populates="condition_results")

    def to_dict(self) -> Dict[str, Any]:
        """Convert condition result record to dictionary."""
        return {
            "id": self.id,
            "execution_id": self.execution_id,
            "condition_index": self.condition_index,
            "canonical_field": self.canonical_field,
            "comparison_operator": self.comparison_operator,
            "expected_value": self.expected_value,
            "observed_value": self.observed_value,
            "field_resolved": self.field_resolved,
            "condition_result": self.condition_result,
            "explanation": self.explanation,
        }
