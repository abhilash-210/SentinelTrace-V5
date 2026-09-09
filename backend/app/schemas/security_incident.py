"""
schemas/security_incident.py
-----------------------------
Pydantic v2 schemas for Security Incidents, Signals, Evidence Links, Findings,
Timeline Events, Investigation Summaries, and 13-Stage Provenance Traces.

Sprint 8A — Security Incident Correlation & Investigation Foundation.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IncidentTypeEnum(str, Enum):
    SEMANTIC_RISK = "SEMANTIC_RISK"
    DETECTION_TRUST = "DETECTION_TRUST"
    MULTI_SIGNAL = "MULTI_SIGNAL"
    PROTECTED_FIELD = "PROTECTED_FIELD"
    RISK_CLUSTER = "RISK_CLUSTER"
    GOVERNANCE_ANOMALY = "GOVERNANCE_ANOMALY"
    MIXED = "MIXED"


class IncidentSeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentPriorityEnum(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class IncidentStatusEnum(str, Enum):
    OPEN = "OPEN"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    PENDING_CLOSURE = "PENDING_CLOSURE"
    CLOSED = "CLOSED"
    REJECTED = "REJECTED"


class IncidentSignalTypeEnum(str, Enum):
    SEMANTIC_DRIFT_ALERT = "SEMANTIC_DRIFT_ALERT"
    DETECTION_TRUST_ALERT = "DETECTION_TRUST_ALERT"
    RISK_CORRELATION = "RISK_CORRELATION"
    REMEDIATION_CANDIDATE = "REMEDIATION_CANDIDATE"
    POSTURE_FINDING = "POSTURE_FINDING"
    GOVERNANCE_EVENT = "GOVERNANCE_EVENT"


class IncidentSignalRelEnum(str, Enum):
    PRIMARY_TRIGGER = "PRIMARY_TRIGGER"
    CONTRIBUTING_SIGNAL = "CONTRIBUTING_SIGNAL"
    ROOT_CAUSE = "ROOT_CAUSE"
    DOWNSTREAM_IMPACT = "DOWNSTREAM_IMPACT"
    SUPPORTING_EVIDENCE = "SUPPORTING_EVIDENCE"


class IncidentEvidenceTypeEnum(str, Enum):
    RAW_EVIDENCE = "RAW_EVIDENCE"
    NORMALIZED_EVENT = "NORMALIZED_EVENT"
    SEMANTIC_INTERPRETATION = "SEMANTIC_INTERPRETATION"
    DRIFT_ALERT = "DRIFT_ALERT"
    TRUST_EVALUATION = "TRUST_EVALUATION"
    RISK_CORRELATION = "RISK_CORRELATION"
    MERKLE_BATCH = "MERKLE_BATCH"


class IncidentEvidenceRelEnum(str, Enum):
    PRIMARY = "PRIMARY"
    SUPPORTING = "SUPPORTING"
    ROOT_CAUSE = "ROOT_CAUSE"
    FORENSIC_CONTEXT = "FORENSIC_CONTEXT"


class IncidentFindingTypeEnum(str, Enum):
    OBSERVATION = "OBSERVATION"
    ROOT_CAUSE = "ROOT_CAUSE"
    IMPACT = "IMPACT"
    HYPOTHESIS = "HYPOTHESIS"
    CONFIRMED_FACT = "CONFIRMED_FACT"


class IncidentFindingStatusEnum(str, Enum):
    OPEN = "OPEN"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


class IncidentTimelineEventTypeEnum(str, Enum):
    INCIDENT_CREATED = "INCIDENT_CREATED"
    STATUS_CHANGED = "STATUS_CHANGED"
    SIGNAL_LINKED = "SIGNAL_LINKED"
    EVIDENCE_LINKED = "EVIDENCE_LINKED"
    FINDING_CREATED = "FINDING_CREATED"
    FINDING_CONFIRMED = "FINDING_CONFIRMED"
    FINDING_REJECTED = "FINDING_REJECTED"
    ANALYST_ASSIGNED = "ANALYST_ASSIGNED"
    SEVERITY_CHANGED = "SEVERITY_CHANGED"
    ROOT_CAUSE_UPDATED = "ROOT_CAUSE_UPDATED"


# ── Request Models ──────────────────────────────────────────────────────────

class IncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255, description="Incident title")
    description: Optional[str] = Field(None, description="Detailed incident description")
    incident_type: IncidentTypeEnum = Field(IncidentTypeEnum.SEMANTIC_RISK, description="Incident category")
    severity: IncidentSeverityEnum = Field(IncidentSeverityEnum.MEDIUM, description="Incident severity")
    priority: Optional[IncidentPriorityEnum] = Field(None, description="Optional priority override (defaults to severity mapping)")
    source_correlation_id: Optional[str] = Field(None, max_length=64)
    source_cluster_key: Optional[str] = Field(None, max_length=128)
    root_cause_summary: Optional[str] = Field(None)
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    assigned_to_user_id: Optional[str] = Field(None, max_length=64)


class IncidentAssignmentRequest(BaseModel):
    assigned_to_user_id: Optional[str] = Field(None, max_length=64, description="User ID of analyst or null to unassign")


class IncidentStatusUpdateRequest(BaseModel):
    status: IncidentStatusEnum = Field(..., description="Target lifecycle state")
    reason: Optional[str] = Field(None, description="Reason for state transition")


class IncidentSignalCreateRequest(BaseModel):
    signal_type: IncidentSignalTypeEnum = Field(..., description="Type of signal")
    signal_id: str = Field(..., min_length=1, max_length=128, description="Target signal identifier")
    relationship_type: IncidentSignalRelEnum = Field(IncidentSignalRelEnum.CONTRIBUTING_SIGNAL, description="Relationship to incident")


class IncidentEvidenceLinkRequest(BaseModel):
    evidence_type: IncidentEvidenceTypeEnum = Field(..., description="Type of upstream evidence")
    evidence_id: str = Field(..., min_length=1, max_length=128, description="Identifier of upstream evidence record")
    relationship: IncidentEvidenceRelEnum = Field(IncidentEvidenceRelEnum.SUPPORTING, description="Relationship classification")


class IncidentFindingCreateRequest(BaseModel):
    finding_type: IncidentFindingTypeEnum = Field(..., description="Type of investigation finding")
    title: str = Field(..., min_length=3, max_length=255, description="Finding summary title")
    description: str = Field(..., min_length=3, description="Detailed analyst reasoning and evidence grounding")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Analyst confidence rating")


class IncidentFindingUpdateRequest(BaseModel):
    status: IncidentFindingStatusEnum = Field(..., description="Updated finding status")
    comment: Optional[str] = Field(None, description="Review notes or rationale")


# ── Response Models ─────────────────────────────────────────────────────────

class IncidentSignalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_signal_id: str
    incident_id: str
    signal_type: str
    signal_id: str
    relationship_type: str
    created_at: Optional[str] = None


class IncidentEvidenceLinkResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    link_id: str
    incident_id: str
    evidence_type: str
    evidence_id: str
    relationship: str
    linked_by_user_id: str
    linked_at: Optional[str] = None
    verification_status: Optional[str] = "VERIFIED"
    verification_hash: Optional[str] = None


class IncidentFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_id: str
    incident_id: str
    finding_type: str
    title: str
    description: str
    confidence: float
    status: str
    created_by_user_id: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class IncidentTimelineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timeline_event_id: str
    incident_id: str
    event_type: str
    actor_user_id: Optional[str] = None
    event_data: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: str
    incident_number: str
    title: str
    description: Optional[str] = None
    incident_type: str
    severity: str
    priority: str
    status: str
    source_correlation_id: Optional[str] = None
    source_cluster_key: Optional[str] = None
    root_cause_summary: Optional[str] = None
    confidence: float
    affected_signal_count: int
    affected_rule_count: int
    affected_field_count: int
    created_by_user_id: str
    assigned_to_user_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class IncidentDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident: IncidentResponse
    signals: List[IncidentSignalResponse] = Field(default_factory=list)
    evidence: List[IncidentEvidenceLinkResponse] = Field(default_factory=list)
    findings: List[IncidentFindingResponse] = Field(default_factory=list)
    timeline: List[IncidentTimelineResponse] = Field(default_factory=list)


class IncidentSummaryResponse(BaseModel):
    incident: Dict[str, Any]
    impact: Dict[str, Any]
    signals: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    root_cause_candidates: List[str]
    trust_summary: Dict[str, Any]
    timeline: List[Dict[str, Any]]


class ProvenanceStage(BaseModel):
    stage_number: int
    stage_name: str
    entity_type: str
    entity_id: Optional[str] = None
    description: str
    timestamp: Optional[str] = None
    status: str  # "VERIFIED", "AVAILABLE", "NOT_AVAILABLE"
    verification_reference: Optional[str] = None
    trace_hash: Optional[str] = None


class IncidentTraceResponse(BaseModel):
    incident_id: str
    incident_number: str
    total_stages: int
    verified_stages: int
    stages: List[ProvenanceStage]
    integrity_status: str
    generated_at: str
