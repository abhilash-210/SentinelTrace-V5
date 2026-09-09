"""
schemas/security_assurance.py
-----------------------------
Pydantic v2 schemas for Continuous Security Assurance, Domain Evaluations,
Platform Assurance Snapshots, Assurance Alerts, Metric Definitions, KPIs,
and the 17-Stage Assurance Provenance Trace.

Sprint 9A — Continuous Security Assurance & Platform Health Intelligence.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AssuranceDomainEnum(str, Enum):
    EVIDENCE_ASSURANCE = "EVIDENCE_ASSURANCE"
    NORMALIZATION_ASSURANCE = "NORMALIZATION_ASSURANCE"
    SEMANTIC_ASSURANCE = "SEMANTIC_ASSURANCE"
    DETECTION_ASSURANCE = "DETECTION_ASSURANCE"
    RISK_ASSURANCE = "RISK_ASSURANCE"
    INCIDENT_RESPONSE_ASSURANCE = "INCIDENT_RESPONSE_ASSURANCE"
    CRYPTOGRAPHIC_ASSURANCE = "CRYPTOGRAPHIC_ASSURANCE"


class AssuranceStatusEnum(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    AT_RISK = "AT_RISK"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class AssuranceAlertSeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssuranceAlertStatusEnum(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class AssuranceAlertTypeEnum(str, Enum):
    ASSURANCE_DEGRADED = "ASSURANCE_DEGRADED"
    ASSURANCE_AT_RISK = "ASSURANCE_AT_RISK"
    ASSURANCE_CRITICAL = "ASSURANCE_CRITICAL"
    SCORE_REGRESSION = "SCORE_REGRESSION"
    CRYPTOGRAPHIC_INTEGRITY_FAILURE = "CRYPTOGRAPHIC_INTEGRITY_FAILURE"
    PIPELINE_TRUST_FAILURE = "PIPELINE_TRUST_FAILURE"
    STALE_SECURITY_OPERATION = "STALE_SECURITY_OPERATION"


# ── Metric Deduction Schema ──────────────────────────────────────────────────
class AssuranceDeduction(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    metric_key: str
    deduction: float
    reason: str
    severity: str = "MEDIUM"
    details: Optional[Dict[str, Any]] = None


# ── Domain Evaluation Schemas ────────────────────────────────────────────────
class AssuranceDomainEvaluationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    domain_name: str
    evaluation_timestamp: datetime
    score: float
    status: str
    metric_snapshot: Dict[str, Any] = Field(default_factory=dict)
    deductions: List[Dict[str, Any]] = Field(default_factory=list)
    explanation: str
    risk_level: str
    evaluation_hash: str
    created_at: datetime


class DomainEvaluationRequest(BaseModel):
    notes: Optional[str] = None


# ── Platform Evaluation Schemas ──────────────────────────────────────────────
class PlatformAssuranceEvaluationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evaluation_timestamp: datetime
    overall_score: float
    overall_status: str
    evidence_score: float
    normalization_score: float
    semantic_score: float
    detection_score: float
    risk_score: float
    incident_response_score: float
    cryptographic_score: float
    domain_weights: Dict[str, float] = Field(default_factory=dict)
    score_breakdown: Dict[str, Any] = Field(default_factory=dict)
    critical_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    explanation: str
    evaluation_hash: str
    previous_evaluation_id: Optional[str] = None
    created_at: datetime


class PlatformEvaluationRequest(BaseModel):
    notes: Optional[str] = None


# ── Alert Schemas ────────────────────────────────────────────────────────────
class AssuranceAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_type: str
    domain_name: str
    severity: str
    status: str
    title: str
    description: str
    source_evaluation_id: Optional[str] = None
    previous_score: Optional[float] = None
    current_score: float
    score_delta: Optional[float] = None
    deduplication_key: str
    first_detected_at: datetime
    last_detected_at: datetime
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    created_at: datetime


class AssuranceAlertStatusUpdate(BaseModel):
    status: AssuranceAlertStatusEnum
    notes: Optional[str] = None


# ── Metric Definition Schemas ────────────────────────────────────────────────
class AssuranceMetricDefinitionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    metric_key: str
    domain_name: str
    metric_name: str
    description: str
    weight: float
    healthy_threshold: float
    degraded_threshold: float
    at_risk_threshold: float
    critical_threshold: float
    enabled: bool
    created_at: datetime
    updated_at: datetime


# ── KPI Summary ──────────────────────────────────────────────────────────────
class AssuranceKPISummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    overall_score: float
    overall_status: str
    domain_health_counts: Dict[str, int] = Field(default_factory=dict)
    critical_domains: List[str] = Field(default_factory=list)
    open_assurance_alerts: int = 0
    critical_assurance_alerts: int = 0
    latest_score_delta: Optional[float] = None
    trend_direction: str = "STABLE"  # "IMPROVING", "DEGRADING", "STABLE"
    last_evaluation_timestamp: Optional[datetime] = None
    last_evaluation_hash: Optional[str] = None


# ── History Response ─────────────────────────────────────────────────────────
class AssuranceTrendSnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    platform_evaluation_id: str
    snapshot_timestamp: datetime
    overall_score: float
    overall_status: str
    domain_scores: Dict[str, float] = Field(default_factory=dict)
    score_delta: Optional[float] = None
    created_at: datetime


class AssuranceHistoryResponse(BaseModel):
    total_evaluations: int
    evaluations: List[PlatformAssuranceEvaluationResponse]
    trend_snapshots: List[AssuranceTrendSnapshotResponse]


# ── 17-Stage Provenance Trace ────────────────────────────────────────────────
class TraceStage(BaseModel):
    stage_number: int
    stage_name: str
    layer_classification: str  # "SOURCE_DATA", "PIPELINE_PROCESS", "TRUST_GOVERNANCE", "ASSURANCE_INTELLIGENCE"
    entity_count: int
    status: str
    details: Dict[str, Any] = Field(default_factory=dict)
    cryptographic_hashes: List[str] = Field(default_factory=list)
    reference_relationships: List[str] = Field(default_factory=list)


class AssuranceProvenanceTraceResponse(BaseModel):
    evaluation_id: str
    overall_score: float
    overall_status: str
    evaluation_hash: str
    trace_timestamp: datetime
    total_stages: int = 17
    stages: List[TraceStage]
    cryptographic_chain_verified: bool
