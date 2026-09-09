"""
schemas/executive_security_intelligence.py
-----------------------------------------
Pydantic v2 schemas for Sprint 10A Unified Executive Security Intelligence &
Executive Risk Posture Command Center.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExecutivePostureStatus(str, Enum):
    HEALTHY = "HEALTHY"
    GUARDED = "GUARDED"
    ELEVATED = "ELEVATED"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class ExecutiveDomainName(str, Enum):
    EVIDENCE_INTEGRITY = "EVIDENCE_INTEGRITY"
    NORMALIZATION = "NORMALIZATION"
    SEMANTIC_TRUST = "SEMANTIC_TRUST"
    DETECTION_TRUST = "DETECTION_TRUST"
    RISK_INTELLIGENCE = "RISK_INTELLIGENCE"
    INCIDENT_SECURITY = "INCIDENT_SECURITY"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    PLATFORM_ASSURANCE = "PLATFORM_ASSURANCE"
    ASSURANCE_RECOVERY = "ASSURANCE_RECOVERY"
    CRYPTOGRAPHIC_ASSURANCE = "CRYPTOGRAPHIC_ASSURANCE"


class ExecutiveDriverSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ExecutiveInsightType(str, Enum):
    RISK_ESCALATION = "RISK_ESCALATION"
    RISK_IMPROVEMENT = "RISK_IMPROVEMENT"
    POSTURE_DEGRADATION = "POSTURE_DEGRADATION"
    POSTURE_RECOVERY = "POSTURE_RECOVERY"
    CONCENTRATED_RISK = "CONCENTRATED_RISK"
    CROSS_DOMAIN_FAILURE = "CROSS_DOMAIN_FAILURE"
    CRYPTOGRAPHIC_ALERT = "CRYPTOGRAPHIC_ALERT"
    TELEMETRY_INSUFFICIENCY = "TELEMETRY_INSUFFICIENCY"
    GOVERNANCE_BOTTLENECK = "GOVERNANCE_BOTTLENECK"


# ── Request Schemas ────────────────────────────────────────────────────────────

class ExecutivePostureEvaluationCreateRequest(BaseModel):
    notes: Optional[str] = Field(
        default="",
        description="Optional executive context or notes regarding this evaluation trigger",
    )
    force_fresh: bool = Field(
        default=False,
        description="Whether to force recalculation across upstream domains",
    )


# ── Component Response Schemas ────────────────────────────────────────────────

class ExecutiveDomainScoreResponse(BaseModel):
    id: str
    posture_evaluation_id: str
    domain_name: str
    base_score: float
    deduction_total: float
    final_score: float
    risk_weight: float
    weighted_contribution: float
    status: str
    critical_flag: bool
    unknown_flag: bool
    primary_driver: str
    explanation: str
    canonical_payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class ExecutiveRiskDriverResponse(BaseModel):
    id: str
    driver_id: str
    posture_evaluation_id: str
    driver_type: str
    severity: str
    risk_points: float
    domain: str
    title: str
    explanation: str
    source_entity_type: str
    source_entity_id: str
    source_reference: str
    rank: int
    active: bool
    resolved: bool
    created_at: datetime


class ExecutiveInsightResponse(BaseModel):
    id: str
    insight_id: str
    posture_evaluation_id: str
    insight_type: str
    severity: str
    title: str
    description: str
    supporting_metrics: Dict[str, Any] = Field(default_factory=dict)
    recommended_attention: str
    source_domains: List[str] = Field(default_factory=list)
    confidence: float
    insight_hash: str
    created_at: datetime


class ExecutiveTrendSnapshotResponse(BaseModel):
    id: str
    snapshot_id: str
    posture_evaluation_id: str
    timestamp: datetime
    overall_security_score: float
    executive_risk_score: float
    posture_status: str
    critical_driver_count: int
    open_incident_count: int
    assurance_score: float
    detection_trust_score: float
    cryptographic_status: str
    score_delta: Optional[float] = None
    created_at: datetime


# ── Composite Evaluation Responses ─────────────────────────────────────────────

class ExecutivePostureEvaluationResponse(BaseModel):
    id: str
    evaluation_id: str
    evaluation_timestamp: datetime
    overall_posture_status: str
    overall_security_score: float
    executive_risk_score: float
    confidence_score: float
    critical_driver_count: int
    high_driver_count: int
    medium_driver_count: int
    open_critical_incidents: int
    open_high_incidents: int
    unresolved_assurance_alerts: int
    active_detection_trust_failures: int
    critical_semantic_drift_events: int
    open_remediation_cases: int
    cryptographic_integrity_status: str
    previous_evaluation_id: Optional[str] = None
    score_delta: Optional[float] = None
    posture_change: Optional[str] = None
    evaluation_reason: str
    evaluation_hash: str
    created_at: datetime
    domain_scores: Optional[List[ExecutiveDomainScoreResponse]] = None
    risk_drivers: Optional[List[ExecutiveRiskDriverResponse]] = None
    insights: Optional[List[ExecutiveInsightResponse]] = None


class ExecutivePostureEvaluationCreateResponse(BaseModel):
    message: str
    evaluation: ExecutivePostureEvaluationResponse
    hard_overrides_applied: List[str] = Field(default_factory=list)
    ledger_entry_hash: Optional[str] = None
    ledger_sequence_number: Optional[int] = None


class ExecutivePostureChangeDetails(BaseModel):
    previous_evaluation_id: Optional[str] = None
    previous_score: Optional[float] = None
    current_score: float
    score_delta: Optional[float] = None
    risk_delta: Optional[float] = None
    critical_driver_delta: Optional[int] = None
    incident_delta: Optional[int] = None
    classification: str
    explanation: str


class ExecutiveExplanationResponse(BaseModel):
    evaluation_id: str
    overall_status: str
    overall_security_score: float
    executive_risk_score: float
    hard_overrides: List[str] = Field(default_factory=list)
    top_risk_drivers: List[ExecutiveRiskDriverResponse] = Field(default_factory=list)
    domain_breakdown: List[ExecutiveDomainScoreResponse] = Field(default_factory=list)
    posture_change: ExecutivePostureChangeDetails
    executive_insights: List[ExecutiveInsightResponse] = Field(default_factory=list)
    provenance_summary: Dict[str, Any] = Field(default_factory=dict)


class ExecutiveKPIResponse(BaseModel):
    overall_posture_status: str
    overall_security_score: float
    executive_risk_score: float
    confidence_score: float
    open_critical_incidents: int
    open_high_incidents: int
    detection_trust_failures: int
    critical_semantic_drift_events: int
    unresolved_assurance_alerts: int
    active_remediation_cases: int
    cryptographic_integrity_status: str
    posture_trend_direction: str
    score_delta_24h: Optional[float] = None
    last_evaluation_timestamp: Optional[datetime] = None
    evaluation_id: Optional[str] = None


class ExecutiveProvenanceNode(BaseModel):
    node_id: str
    node_type: str
    label: str
    entity_type: str
    entity_id: str
    hash: Optional[str] = None
    status: str
    stage_number: Optional[int] = None
    stage_name: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    parents: List[str] = Field(default_factory=list)
    children: List[str] = Field(default_factory=list)


class ExecutiveProvenanceStage(BaseModel):
    stage_number: int
    stage_name: str
    status: str  # AVAILABLE, NOT_AVAILABLE, NOT_APPLICABLE
    entity_type: str
    entity_id: Optional[str] = None
    hash: Optional[str] = None
    verification_status: Optional[str] = None
    timestamp: Optional[datetime] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class ExecutiveProvenanceResponse(BaseModel):
    evaluation_id: str
    overall_posture_status: str
    overall_security_score: float
    stages: List[ExecutiveProvenanceStage]
    nodes: List[ExecutiveProvenanceNode]
    edges: List[Dict[str, str]]
    cryptographic_seal_verified: bool
    merkle_proof_verified: bool


class ExecutiveLedgerVerificationResponse(BaseModel):
    evaluation_id: str
    evaluation_hash: str
    ledger_entry_id: Optional[int] = None
    ledger_event_type: Optional[str] = None
    ledger_entry_hash: Optional[str] = None
    previous_hash: Optional[str] = None
    merkle_batch_id: Optional[str] = None
    merkle_root: Optional[str] = None
    merkle_proof_status: str  # VALID, INVALID, NOT_BATCHED
    cryptographic_chain_valid: bool
    verification_reason: str
