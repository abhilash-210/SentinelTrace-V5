"""
schemas/remediation.py
----------------------
Pydantic v2 schemas for Remediation Candidates, Priority Explanations, Simulations, and Lifecycle Transitions.

Sprint 7B — Security Posture Risk Correlation, Prioritized Remediation & Executive Risk Intelligence.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class RemediationTypeEnum(str, Enum):
    SEMANTIC_POLICY_REVIEW = "SEMANTIC_POLICY_REVIEW"
    DETECTION_RULE_REVIEW = "DETECTION_RULE_REVIEW"
    PROTECTED_FIELD_INVESTIGATION = "PROTECTED_FIELD_INVESTIGATION"
    RULE_VERSION_REVIEW = "RULE_VERSION_REVIEW"
    TRUST_REEVALUATION = "TRUST_REEVALUATION"
    SOURCE_MAPPING_REVIEW = "SOURCE_MAPPING_REVIEW"
    GOVERNANCE_REVIEW = "GOVERNANCE_REVIEW"
    ACCESS_CONTROL_REVIEW = "ACCESS_CONTROL_REVIEW"


class PriorityClassificationEnum(str, Enum):
    IMMEDIATE = "IMMEDIATE"   # 90-100
    URGENT = "URGENT"         # 75-89
    HIGH = "HIGH"             # 50-74
    MEDIUM = "MEDIUM"         # 25-49
    LOW = "LOW"               # 0-24


class RemediationStatusEnum(str, Enum):
    GENERATED = "GENERATED"
    RECOMMENDED = "RECOMMENDED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class RemediationActionResponse(BaseModel):
    id: int
    action_id: str
    remediation_id: str
    action_type: str
    from_status: Optional[str] = None
    to_status: str
    performed_by: str
    reason: Optional[str] = None
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class RemediationPriorityFactor(BaseModel):
    factor_name: str
    factor_description: str
    points: int
    applied: bool
    evidence_reference: Optional[str] = None


class RemediationPriorityExplanation(BaseModel):
    base_priority: int = 0
    calculated_score: int
    final_score: int
    priority_classification: str
    factors: List[RemediationPriorityFactor] = Field(default_factory=list)
    mathematical_formula: str
    summary: str


class RemediationCandidateResponse(BaseModel):
    id: int
    remediation_id: str
    title: str
    description: str
    remediation_type: str
    priority_score: int
    priority_classification: str
    severity: str
    status: str
    expected_risk_reduction: float
    simulation_confidence: float
    related_posture_snapshot_id: Optional[str] = None
    related_correlation_id: Optional[str] = None
    affected_fields: List[str] = Field(default_factory=list)
    affected_rules: List[str] = Field(default_factory=list)
    affected_policies: List[str] = Field(default_factory=list)
    root_cause_candidates: List[Any] = Field(default_factory=list)
    deterministic_reasoning: Dict[str, Any] = Field(default_factory=dict)
    created_by: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    action_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class RemediationDetailResponse(BaseModel):
    id: int
    remediation_id: str
    title: str
    description: str
    remediation_type: str
    priority_score: int
    priority_classification: str
    severity: str
    status: str
    expected_risk_reduction: float
    simulation_confidence: float
    related_posture_snapshot_id: Optional[str] = None
    related_correlation_id: Optional[str] = None
    affected_fields: List[str] = Field(default_factory=list)
    affected_rules: List[str] = Field(default_factory=list)
    affected_policies: List[str] = Field(default_factory=list)
    root_cause_candidates: List[Any] = Field(default_factory=list)
    deterministic_reasoning: Dict[str, Any] = Field(default_factory=dict)
    priority_explanation: Optional[RemediationPriorityExplanation] = None
    created_by: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    actions: List[RemediationActionResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class RemediationSimulationRequest(BaseModel):
    hypothetical_action: Optional[str] = None
    target_rule_ids: Optional[List[str]] = None


class AffectedRuleSimulationResult(BaseModel):
    rule_id: str
    rule_name: Optional[str] = None
    before_trust_status: str
    after_trust_status: str
    before_trust_score: float
    after_trust_score: float
    improvement_delta: float


class RemediationSimulationResponse(BaseModel):
    remediation_id: str
    remediation_title: str
    is_hypothetical: bool = True
    notice: str = "HYPOTHETICAL SIMULATION — NO PRODUCTION STATE MODIFIED"
    current_posture_score: float
    predicted_posture_score: float
    expected_improvement_delta: float
    simulation_confidence: float
    classification: str
    affected_rules: List[AffectedRuleSimulationResult] = Field(default_factory=list)
    simulation_summary: str
    recalculated_at: str


class RemediationStatusUpdateRequest(BaseModel):
    status: RemediationStatusEnum
    reason: Optional[str] = None


class RemediationGenerationRequest(BaseModel):
    force_regenerate: bool = False
    context_note: Optional[str] = None


class RemediationGenerationSummaryResponse(BaseModel):
    candidates_generated: int
    immediate_priority_count: int
    urgent_priority_count: int
    high_priority_count: int
    total_expected_posture_gain: float
    remediations: List[RemediationCandidateResponse] = Field(default_factory=list)


class RemediationProvenanceTraceStage(BaseModel):
    stage_number: int
    stage_name: str
    stage_category: str
    entity_id: Optional[str] = None
    entity_type: str
    status: str
    verification_hash: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class RemediationProvenanceTraceResponse(BaseModel):
    remediation_id: str
    title: str
    priority_classification: str
    stages_count: int
    trace_integrity_verified: bool
    stages: List[RemediationProvenanceTraceStage] = Field(default_factory=list)
