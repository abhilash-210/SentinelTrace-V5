"""
schemas/assurance_remediation.py
---------------------------------
Pydantic schemas for Sprint 9B Continuous Assurance Governance,
Remediation & Recovery Verification.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


# ── Root Cause Analysis Schemas ───────────────────────────────────────────────

class RootCauseAnalysisCreate(BaseModel):
    root_cause_category: str = Field(
        ...,
        description="Root cause category: DATA_INGESTION_FAILURE, NORMALIZATION_FAILURE, SEMANTIC_POLICY_FAILURE, DETECTION_RULE_FAILURE, RISK_CORRELATION_FAILURE, INCIDENT_RESPONSE_PIPELINE_FAILURE, CRYPTOGRAPHIC_INTEGRITY_FAILURE, TELEMETRY_GAP, CONFIGURATION_DRIFT, DEPENDENCY_FAILURE, UNKNOWN",
    )
    root_cause_key: str = Field(
        ...,
        description="Deterministic classification key (e.g. RCA_CRYPTO_HASH_MISMATCH)",
    )
    hypothesis: str = Field(
        ...,
        min_length=5,
        description="Structured hypothesis explaining degradation",
    )
    evidence_summary: str = Field(
        ...,
        min_length=5,
        description="Summary of telemetry/evidence gathered",
    )
    confidence: str = Field(
        default="MEDIUM",
        description="Confidence level: LOW, MEDIUM, HIGH, CONFIRMED",
    )
    reviewed_by_user_id: Optional[str] = Field(
        default=None,
        description="Reviewer user ID (mandatory if confidence is CONFIRMED)",
    )

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: str) -> str:
        valid = {"LOW", "MEDIUM", "HIGH", "CONFIRMED"}
        if v.upper() not in valid:
            raise ValueError(f"Confidence must be one of {valid}")
        return v.upper()


class RootCauseAnalysisResponse(BaseModel):
    id: str
    remediation_case_id: str
    analysis_version: int
    root_cause_category: str
    root_cause_key: str
    hypothesis: str
    evidence_summary: str
    confidence: str
    analysis_status: str
    created_by_user_id: str
    reviewed_by_user_id: Optional[str] = None
    created_at: Optional[datetime] = None
    reviewed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Recommendation Schemas ────────────────────────────────────────────────────

class RemediationRecommendationResponse(BaseModel):
    id: str
    remediation_case_id: str
    recommendation_type: str
    recommendation_title: str
    recommended_actions: List[Any] = Field(default_factory=list)
    reasoning: str
    confidence_score: float
    risk_score: float
    requires_dual_control: bool
    priority: str
    deterministic_inputs: Dict[str, Any] = Field(default_factory=dict)
    recommendation_hash: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Remediation Plan Schemas ──────────────────────────────────────────────────

class RemediationPlanCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=5)
    proposed_actions: List[Dict[str, Any]] = Field(..., min_items=1)
    expected_outcome: str = Field(..., min_length=5)
    rollback_strategy: str = Field(..., min_length=5)
    estimated_risk: str = Field(default="LOW")
    requires_dual_control: bool = Field(default=False)

    @field_validator("estimated_risk")
    @classmethod
    def validate_risk(cls, v: str) -> str:
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v.upper() not in valid:
            raise ValueError(f"estimated_risk must be one of {valid}")
        return v.upper()


class RemediationPlanSubmit(BaseModel):
    notes: Optional[str] = Field(default=None, description="Submission notes")


class RemediationPlanReview(BaseModel):
    decision: str = Field(..., description="Decision: APPROVE, REJECT, REQUEST_CHANGES")
    review_notes: str = Field(..., min_length=3, description="Notes justifying the review decision")

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, v: str) -> str:
        valid = {"APPROVE", "REJECT", "REQUEST_CHANGES"}
        if v.upper() not in valid:
            raise ValueError(f"Decision must be one of {valid}")
        return v.upper()


class RemediationPlanResponse(BaseModel):
    id: str
    remediation_case_id: str
    plan_version: int
    title: str
    description: str
    proposed_actions: List[Any] = Field(default_factory=list)
    expected_outcome: str
    rollback_strategy: str
    estimated_risk: str
    requires_dual_control: bool
    status: str
    proposed_by_user_id: str
    created_at: Optional[datetime] = None
    submitted_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Execution Attestation Schemas ─────────────────────────────────────────────

class ExecutionAttestationCreate(BaseModel):
    execution_reference: str = Field(..., min_length=3, max_length=128)
    external_ticket_id: Optional[str] = Field(default=None, max_length=128)
    execution_summary: str = Field(..., min_length=5)
    executed_actions: List[Dict[str, Any]] = Field(..., min_items=1)
    execution_status: str = Field(default="COMPLETED")
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    attestation: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("execution_status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        valid = {"NOT_STARTED", "IN_PROGRESS", "COMPLETED", "FAILED", "ROLLED_BACK"}
        if v.upper() not in valid:
            raise ValueError(f"Execution status must be one of {valid}")
        return v.upper()


class ExecutionAttestationResponse(BaseModel):
    id: str
    remediation_case_id: str
    remediation_plan_id: str
    execution_reference: str
    external_ticket_id: Optional[str] = None
    execution_summary: str
    executed_actions: List[Any] = Field(default_factory=list)
    executed_by_user_id: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_status: str
    execution_hash: str
    attestation: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Recovery Verification Schemas ─────────────────────────────────────────────

class RecoveryVerificationResponse(BaseModel):
    id: str
    remediation_case_id: str
    execution_id: str
    verification_status: str
    verification_method: str
    verification_evidence: Dict[str, Any] = Field(default_factory=dict)
    pre_remediation_score: float
    post_remediation_score: float
    score_delta: float
    domain_status_before: str
    domain_status_after: str
    verified_by_user_id: str
    verification_reasoning: str
    verification_hash: str
    verified_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class RecoveryConfirmationRequest(BaseModel):
    reasoning: Optional[str] = Field(default="", description="Operator confirmation notes")


class AssuranceRecoveryRecordResponse(BaseModel):
    id: str
    remediation_case_id: str
    previous_assurance_evaluation_id: str
    new_assurance_evaluation_id: str
    recovery_status: str
    recovery_confidence: float
    score_before: float
    score_after: float
    score_delta: float
    recovered_domains: List[str] = Field(default_factory=list)
    remaining_degraded_domains: List[str] = Field(default_factory=list)
    recovery_reasoning: str
    recovery_hash: str
    confirmed_by_user_id: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Case Schemas ──────────────────────────────────────────────────────────────

class AssuranceRemediationCaseCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=5)
    affected_domain: str = Field(...)
    severity: str = Field(default="MEDIUM")
    priority: str = Field(default="P2")
    assurance_alert_id: Optional[str] = None
    platform_assurance_evaluation_id: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v.upper() not in valid:
            raise ValueError(f"Severity must be one of {valid}")
        return v.upper()


class AssuranceRemediationCaseResponse(BaseModel):
    id: str
    case_number: str
    platform_assurance_evaluation_id: Optional[str] = None
    assurance_alert_id: Optional[str] = None
    affected_domain: str
    title: str
    description: str
    root_cause_category: Optional[str] = None
    root_cause_description: Optional[str] = None
    severity: str
    priority: str
    status: str
    created_by_user_id: str
    assigned_to_user_id: Optional[str] = None
    opened_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    deduplication_fingerprint: str
    timeline: List[Any] = Field(default_factory=list)
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Analytics & KPI Schemas ───────────────────────────────────────────────────

class AssuranceRemediationKPIs(BaseModel):
    total_cases: int
    open_cases: int
    pending_review: int
    executing: int
    verification_pending: int
    recovered: int
    partially_recovered: int
    failed: int
    critical_cases: int
    average_recovery_score_delta: float


class AssuranceRecoveryTrendItem(BaseModel):
    timestamp: str
    case_number: str
    domain: str
    score_before: float
    score_after: float
    score_delta: float
    recovery_status: str
    confidence: float


class AssuranceRecoveryTrendResponse(BaseModel):
    trends: List[AssuranceRecoveryTrendItem] = Field(default_factory=list)
    total_count: int


# ── 18-Stage Provenance Trace Schemas ──────────────────────────────────────────

class TraceStageItem(BaseModel):
    stage_number: int
    stage_name: str
    status: str  # AVAILABLE, NOT_AVAILABLE, NOT_APPLICABLE
    entity_id: Optional[str] = None
    timestamp: Optional[str] = None
    hash: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class AssuranceRemediationTraceResponse(BaseModel):
    case_id: str
    case_number: str
    affected_domain: str
    stages: List[TraceStageItem] = Field(default_factory=list)
    merkle_root: Optional[str] = None
    governance_ledger_sequence: Optional[int] = None
    overall_provenance_verified: bool
