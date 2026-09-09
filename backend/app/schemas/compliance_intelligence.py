"""
schemas/compliance_intelligence.py
----------------------------------
Pydantic v2 schemas and validation for Compliance Intelligence,
Security Control Governance, Evidence-Backed Assurance & 22-Stage Provenance.

Sprint 11A — Compliance Intelligence, Security Control Governance & Evidence-Backed Compliance Assurance.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ── Framework Schemas ─────────────────────────────────────────────────────────

class ComplianceFrameworkCreate(BaseModel):
    framework_code: str = Field(..., description="Unique code e.g. FW-NIST-CSF-2.0")
    framework_name: str = Field(..., description="Framework title")
    framework_version: str = Field(default="1.0", description="Framework version")
    description: str = Field(..., description="Framework scope and description")
    framework_category: str = Field(default="SECURITY_BASELINE")
    publisher: Optional[str] = Field(default="SentinelTrace Architecture")
    effective_date: Optional[datetime] = None
    metadata_json: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ComplianceFrameworkResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    framework_code: str
    framework_name: str
    framework_version: str
    description: str
    framework_category: str
    status: str
    publisher: str
    effective_date: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    metadata_json: Optional[Dict[str, Any]] = Field(default_factory=dict)
    created_by_user_id: Optional[str] = "SYSTEM"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# ── Requirement Schemas ───────────────────────────────────────────────────────

class ComplianceRequirementCreate(BaseModel):
    requirement_code: str = Field(..., description="Code e.g. ST-REQ-01")
    title: str = Field(..., description="Requirement title")
    description: str = Field(..., description="Detailed specification")
    domain_section: Optional[str] = "GENERAL"
    weight: Optional[float] = 1.0
    is_mandatory: Optional[bool] = True
    metadata_json: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ComplianceRequirementResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    framework_id: str
    requirement_code: str
    title: str
    description: str
    requirement_category: str
    importance_weight: float
    verification_required: bool
    evidence_freshness_days: int
    status: str
    created_at: Optional[datetime] = None


# ── Security Control Schemas ──────────────────────────────────────────────────

class SecurityControlCreate(BaseModel):
    control_code: str = Field(..., description="Unique code e.g. SC-AUTH-01")
    control_name: str = Field(..., description="Human readable name")
    category: Optional[str] = "TECHNICAL"
    description: str = Field(..., description="Control implementation details")
    domain: Optional[str] = "IDENTITY_ACCESS"
    criticality: Optional[str] = "HIGH"
    freshness_sla_days: Optional[int] = 30
    metadata_json: Optional[Dict[str, Any]] = Field(default_factory=dict)


class SecurityControlResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    control_code: str
    control_name: str
    description: str
    control_domain: str
    control_owner: str
    control_type: str
    criticality: str
    expected_state: str
    verification_frequency: str
    status: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# ── Evidence Binding Schemas ──────────────────────────────────────────────────

class ControlEvidenceBindingCreate(BaseModel):
    evidence_type: str = Field(..., description="e.g. RAW_LOG, NORMALIZED_EVENT, DETECTION_RULE")
    evidence_id: str = Field(..., description="ID of existing immutable record")
    evidence_hash: str = Field(..., description="SHA-256 fingerprint")
    source_stage: str = Field(..., description="Source pipeline stage")
    verification_status: Optional[str] = "VERIFIED"
    binding_reason: Optional[str] = ""
    expires_at: Optional[datetime] = None


class ControlEvidenceBindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    security_control_id: str
    evidence_type: str
    evidence_id: str
    evidence_hash: str
    source_stage: str
    observed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    binding_reason: str
    binding_hash: str
    created_at: Optional[datetime] = None


# ── Control Effectiveness Schemas ─────────────────────────────────────────────

class ControlEvaluateRequest(BaseModel):
    trigger_source: Optional[str] = "MANUAL"
    operational_state_override: Optional[str] = None
    force_crypto_failure: Optional[bool] = False


class ControlEffectivenessResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evaluation_number: str
    security_control_id: str
    evaluation_status: str
    effectiveness_score: float
    confidence_score: float
    evidence_coverage: float
    freshness_score: float
    operational_score: float
    integrity_score: float
    deductions_json: List[Dict[str, Any]] = Field(default_factory=list)
    reasoning_json: Dict[str, Any] = Field(default_factory=dict)
    evaluation_hash: str
    evaluated_at: Optional[datetime] = None
    evaluated_by: str


# ── Compliance Gap Schemas ────────────────────────────────────────────────────

class ComplianceGapResolveRequest(BaseModel):
    resolution_summary: str = Field(..., description="Remediation explanation and details")
    resolution_evidence_binding_id: Optional[str] = None


class ComplianceGapResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    gap_number: str
    framework_requirement_id: Optional[str] = None
    security_control_id: Optional[str] = None
    gap_category: str
    severity: str
    gap_status: str
    description: str
    root_cause: str
    detected_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    resolution_evidence_id: Optional[str] = None
    deduplication_fingerprint: str
    gap_hash: str


# ── Compliance Finding Schemas ────────────────────────────────────────────────

class ComplianceFindingCreate(BaseModel):
    framework_requirement_id: Optional[str] = None
    security_control_id: Optional[str] = None
    title: str
    description: str
    finding_type: Optional[str] = "NON_COMPLIANCE"
    severity: Optional[str] = "HIGH"
    gap_id: Optional[str] = None
    compensating_controls: Optional[List[str]] = Field(default_factory=list)
    remediation_plan: Optional[str] = None


class ComplianceFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_number: str
    framework_requirement_id: Optional[str] = None
    security_control_id: Optional[str] = None
    finding_type: str
    statement: str
    evidence_summary: str
    confidence: str
    status: str
    created_by_user_id: str
    reviewed_by_user_id: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    finding_hash: str
    created_at: Optional[datetime] = None


# ── Maker-Checker Review Schemas ──────────────────────────────────────────────

class ComplianceReviewCreate(BaseModel):
    review_type: Optional[str] = "COMPLIANCE_POSTURE"
    target_entity_id: str
    review_decision: str = Field(..., description="APPROVE, REJECT, REQUEST_REASSESSMENT")
    review_notes: str = Field(..., description="Governance justification")
    initiator_user_id: Optional[str] = None
    initiator_username: Optional[str] = None


class ComplianceReviewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    compliance_posture_evaluation_id: str
    review_action: str
    review_comment: str
    reviewer_user_id: str
    review_hash: str
    reviewed_at: Optional[datetime] = None


# ── Framework Posture Schemas ─────────────────────────────────────────────────

class CompliancePostureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evaluation_number: str
    framework_id: str
    overall_score: float
    posture_status: str
    requirements_total: int
    requirements_effective: int
    requirements_partial: int
    requirements_failed: int
    requirements_unknown: int
    critical_gaps: int
    high_gaps: int
    hard_failure_override: bool
    override_reason: Optional[str] = None
    evaluation_reasoning_json: Dict[str, Any] = Field(default_factory=dict)
    evaluation_hash: str
    created_by_user_id: str
    created_at: Optional[datetime] = None


# ── Provenance Schemas ────────────────────────────────────────────────────────

class ComplianceProvenanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    entity_type: str
    entity_id: str
    provenance_hash: str
    verification_status: str
    lineage_stages_json: List[Dict[str, Any]] = Field(default_factory=list)


# ── Command Center Dashboard Schemas ──────────────────────────────────────────

class ComplianceCommandCenterMetrics(BaseModel):
    global_compliance_index: float
    total_frameworks: int
    total_controls: int
    effective_controls: int
    partially_effective_controls: int
    ineffective_controls: int
    active_gaps_count: int
    critical_gaps_count: int
    high_gaps_count: int
    open_findings_count: int
    pending_reviews_count: int
    framework_summaries: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: str
