"""
schemas/security_investigation.py
----------------------------------
Pydantic validation schemas for Unified SOC Investigation & Security Case Management.

Sprint 12A — Unified SOC Investigation & Security Case Management.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import ConfigDict, BaseModel, Field


# ── Case Schemas ─────────────────────────────────────────────────────────────

class InvestigationCaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=5)
    priority: Optional[str] = Field("MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW")
    severity: Optional[str] = Field("MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    investigation_type: Optional[str] = Field("SECURITY_INCIDENT", description="SECURITY_INCIDENT, THREAT_HUNT, ANOMALOUS_BEHAVIOR, COMPLIANCE_INVESTIGATION, EVIDENCE_FORENSICS, DATA_EXFILTRATION, CREDENTIAL_ACCESS, PROACTIVE_ANALYSIS")
    source_domain: Optional[str] = Field("DETECTION", description="DETECTION, THREAT_INTELLIGENCE, RISK, INCIDENT, COMPLIANCE, EVIDENCE, MANUAL")
    assigned_to: Optional[str] = None
    initial_artifact_bindings: Optional[List[Dict[str, Any]]] = None


class InvestigationCaseUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution: Optional[str] = None
    resolution_notes: Optional[str] = None


class InvestigationCaseResponse(BaseModel):
    id: str
    case_number: str
    title: str
    description: str
    priority: str
    severity: str
    status: str
    investigation_type: str
    source_domain: str
    created_by: str
    assigned_to: Optional[str]
    opened_at: datetime
    closed_at: Optional[datetime]
    resolution: Optional[str]
    resolution_notes: Optional[str]
    priority_score: float
    priority_drivers: List[Any]
    hard_failure_override: bool
    canonical_hash: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Artifact Binding Schemas ─────────────────────────────────────────────────

class ArtifactBindingCreateRequest(BaseModel):
    artifact_type: str = Field(..., description="EVIDENCE, NORMALIZED_EVENT, SEMANTIC_INTERPRETATION, DETECTION_RULE, DETECTION_RESULT, RISK_CORRELATION, SECURITY_INCIDENT, THREAT_INDICATOR, THREAT_ACTOR, THREAT_CAMPAIGN, COMPLIANCE_FINDING, REMEDIATION_CASE, SCENARIO_EXECUTION")
    artifact_id: str = Field(..., min_length=1)
    source_domain: str = Field(..., min_length=1)
    canonical_hash: Optional[str] = ""
    summary: Optional[str] = None


class ArtifactBindingResponse(BaseModel):
    id: str
    case_id: str
    artifact_type: str
    artifact_id: str
    source_domain: str
    canonical_hash: str
    summary: Optional[str]
    binding_timestamp: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Hypothesis Schemas ───────────────────────────────────────────────────────

class HypothesisCreateRequest(BaseModel):
    hypothesis_title: str = Field(..., min_length=3, max_length=255)
    hypothesis_statement: str = Field(..., min_length=5)
    confidence_score: Optional[float] = Field(0.5, ge=0.0, le=1.0)
    status: Optional[str] = Field("PROPOSED", description="PROPOSED, UNDER_INVESTIGATION, SUPPORTED, REFUTED, INCONCLUSIVE")
    deductions_json: Optional[List[Dict[str, Any]]] = None
    supporting_evidence_ids: Optional[List[str]] = None
    analyst_notes: Optional[str] = None


class HypothesisUpdateRequest(BaseModel):
    hypothesis_title: Optional[str] = None
    hypothesis_statement: Optional[str] = None
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    status: Optional[str] = None
    deductions_json: Optional[List[Dict[str, Any]]] = None
    supporting_evidence_ids: Optional[List[str]] = None
    analyst_notes: Optional[str] = None


class HypothesisResponse(BaseModel):
    id: str
    case_id: str
    hypothesis_title: str
    hypothesis_statement: str
    confidence_score: float
    status: str
    deductions_json: List[Any]
    supporting_evidence_ids: List[Any]
    analyst_notes: Optional[str]
    created_by: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Finding Schemas ──────────────────────────────────────────────────────────

class FindingCreateRequest(BaseModel):
    finding_type: str = Field("OBSERVATION", description="OBSERVATION, CONFIRMED_COMPROMISE, POLICY_VIOLATION, FALSE_ALARM, BENIGN_ANOMALY, INSUFFICIENT_TELEMETRY")
    confidence_score: Optional[float] = Field(0.8, ge=0.0, le=1.0)
    evidence_summary: str = Field(..., min_length=3)
    analyst_conclusion: str = Field(..., min_length=3)
    status: Optional[str] = Field("CONFIRMED", description="DRAFT, CONFIRMED, DISMISSED")
    mitre_technique_id: Optional[str] = None


class FindingResponse(BaseModel):
    id: str
    case_id: str
    finding_type: str
    confidence_score: float
    evidence_summary: str
    analyst_conclusion: str
    status: str
    mitre_technique_id: Optional[str]
    created_by: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Timeline Event Schemas ───────────────────────────────────────────────────

class TimelineEventCreateRequest(BaseModel):
    timestamp: datetime
    event_type: str
    source_domain: str
    artifact_reference: str
    description: str
    hash_reference: Optional[str] = ""
    sequence_order: Optional[int] = 0


class TimelineEventResponse(BaseModel):
    id: str
    case_id: str
    timestamp: datetime
    event_type: str
    source_domain: str
    artifact_reference: str
    description: str
    hash_reference: str
    sequence_order: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Impact Assessment Schemas ────────────────────────────────────────────────

class ImpactAssessmentCreateRequest(BaseModel):
    confidentiality_impact: Optional[str] = Field("NONE", description="NONE, LOW, MODERATE, HIGH, CRITICAL")
    integrity_impact: Optional[str] = Field("NONE", description="NONE, LOW, MODERATE, HIGH, CRITICAL")
    availability_impact: Optional[str] = Field("NONE", description="NONE, LOW, MODERATE, HIGH, CRITICAL")
    business_impact: Optional[str] = Field("NONE", description="NONE, LOW, MODERATE, HIGH, CRITICAL")
    compliance_impact: Optional[str] = Field("NONE", description="NONE, LOW, MODERATE, HIGH, CRITICAL")
    assessment_notes: Optional[str] = ""


class ImpactAssessmentResponse(BaseModel):
    id: str
    case_id: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str
    business_impact: str
    compliance_impact: str
    overall_impact: str
    impact_score: float
    assessment_notes: str
    assessed_by: str
    assessment_hash: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Governance Review & Resolution Schemas ───────────────────────────────────

class ProposeResolutionRequest(BaseModel):
    proposed_resolution: str = Field(..., description="TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_ACTIVITY, SECURITY_INCIDENT, INCONCLUSIVE, INSUFFICIENT_EVIDENCE")
    proposed_notes: Optional[str] = None


class ReviewDecisionRequest(BaseModel):
    decision: str = Field(..., description="APPROVED, CHANGES_REQUESTED, REJECTED")
    review_notes: Optional[str] = None


class InvestigationReviewResponse(BaseModel):
    id: str
    case_id: str
    proposed_by_user_id: str
    proposed_resolution: str
    proposed_notes: Optional[str]
    reviewer_user_id: Optional[str]
    decision: str
    review_notes: Optional[str]
    reviewed_at: Optional[datetime]
    governance_hash: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InvestigationResolutionResponse(BaseModel):
    id: str
    case_id: str
    resolution_type: str
    summary: str
    containment_verified: bool
    root_cause_summary: Optional[str]
    resolved_by: str
    reviewer_id: str
    resolution_hash: str
    ledger_reference: Optional[str]
    merkle_reference: Optional[str]
    resolved_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Provenance Schemas ───────────────────────────────────────────────────────

class InvestigationProvenanceStageResponse(BaseModel):
    stage_number: int
    stage_name: str
    entity_type: str
    entity_reference: str
    previous_hash: str
    current_hash: str
    ledger_reference: Optional[str]
    merkle_reference: Optional[str]
    verified: bool


class InvestigationProvenanceResponse(BaseModel):
    case_id: str
    case_number: str
    total_stages: int
    lineage_integrity: bool
    stages: List[InvestigationProvenanceStageResponse]


# ── Dashboard & Summary Schemas ──────────────────────────────────────────────

class InvestigationDashboardSummary(BaseModel):
    active_investigations: int
    critical_investigations: int
    high_priority_investigations: int
    triage_pending: int
    awaiting_review: int
    resolved_cases: int
    average_investigation_hours: float
    resolution_rate_percent: float
    integrity_status: str
    cases_by_type: Dict[str, int]
    cases_by_domain: Dict[str, int]
    cases_by_status: Dict[str, int]
