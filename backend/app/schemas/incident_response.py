"""
schemas/incident_response.py
----------------------------
Pydantic v2 schemas for Sprint 8B Incident Response Governance,
Playbooks, Deterministic Recommendations, Containment Lifecycle,
Maker-Checker Approvals, Execution Attestations, and 17-Stage Provenance.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


# ── Playbook Schemas ─────────────────────────────────────────────────────────

class PlaybookActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    action_id: str
    playbook_id: str
    action_key: str
    action_name: str
    description: str
    sequence_number: int
    action_type: str
    impact_level: str
    requires_dual_control: bool
    is_mandatory: bool
    created_at: Optional[str] = None


class PlaybookResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    playbook_id: str
    name: str
    description: str
    incident_category: str
    minimum_severity: str
    status: str
    version: str
    is_active: bool
    created_by_user_id: str
    playbook_hash: str
    actions_count: int = 0
    actions: Optional[List[PlaybookActionResponse]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


# ── Recommendation Schemas ──────────────────────────────────────────────────

class RecommendationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    recommendation_id: str
    incident_id: str
    playbook_id: Optional[str] = None
    action_key: str
    action_type: str
    priority: str
    impact_level: str
    confidence_score: float
    reasoning: str
    risk_context: Dict[str, Any] = Field(default_factory=dict)
    status: str
    recommendation_hash: str
    created_at: Optional[str] = None


class RecommendationListResponse(BaseModel):
    incident_id: str
    total_recommendations: int
    recommendations: List[RecommendationResponse]


# ── Containment Request Schemas ─────────────────────────────────────────────

class ContainmentRequestCreate(BaseModel):
    action_type: str = Field(..., description="Action type: ISOLATE_ENDPOINT, DISABLE_ACCOUNT, BLOCK_NETWORK, etc.")
    action_description: str = Field(..., description="Detailed description of containment action")
    impact_level: str = Field("HIGH_IMPACT", description="Impact classification: LOW_IMPACT, MEDIUM_IMPACT, HIGH_IMPACT, CRITICAL_IMPACT")
    risk_justification: str = Field(..., description="Analyst justification explaining containment necessity")
    recommendation_id: Optional[str] = Field(None, description="Optional link to originating recommendation")


class ContainmentReviewRequest(BaseModel):
    decision: str = Field(..., description="Decision: 'APPROVE', 'REJECT', 'REQUEST_CHANGES'")
    reason: str = Field(..., description="Independent reviewer rationale")


class ContainmentApprovalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    approval_id: str
    containment_request_id: str
    decision: str
    decision_reason: str
    reviewer_user_id: str
    approval_hash: str
    governance_event_id: Optional[str] = None
    created_at: Optional[str] = None


class ExecutionAttestationRequest(BaseModel):
    execution_status: str = Field("EXECUTION_ATTESTED", description="'EXECUTION_ATTESTED', 'EXECUTION_FAILED', 'NOT_EXECUTED'")
    execution_reference: str = Field(..., description="External change ticket or SOC reference (e.g. SOC-CHG-2026-001)")
    execution_notes: str = Field(..., description="Operator attestation notes and execution telemetry")


class ExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    execution_id: str
    containment_request_id: str
    execution_status: str
    execution_notes: str
    executed_by_user_id: str
    execution_reference: str
    attestation_hash: str
    attested_at: Optional[str] = None


class VerificationRequest(BaseModel):
    verification_status: str = Field("VERIFIED", description="'VERIFIED', 'FAILED', 'INCONCLUSIVE'")
    verification_method: str = Field(..., description="'LOG_REVIEW', 'NETWORK_TELEMETRY', 'ENDPOINT_TELEMETRY', 'AUTHENTICATION_AUDIT', 'MANUAL_CONFIRMATION'")
    verification_evidence: str = Field(..., description="Technical evidence and observations confirming outcome")
    verification_notes: Optional[str] = Field(None, description="Additional verification notes")


class VerificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    verification_id: str
    containment_request_id: str
    verification_status: str
    verification_method: str
    verification_evidence: str
    verified_by_user_id: str
    verification_notes: Optional[str] = None
    verification_hash: str
    verified_at: Optional[str] = None


class ContainmentRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    request_id: str
    incident_id: str
    recommendation_id: Optional[str] = None
    action_type: str
    action_description: str
    impact_level: str
    risk_justification: str
    proposed_by_user_id: str
    reviewed_by_user_id: Optional[str] = None
    approved_by_user_id: Optional[str] = None
    status: str
    proposed_at: Optional[str] = None
    reviewed_at: Optional[str] = None
    approved_at: Optional[str] = None
    execution_attested_at: Optional[str] = None
    verification_completed_at: Optional[str] = None
    request_hash: str
    governance_ledger_entry_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    approvals: Optional[List[ContainmentApprovalResponse]] = None
    executions: Optional[List[ExecutionResponse]] = None
    verifications: Optional[List[VerificationResponse]] = None


# ── Provenance Trace Schemas ────────────────────────────────────────────────

class ProvenanceStage(BaseModel):
    stage_number: int
    stage_name: str
    entity_type: str
    entity_id: str
    status: str
    summary: str
    timestamp: Optional[str] = None
    hash_reference: Optional[str] = None


class ResponseTraceResponse(BaseModel):
    incident_id: str
    total_stages: int
    is_complete: bool
    stages: List[ProvenanceStage]
