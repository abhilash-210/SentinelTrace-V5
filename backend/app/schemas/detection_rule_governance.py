"""
schemas/detection_rule_governance.py
------------------------------------
Pydantic schemas for Detection Rule Governance, Dual-Control Approval,
Rule Versioning, Version Impact Analysis, and Provenance Trace.

Sprint 6C — Detection Rule Governance, Approval Workflow & Version Impact Management.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class DetectionRuleVersionDependencyCreate(BaseModel):
    """Dependency declaration for a candidate rule version."""
    canonical_field: str = Field(..., description="Canonical field name")
    dependency_type: str = Field("REQUIRED", description="'REQUIRED', 'OPTIONAL', 'ENRICHMENT'")
    is_protected_field: bool = Field(False, description="Whether field is protected")


class DetectionRuleVersionDependencyResponse(BaseModel):
    """Response model for a version-scoped dependency snapshot."""
    id: int
    version_id: str
    canonical_field: str
    dependency_type: str
    is_protected_field: bool
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class DetectionRuleVersionCreateRequest(BaseModel):
    """Request model to create a new draft version for a detection rule."""
    parent_version_id: Optional[str] = Field(None, description="Parent version ID if branching")
    rule_name: str = Field(..., description="Governed rule title")
    vendor_name: str = Field(..., description="Vendor applicability scope")
    description: Optional[str] = Field(None, description="Governed description")
    query_signature: Optional[str] = Field(None, description="Query logic / signature")
    severity: str = Field("MEDIUM", description="'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE technique IDs")
    dependencies: List[DetectionRuleVersionDependencyCreate] = Field(
        default_factory=list,
        description="Declared canonical field dependencies for this version",
    )


class DetectionRuleVersionResponse(BaseModel):
    """Response model for a detection rule version snapshot."""
    id: int
    version_id: str
    rule_id: str
    rule_name: str
    version_number: int
    parent_version_id: Optional[str] = None
    vendor_name: str
    description: Optional[str] = None
    query_signature: Optional[str] = None
    severity: str
    mitre_techniques: List[str]
    status: str
    created_by_user_id: str
    created_at: Optional[str] = None
    submitted_at: Optional[str] = None
    submitted_by_user_id: Optional[str] = None
    reviewed_at: Optional[str] = None
    reviewed_by_user_id: Optional[str] = None
    approval_decision: Optional[str] = None
    approval_comment: Optional[str] = None
    risk_acknowledged: bool = False
    risk_acknowledgement_comment: Optional[str] = None
    activated_at: Optional[str] = None
    activated_by_user_id: Optional[str] = None
    superseded_at: Optional[str] = None
    superseded_by_version_id: Optional[str] = None
    version_hash: str
    dependencies: List[DetectionRuleVersionDependencyResponse] = []

    model_config = ConfigDict(from_attributes=True)


class DetectionRuleApprovalRequestResponse(BaseModel):
    """Response model for a dual-control approval request."""
    id: int
    approval_request_id: str
    version_id: str
    rule_id: str
    rule_name: Optional[str] = None
    submitted_by_user_id: str
    submitted_at: Optional[str] = None
    status: str
    reviewed_by_user_id: Optional[str] = None
    reviewed_at: Optional[str] = None
    decision: Optional[str] = None
    review_comment: Optional[str] = None
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class DetectionRuleReviewActionRequest(BaseModel):
    """Request model for reviewer decision."""
    decision: str = Field(..., description="'APPROVE' or 'REJECT'")
    comment: Optional[str] = Field(None, description="Reviewer audit comment")
    risk_acknowledged: bool = Field(False, description="Explicit acknowledgement if version is AT_RISK/INVALID")
    risk_acknowledgement_comment: Optional[str] = Field(None, description="Justification for approving risky version")


class DetectionRuleVersionImpactResponse(BaseModel):
    """Response model for version comparison and impact analysis."""
    id: int
    impact_id: str
    source_version_id: Optional[str] = None
    target_version_id: str
    impact_level: str
    query_changed: bool
    severity_changed: bool
    vendor_scope_changed: bool
    mitre_changed: bool
    dependencies_added: List[str]
    dependencies_removed: List[str]
    protected_fields_added: List[str]
    trust_risk_delta: float
    blast_radius_summary: str
    impact_details: Dict[str, Any]
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class DetectionRuleTrustSimulationResponse(BaseModel):
    """Response model for hypothetical pre-approval trust simulation."""
    simulation_type: str = "PRE_APPROVAL_HYPOTHETICAL"
    version_id: str
    rule_id: str
    rule_name: str
    simulated_score: float
    simulated_state: str
    worst_dependency_field: Optional[str] = None
    reasons: List[str]
    is_safe_to_activate: bool
    requires_risk_acknowledgement: bool


class DetectionRuleGovernanceEventResponse(BaseModel):
    """Response model for immutable governance audit event."""
    id: int
    event_id: str
    rule_id: str
    version_id: Optional[str] = None
    event_type: str
    actor_user_id: str
    actor_role: str
    previous_status: Optional[str] = None
    new_status: Optional[str] = None
    event_payload: Dict[str, Any]
    event_hash: str
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class GovernanceTraceStep(BaseModel):
    """Single stage in the 15-stage governance provenance trace."""
    step_number: int
    stage_name: str
    entity_id: str
    entity_type: str
    summary: str
    details: Dict[str, Any]
    timestamp: Optional[str] = None


class EndToEndGovernanceTraceResponse(BaseModel):
    """Complete 15-stage governance provenance trace."""
    version_id: str
    rule_id: str
    rule_name: str
    version_number: int
    version_hash: str
    status: str
    provenance_chain: List[GovernanceTraceStep]
