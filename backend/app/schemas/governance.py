"""
schemas/governance.py
--------------------
Pydantic response and request schemas for Dual-Control Policy Governance, Approvals, and Audit Trails.

Sprint 4B — Dual-Control Approval & Policy Governance Workflow.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.semantic_policy import SemanticPolicyDetailResponse, SemanticPolicyRuleResponse


class PolicyApprovalSubmitResponse(BaseModel):
    """Response returned upon submitting a policy for review."""
    policy_id: str
    policy_status: str
    approval_id: str
    approval_status: str
    requested_by: str
    requested_at: str


class PolicyReviewActionRequest(BaseModel):
    """Request payload for approving or rejecting a policy."""
    review_comment: Optional[str] = Field(
        default=None,
        description="Reviewer rationale, compliance notes, or rejection reason",
    )


class PolicyApprovalResponse(BaseModel):
    """Standard approval request summary response."""
    approval_id: str
    policy_id: str
    policy_name: Optional[str] = None
    vendor_name: Optional[str] = None
    version: Optional[int] = 1
    requested_by_user_id: str
    requested_by_username: Optional[str] = None
    requested_at: str
    status: str
    reviewed_by_user_id: Optional[str] = None
    reviewed_by_username: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_comment: Optional[str] = None
    policy_status: Optional[str] = None
    created_at: str
    updated_at: str


class PolicyApprovalDetailResponse(BaseModel):
    """Detailed approval view with full policy inspection, rules, and protected field impacts."""
    approval_id: str
    policy_id: str
    status: str
    requested_by_user_id: str
    requested_by_username: str
    requested_at: str
    reviewed_by_user_id: Optional[str] = None
    reviewed_by_username: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_comment: Optional[str] = None
    policy: SemanticPolicyDetailResponse
    rule_count: int
    protected_field_impact_count: int
    protected_field_summary: List[str]
    supersedes_policy_id: Optional[str] = None
    maker_checker_warning: str = Field(
        default="MAKER-CHECKER SEPARATION: The policy creator cannot approve this policy."
    )


class PolicyApprovalListResponse(BaseModel):
    """Paginated list of policy approval tickets."""
    total: int
    pending_count: int
    approved_count: int
    rejected_count: int
    items: List[PolicyApprovalResponse]


class PolicyActivationResponse(BaseModel):
    """Response returned upon successfully activating an approved policy."""
    activated_policy_id: str
    activated_version: int
    vendor_name: str
    status: str
    superseded_policy_id: Optional[str] = None
    activated_by: str
    activated_at: str
    audit_id: str


class GovernanceAuditItemResponse(BaseModel):
    """Single chronological governance audit event entry."""
    audit_id: str
    actor_user_id: str
    actor_username: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: str
    previous_state: Optional[str] = None
    new_state: Optional[str] = None
    reason: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class GovernanceTimelineResponse(BaseModel):
    """Chronological governance history timeline for a semantic policy."""
    policy_id: str
    policy_name: str
    vendor_name: str
    version: int
    status: str
    supersedes_policy_id: Optional[str] = None
    timeline: List[GovernanceAuditItemResponse]
