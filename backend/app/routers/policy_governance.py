"""
routers/policy_governance.py
----------------------------
Dual-Control Policy Approval & Governance REST API Endpoints.

Sprint 4B — Dual-Control Approval & Policy Governance Workflow.
Provides:
- POST /api/v1/semantic-policies/{policy_id}/submit
- GET  /api/v1/policy-approvals
- GET  /api/v1/policy-approvals/{approval_id}
- POST /api/v1/policy-approvals/{approval_id}/approve
- POST /api/v1/policy-approvals/{approval_id}/reject
- POST /api/v1/semantic-policies/{policy_id}/activate
- GET  /api/v1/semantic-policies/{policy_id}/governance-history
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, require_permission
from app.database import get_db
from app.models.user import User
from app.schemas.governance import (
    GovernanceTimelineResponse,
    PolicyActivationResponse,
    PolicyApprovalDetailResponse,
    PolicyApprovalListResponse,
    PolicyApprovalResponse,
    PolicyApprovalSubmitResponse,
    PolicyReviewActionRequest,
)
from app.services.policy_governance_service import PolicyGovernanceService

logger = logging.getLogger("sentinel.routers.governance")

router = APIRouter(tags=["Dual-Control Policy Governance"])


# ── 1. Submit Policy for Review ────────────────────────────────────────────────
@router.post(
    "/api/v1/semantic-policies/{policy_id}/submit",
    response_model=PolicyApprovalSubmitResponse,
    summary="Submit Semantic Policy for Review",
    description="Transitions a DRAFT policy to PENDING_REVIEW and registers a formal dual-control approval ticket.",
    responses={
        200: {"description": "Policy successfully submitted for review"},
        403: {"description": "Forbidden - Insufficient permissions"},
        404: {"description": "Policy not found"},
        409: {"description": "Invalid lifecycle transition (policy not DRAFT)"},
    },
)
def submit_policy_for_review(
    policy_id: str,
    current_user: User = Depends(require_permission("SEMANTIC_POLICY_SUBMIT")),
    db: Session = Depends(get_db),
) -> PolicyApprovalSubmitResponse:
    """Submit a draft policy for maker-checker review."""
    policy, approval = PolicyGovernanceService.submit_for_review(
        db=db,
        policy_id=policy_id,
        current_user=current_user,
    )
    return PolicyApprovalSubmitResponse(
        policy_id=policy.policy_id,
        policy_status=policy.status,
        approval_id=approval.approval_id,
        approval_status=approval.status,
        requested_by=current_user.username,
        requested_at=approval.requested_at.isoformat(),
    )


# ── 2. List Approval Requests ──────────────────────────────────────────────────
@router.get(
    "/api/v1/policy-approvals",
    response_model=PolicyApprovalListResponse,
    summary="List Policy Approval Tickets",
    description="Retrieves paginated dual-control approval tickets with filter support.",
    responses={
        200: {"description": "List of approval tickets"},
        403: {"description": "Forbidden"},
    },
)
def list_policy_approvals(
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by status (PENDING, APPROVED, REJECTED)"),
    policy_id: Optional[str] = Query(default=None, description="Filter by policy ID"),
    requested_by: Optional[str] = Query(default=None, description="Filter by requester user ID"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    current_user: User = Depends(require_permission("POLICY_REVIEW")),
    db: Session = Depends(get_db),
) -> PolicyApprovalListResponse:
    """List approval requests."""
    items, total, pending, approved, rejected = PolicyGovernanceService.list_approval_requests(
        db=db,
        status_filter=status_filter,
        policy_id=policy_id,
        requested_by=requested_by,
        skip=skip,
        limit=limit,
    )
    return PolicyApprovalListResponse(
        total=total,
        pending_count=pending,
        approved_count=approved,
        rejected_count=rejected,
        items=[PolicyApprovalResponse(**item) for item in items],
    )


# ── 3. Get Approval Ticket Details ─────────────────────────────────────────────
@router.get(
    "/api/v1/policy-approvals/{approval_id}",
    response_model=PolicyApprovalDetailResponse,
    summary="Get Detailed Approval Ticket",
    description="Inspects policy rules, protected field impacts, and maker-checker metadata.",
    responses={
        200: {"description": "Detailed approval ticket"},
        404: {"description": "Approval request not found"},
    },
)
def get_policy_approval_details(
    approval_id: str,
    current_user: User = Depends(require_permission("POLICY_REVIEW")),
    db: Session = Depends(get_db),
) -> PolicyApprovalDetailResponse:
    """Retrieve deep approval ticket context."""
    details = PolicyGovernanceService.get_approval_details(db=db, approval_id=approval_id)
    return PolicyApprovalDetailResponse(**details)


# ── 4. Approve Policy (Maker-Checker Enforced) ─────────────────────────────────
@router.post(
    "/api/v1/policy-approvals/{approval_id}/approve",
    response_model=PolicyApprovalResponse,
    summary="Approve Policy (Maker-Checker Enforced)",
    description="Approves a pending policy. Policy author cannot self-approve their own submission.",
    responses={
        200: {"description": "Policy successfully approved"},
        403: {"description": "Forbidden - Self-approval violation or insufficient role"},
        404: {"description": "Ticket not found"},
        409: {"description": "Ticket already processed"},
    },
)
def approve_policy_request(
    approval_id: str,
    request: PolicyReviewActionRequest = PolicyReviewActionRequest(),
    current_user: User = Depends(require_permission("POLICY_APPROVE")),
    db: Session = Depends(get_db),
) -> PolicyApprovalResponse:
    """Approve a policy ticket."""
    approval, policy = PolicyGovernanceService.approve_policy(
        db=db,
        approval_id=approval_id,
        current_user=current_user,
        review_comment=request.review_comment,
    )
    item_dict = approval.to_dict()
    item_dict["policy_name"] = policy.policy_name
    item_dict["vendor_name"] = policy.vendor_name
    item_dict["version"] = policy.version
    item_dict["policy_status"] = policy.status
    item_dict["requested_by_username"] = approval.requested_by_user_id
    item_dict["reviewed_by_username"] = current_user.username
    return PolicyApprovalResponse(**item_dict)


# ── 5. Reject Policy ───────────────────────────────────────────────────────────
@router.post(
    "/api/v1/policy-approvals/{approval_id}/reject",
    response_model=PolicyApprovalResponse,
    summary="Reject Policy Request",
    description="Rejects a pending policy submission and records reviewer comments.",
    responses={
        200: {"description": "Policy rejected"},
        403: {"description": "Forbidden - Self-review violation or insufficient role"},
        404: {"description": "Ticket not found"},
        409: {"description": "Ticket already processed"},
    },
)
def reject_policy_request(
    approval_id: str,
    request: PolicyReviewActionRequest = PolicyReviewActionRequest(),
    current_user: User = Depends(require_permission("POLICY_REJECT")),
    db: Session = Depends(get_db),
) -> PolicyApprovalResponse:
    """Reject a policy ticket."""
    approval, policy = PolicyGovernanceService.reject_policy(
        db=db,
        approval_id=approval_id,
        current_user=current_user,
        review_comment=request.review_comment,
    )
    item_dict = approval.to_dict()
    item_dict["policy_name"] = policy.policy_name
    item_dict["vendor_name"] = policy.vendor_name
    item_dict["version"] = policy.version
    item_dict["policy_status"] = policy.status
    item_dict["requested_by_username"] = approval.requested_by_user_id
    item_dict["reviewed_by_username"] = current_user.username
    return PolicyApprovalResponse(**item_dict)


# ── 6. Activate Approved Policy ────────────────────────────────────────────────
@router.post(
    "/api/v1/semantic-policies/{policy_id}/activate",
    response_model=PolicyActivationResponse,
    summary="Activate Approved Policy",
    description="Transitions an APPROVED policy to ACTIVE, superseding any prior active policy version for the vendor.",
    responses={
        200: {"description": "Policy successfully activated and prior version superseded"},
        403: {"description": "Forbidden - Insufficient permissions"},
        404: {"description": "Policy not found"},
        409: {"description": "Policy is not APPROVED (direct DRAFT->ACTIVE blocked)"},
    },
)
def activate_approved_policy(
    policy_id: str,
    current_user: User = Depends(require_permission("POLICY_ACTIVATE")),
    db: Session = Depends(get_db),
) -> PolicyActivationResponse:
    """Activate an approved policy."""
    policy, superseded_policy, audit_id = PolicyGovernanceService.activate_policy(
        db=db,
        policy_id=policy_id,
        current_user=current_user,
    )
    return PolicyActivationResponse(
        activated_policy_id=policy.policy_id,
        activated_version=policy.version,
        vendor_name=policy.vendor_name,
        status=policy.status,
        superseded_policy_id=superseded_policy.policy_id if superseded_policy else None,
        activated_by=current_user.username,
        activated_at=policy.updated_at.isoformat(),
        audit_id=audit_id,
    )


# ── 7. Policy Governance History Timeline ──────────────────────────────────────
@router.get(
    "/api/v1/semantic-policies/{policy_id}/governance-history",
    response_model=GovernanceTimelineResponse,
    summary="Get Policy Governance Audit Timeline",
    description="Retrieves the immutable, chronological governance audit events for a semantic policy.",
    responses={
        200: {"description": "Chronological governance audit history"},
        403: {"description": "Forbidden"},
        404: {"description": "Policy not found"},
    },
)
def get_policy_governance_history(
    policy_id: str,
    current_user: User = Depends(require_permission("GOVERNANCE_AUDIT_READ")),
    db: Session = Depends(get_db),
) -> GovernanceTimelineResponse:
    """Retrieve full governance timeline."""
    history = PolicyGovernanceService.get_governance_history(db=db, policy_id=policy_id)
    return GovernanceTimelineResponse(**history)
