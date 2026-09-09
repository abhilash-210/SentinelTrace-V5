"""
services/policy_governance_service.py
------------------------------------
Service layer for Dual-Control Policy Governance, Maker-Checker Approvals,
Lifecycle State Machine, and Immutable Audit Trails.

Sprint 4B — Dual-Control Approval & Policy Governance Workflow.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.governance import GovernanceAuditLog, PolicyApprovalRequest
from app.models.semantic_policy import ProtectedSemanticField, SemanticPolicy, SemanticPolicyRule
from app.models.user import User
from app.services.governance_ledger_service import GovernanceLedgerService

logger = logging.getLogger("sentinel.services.governance")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PolicyGovernanceService:
    """
    Centralized governance service enforcing:
    1. Explicit policy lifecycle state transitions
    2. Maker-checker dual control (separation of duties)
    3. Immutable append-only audit trail logging
    4. Controlled atomic policy activation and supersession
    """

    ALLOWED_TRANSITIONS = {
        "DRAFT": {"PENDING_REVIEW"},
        "PENDING_REVIEW": {"APPROVED", "REJECTED"},
        "APPROVED": {"ACTIVE"},
        "ACTIVE": {"SUPERSEDED"},
        "REJECTED": {"DRAFT"},
        "SUPERSEDED": set(),
    }

    @staticmethod
    def validate_transition(current_status: str, target_status: str) -> None:
        """
        Validates state machine transitions. Raises HTTP 409 Conflict if invalid.
        """
        allowed = PolicyGovernanceService.ALLOWED_TRANSITIONS.get(current_status, set())
        if target_status not in allowed:
            logger.warning(
                f"Invalid policy state transition attempted: {current_status} -> {target_status}"
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"INVALID_POLICY_STATE_TRANSITION: Cannot transition policy from '{current_status}' to '{target_status}'. "
                    f"Required path is DRAFT -> PENDING_REVIEW -> APPROVED -> ACTIVE."
                ),
            )

    @staticmethod
    def log_governance_audit(
        db: Session,
        actor: User,
        action: str,
        resource_id: str,
        resource_type: str = "SEMANTIC_POLICY",
        previous_state: Optional[str] = None,
        new_state: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GovernanceAuditLog:
        """
        Appends an immutable audit log entry for governance accountability.
        """
        audit_entry = GovernanceAuditLog(
            audit_id=f"audit_{uuid.uuid4().hex[:12]}",
            actor_user_id=actor.user_id,
            actor_username=actor.username,
            actor_role=actor.role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            previous_state=previous_state,
            new_state=new_state,
            reason=reason,
            metadata_json=metadata or {},
            created_at=utcnow(),
        )
        db.add(audit_entry)
        db.flush()

        # Cryptographically chain this governance event into the append-only ledger (Sprint 5A)
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type=action,
                actor_id=actor.user_id,
                actor_username=actor.username,
                payload={
                    "audit_id": audit_entry.audit_id,
                    "action": action,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "previous_state": previous_state,
                    "new_state": new_state,
                    "reason": reason,
                    "actor_role": actor.role,
                    "metadata": metadata or {},
                },
            )
        except Exception as e:
            logger.error(f"Failed to append governance ledger entry: {e}")

        logger.info(
            f"Governance Audit [{action}] by '{actor.username}' ({actor.role}) on {resource_type}:{resource_id}"
        )
        return audit_entry

    @staticmethod
    def submit_for_review(
        db: Session,
        policy_id: str,
        current_user: User,
    ) -> Tuple[SemanticPolicy, PolicyApprovalRequest]:
        """
        Submits a DRAFT semantic policy for formal dual-control review.
        """
        policy = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == policy_id).first()
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Semantic policy '{policy_id}' not found.",
            )

        # Validate transition from DRAFT -> PENDING_REVIEW
        PolicyGovernanceService.validate_transition(policy.status, "PENDING_REVIEW")

        prev_state = policy.status
        policy.status = "PENDING_REVIEW"
        policy.updated_at = utcnow()

        # Create approval request ticket
        approval = PolicyApprovalRequest(
            approval_id=f"approval_{uuid.uuid4().hex[:12]}",
            policy_id=policy.policy_id,
            requested_by_user_id=current_user.user_id,
            requested_at=utcnow(),
            status="PENDING",
        )
        db.add(approval)
        db.flush()

        # Log audit entry
        PolicyGovernanceService.log_governance_audit(
            db=db,
            actor=current_user,
            action="POLICY_SUBMITTED",
            resource_id=policy.policy_id,
            resource_type="SEMANTIC_POLICY",
            previous_state=prev_state,
            new_state="PENDING_REVIEW",
            reason="Submitted for dual-control governance review.",
            metadata={
                "approval_id": approval.approval_id,
                "policy_name": policy.policy_name,
                "vendor_name": policy.vendor_name,
                "version": policy.version,
                "rule_count": len(policy.rules),
            },
        )

        db.commit()
        db.refresh(policy)
        db.refresh(approval)
        return policy, approval

    @staticmethod
    def list_approval_requests(
        db: Session,
        status_filter: Optional[str] = None,
        policy_id: Optional[str] = None,
        requested_by: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int, int, int, int]:
        """
        Lists approval requests with metadata and breakdown counts.
        """
        query = db.query(PolicyApprovalRequest)

        if status_filter:
            query = query.filter(PolicyApprovalRequest.status == status_filter.upper())
        if policy_id:
            query = query.filter(PolicyApprovalRequest.policy_id == policy_id)
        if requested_by:
            query = query.filter(PolicyApprovalRequest.requested_by_user_id == requested_by)

        total = query.count()
        approvals = (
            query.order_by(PolicyApprovalRequest.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

        # Get metric counts
        pending_count = (
            db.query(PolicyApprovalRequest)
            .filter(PolicyApprovalRequest.status == "PENDING")
            .count()
        )
        approved_count = (
            db.query(PolicyApprovalRequest)
            .filter(PolicyApprovalRequest.status == "APPROVED")
            .count()
        )
        rejected_count = (
            db.query(PolicyApprovalRequest)
            .filter(PolicyApprovalRequest.status == "REJECTED")
            .count()
        )

        # Enhance with policy and user details
        items = []
        for app in approvals:
            pol = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == app.policy_id).first()
            req_user = db.query(User).filter(User.user_id == app.requested_by_user_id).first()
            rev_user = (
                db.query(User).filter(User.user_id == app.reviewed_by_user_id).first()
                if app.reviewed_by_user_id
                else None
            )

            item_dict = app.to_dict()
            item_dict["policy_name"] = pol.policy_name if pol else None
            item_dict["vendor_name"] = pol.vendor_name if pol else None
            item_dict["version"] = pol.version if pol else 1
            item_dict["policy_status"] = pol.status if pol else None
            item_dict["requested_by_username"] = req_user.username if req_user else app.requested_by_user_id
            item_dict["reviewed_by_username"] = rev_user.username if rev_user else None
            items.append(item_dict)

        return items, total, pending_count, approved_count, rejected_count

    @staticmethod
    def get_approval_details(db: Session, approval_id: str) -> Dict[str, Any]:
        """
        Retrieves rich approval ticket details including rules and protected field impacts.
        """
        approval = (
            db.query(PolicyApprovalRequest)
            .filter(PolicyApprovalRequest.approval_id == approval_id)
            .first()
        )
        if not approval:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy approval request '{approval_id}' not found.",
            )

        policy = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == approval.policy_id).first()
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Associated semantic policy '{approval.policy_id}' not found.",
            )

        req_user = db.query(User).filter(User.user_id == approval.requested_by_user_id).first()
        rev_user = (
            db.query(User).filter(User.user_id == approval.reviewed_by_user_id).first()
            if approval.reviewed_by_user_id
            else None
        )

        # Protected field impact summary
        protected_fields = {
            f.field_name
            for f in db.query(ProtectedSemanticField).filter(ProtectedSemanticField.is_protected == True).all()
        }
        rules = policy.rules or []
        impacted_protected_fields = sorted(
            list({r.canonical_field for r in rules if r.canonical_field in protected_fields})
        )

        return {
            "approval_id": approval.approval_id,
            "policy_id": approval.policy_id,
            "status": approval.status,
            "requested_by_user_id": approval.requested_by_user_id,
            "requested_by_username": req_user.username if req_user else approval.requested_by_user_id,
            "requested_at": approval.requested_at.isoformat(),
            "reviewed_by_user_id": approval.reviewed_by_user_id,
            "reviewed_by_username": rev_user.username if rev_user else None,
            "reviewed_at": approval.reviewed_at.isoformat() if approval.reviewed_at else None,
            "review_comment": approval.review_comment,
            "policy": policy.to_dict(),
            "rule_count": len(rules),
            "protected_field_impact_count": len(impacted_protected_fields),
            "protected_field_summary": impacted_protected_fields,
            "supersedes_policy_id": policy.supersedes_policy_id,
            "maker_checker_warning": "MAKER-CHECKER SEPARATION: The policy creator cannot approve this policy.",
        }

    @staticmethod
    def approve_policy(
        db: Session,
        approval_id: str,
        current_user: User,
        review_comment: Optional[str] = None,
    ) -> Tuple[PolicyApprovalRequest, SemanticPolicy]:
        """
        Approves a pending policy with strict Maker-Checker separation enforcement.
        """
        approval = (
            db.query(PolicyApprovalRequest)
            .filter(PolicyApprovalRequest.approval_id == approval_id)
            .first()
        )
        if not approval:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy approval request '{approval_id}' not found.",
            )

        if approval.status != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Approval request '{approval_id}' is already {approval.status} and cannot be approved again.",
            )

        # ── CRITICAL SECURITY CONTROL: MAKER-CHECKER SEPARATION ──────────────────
        if current_user.user_id == approval.requested_by_user_id:
            logger.warning(
                f"SECURITY VIOLATION: User '{current_user.username}' attempted self-approval of ticket {approval_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="SELF_APPROVAL_FORBIDDEN: Maker-checker violation. Policy creators cannot approve their own policy.",
            )

        policy = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == approval.policy_id).first()
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy '{approval.policy_id}' not found.",
            )

        # Validate transition: PENDING_REVIEW -> APPROVED
        PolicyGovernanceService.validate_transition(policy.status, "APPROVED")

        prev_state = policy.status
        policy.status = "APPROVED"
        policy.updated_at = utcnow()

        approval.status = "APPROVED"
        approval.reviewed_by_user_id = current_user.user_id
        approval.reviewed_at = utcnow()
        approval.review_comment = review_comment or "Policy approved following governance inspection."
        approval.updated_at = utcnow()

        # Log audit entry
        PolicyGovernanceService.log_governance_audit(
            db=db,
            actor=current_user,
            action="POLICY_APPROVED",
            resource_id=policy.policy_id,
            resource_type="SEMANTIC_POLICY",
            previous_state=prev_state,
            new_state="APPROVED",
            reason=approval.review_comment,
            metadata={
                "approval_id": approval.approval_id,
                "requested_by_user_id": approval.requested_by_user_id,
                "reviewed_by_user_id": current_user.user_id,
                "vendor_name": policy.vendor_name,
                "version": policy.version,
            },
        )

        db.commit()
        db.refresh(approval)
        db.refresh(policy)
        return approval, policy

    @staticmethod
    def reject_policy(
        db: Session,
        approval_id: str,
        current_user: User,
        review_comment: Optional[str] = None,
    ) -> Tuple[PolicyApprovalRequest, SemanticPolicy]:
        """
        Rejects a pending policy with reviewer comments and audit trail.
        """
        approval = (
            db.query(PolicyApprovalRequest)
            .filter(PolicyApprovalRequest.approval_id == approval_id)
            .first()
        )
        if not approval:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy approval request '{approval_id}' not found.",
            )

        if approval.status != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Approval request '{approval_id}' is already {approval.status} and cannot be modified.",
            )

        # Maker-checker check: creator cannot reject own ticket (should cancel instead)
        if current_user.user_id == approval.requested_by_user_id:
            logger.warning(
                f"SECURITY VIOLATION: User '{current_user.username}' attempted self-review of ticket {approval_id}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="SELF_APPROVAL_FORBIDDEN: Maker-checker violation. Policy creators cannot reject or review their own policy.",
            )

        policy = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == approval.policy_id).first()
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Policy '{approval.policy_id}' not found.",
            )

        # Validate transition: PENDING_REVIEW -> REJECTED
        PolicyGovernanceService.validate_transition(policy.status, "REJECTED")

        prev_state = policy.status
        policy.status = "REJECTED"
        policy.updated_at = utcnow()

        approval.status = "REJECTED"
        approval.reviewed_by_user_id = current_user.user_id
        approval.reviewed_at = utcnow()
        approval.review_comment = review_comment or "Policy rejected during governance inspection."
        approval.updated_at = utcnow()

        # Log audit entry
        PolicyGovernanceService.log_governance_audit(
            db=db,
            actor=current_user,
            action="POLICY_REJECTED",
            resource_id=policy.policy_id,
            resource_type="SEMANTIC_POLICY",
            previous_state=prev_state,
            new_state="REJECTED",
            reason=approval.review_comment,
            metadata={
                "approval_id": approval.approval_id,
                "requested_by_user_id": approval.requested_by_user_id,
                "reviewed_by_user_id": current_user.user_id,
                "vendor_name": policy.vendor_name,
                "version": policy.version,
            },
        )

        db.commit()
        db.refresh(approval)
        db.refresh(policy)
        return approval, policy

    @staticmethod
    def activate_policy(
        db: Session,
        policy_id: str,
        current_user: User,
    ) -> Tuple[SemanticPolicy, Optional[SemanticPolicy], str]:
        """
        Activates an APPROVED policy with atomic transaction safety and version supersession.
        """
        policy = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == policy_id).first()
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Semantic policy '{policy_id}' not found.",
            )

        # Strict validation: ONLY APPROVED policies can be activated
        if policy.status != "APPROVED":
            PolicyGovernanceService.validate_transition(policy.status, "ACTIVE")

        # Begin atomic activation
        superseded_policy = None
        # Find active policy for same vendor and source_profile
        existing_active = (
            db.query(SemanticPolicy)
            .filter(
                SemanticPolicy.vendor_name == policy.vendor_name,
                SemanticPolicy.source_profile_id == policy.source_profile_id,
                SemanticPolicy.status == "ACTIVE",
                SemanticPolicy.policy_id != policy.policy_id,
            )
            .first()
        )

        if existing_active:
            existing_active.status = "SUPERSEDED"
            existing_active.updated_at = utcnow()
            superseded_policy = existing_active

            # Link lineage if not set
            if not policy.supersedes_policy_id:
                policy.supersedes_policy_id = existing_active.policy_id

            PolicyGovernanceService.log_governance_audit(
                db=db,
                actor=current_user,
                action="POLICY_SUPERSEDED",
                resource_id=existing_active.policy_id,
                resource_type="SEMANTIC_POLICY",
                previous_state="ACTIVE",
                new_state="SUPERSEDED",
                reason=f"Superseded by newly activated policy '{policy.policy_id}' v{policy.version}.",
                metadata={
                    "superseded_by": policy.policy_id,
                    "vendor_name": policy.vendor_name,
                },
            )

        prev_state = policy.status
        policy.status = "ACTIVE"
        policy.updated_at = utcnow()

        audit_entry = PolicyGovernanceService.log_governance_audit(
            db=db,
            actor=current_user,
            action="POLICY_ACTIVATED",
            resource_id=policy.policy_id,
            resource_type="SEMANTIC_POLICY",
            previous_state=prev_state,
            new_state="ACTIVE",
            reason="Approved policy activated into live production interpretation pipeline.",
            metadata={
                "vendor_name": policy.vendor_name,
                "version": policy.version,
                "superseded_policy_id": superseded_policy.policy_id if superseded_policy else None,
            },
        )

        db.commit()
        db.refresh(policy)
        if superseded_policy:
            db.refresh(superseded_policy)

        logger.info(
            f"Policy '{policy.policy_id}' v{policy.version} successfully ACTIVATED by '{current_user.username}'"
        )
        return policy, superseded_policy, audit_entry.audit_id

    @staticmethod
    def get_governance_history(db: Session, policy_id: str) -> Dict[str, Any]:
        """
        Returns full chronological governance audit timeline for a semantic policy.
        """
        policy = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == policy_id).first()
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Semantic policy '{policy_id}' not found.",
            )

        audit_records = (
            db.query(GovernanceAuditLog)
            .filter(
                GovernanceAuditLog.resource_id == policy_id,
                GovernanceAuditLog.resource_type == "SEMANTIC_POLICY",
            )
            .order_by(GovernanceAuditLog.created_at.asc())
            .all()
        )

        return {
            "policy_id": policy.policy_id,
            "policy_name": policy.policy_name,
            "vendor_name": policy.vendor_name,
            "version": policy.version,
            "status": policy.status,
            "supersedes_policy_id": policy.supersedes_policy_id,
            "timeline": [r.to_dict() for r in audit_records],
        }
