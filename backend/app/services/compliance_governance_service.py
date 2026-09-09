"""
services/compliance_governance_service.py
-----------------------------------------
Maker-Checker Dual Governance, Self-Approval Blocking & Finding Workflows.

Sprint 11A — Compliance Intelligence, Security Control Governance & Evidence-Backed Compliance Assurance.

Core Invariant: "COMPLIANCE MUST BE EVIDENCE-BACKED, EXPLAINABLE, HUMAN-GOVERNED, AND CRYPTOGRAPHICALLY VERIFIABLE."
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.compliance_intelligence import (
    ComplianceFinding,
    ComplianceReview,
    CompliancePostureEvaluation,
    COMPLIANCE_FINDING_DOMAIN_PREFIX,
    COMPLIANCE_REVIEW_DOMAIN_PREFIX,
    calculate_compliance_hash,
    utcnow,
)
from app.services.governance_ledger_service import GovernanceLedgerService

logger = logging.getLogger("sentinel.services.compliance_governance")


class SelfApprovalForbiddenError(Exception):
    """Raised when an actor attempts to approve their own compliance evaluation, posture, or finding."""
    def __init__(self, message: str = "Maker-Checker violation: Evaluator/author cannot approve their own submission."):
        super().__init__(message)
        self.message = message


class ComplianceGovernanceService:
    """Service for Maker-Checker dual control review, finding management, and self-approval block enforcement."""

    @classmethod
    def create_finding(
        cls,
        db: Session,
        framework_requirement_id: Optional[str],
        security_control_id: Optional[str],
        title: str,
        description: str,
        creator_user_id: str,
        finding_type: str = "NON_COMPLIANCE",
        confidence: str = "HIGH",
    ) -> ComplianceFinding:
        """
        Creates a formal compliance finding.
        """
        now = utcnow()
        finding_number = f"CFN-{now.strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"

        finding_payload = {
            "finding_number": finding_number,
            "requirement_id": framework_requirement_id,
            "control_id": security_control_id,
            "statement": title,
            "evidence_summary": description,
            "finding_type": finding_type,
            "created_by": creator_user_id,
            "created_at": now.isoformat(),
        }
        finding_hash = calculate_compliance_hash(COMPLIANCE_FINDING_DOMAIN_PREFIX, finding_payload)

        finding = ComplianceFinding(
            finding_number=finding_number,
            framework_requirement_id=framework_requirement_id,
            security_control_id=security_control_id,
            finding_type=finding_type,
            statement=title,
            evidence_summary=description,
            confidence=confidence,
            status="DRAFT",
            created_by_user_id=creator_user_id,
            finding_hash=finding_hash,
            created_at=now,
        )
        db.add(finding)
        db.flush()

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="COMPLIANCE_FINDING_CREATED",
                actor_id=creator_user_id,
                actor_username=creator_user_id,
                payload={
                    "entity_type": "COMPLIANCE_FINDING",
                    "entity_id": finding.id,
                    "finding_number": finding_number,
                    "statement": title,
                    "finding_hash": finding_hash,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to log finding to ledger: {e}")

        logger.info(f"Created compliance finding {finding_number}: {title}")
        return finding

    @classmethod
    def submit_review(
        cls,
        db: Session,
        compliance_posture_evaluation_id: str,
        review_action: str,  # APPROVE, REJECT, REQUEST_REASSESSMENT
        review_comment: str,
        reviewer_user_id: str,
        initiator_user_id: Optional[str] = None,
    ) -> ComplianceReview:
        """
        Executes a dual-control human governance review.
        STRICTLY BLOCKS SELF-APPROVAL: If reviewer is the initiator, rejects with SelfApprovalForbiddenError.
        """
        # 1. Self-approval verification
        if initiator_user_id and reviewer_user_id and str(initiator_user_id).lower() == str(reviewer_user_id).lower():
            logger.warning(
                f"Self-approval attempt blocked for actor '{reviewer_user_id}' on posture {compliance_posture_evaluation_id}"
            )
            try:
                GovernanceLedgerService.append_entry(
                    db=db,
                    event_type="COMPLIANCE_SELF_APPROVAL_ATTEMPT_BLOCKED",
                    actor_id=reviewer_user_id,
                    actor_username=reviewer_user_id,
                    payload={
                        "target_entity_id": compliance_posture_evaluation_id,
                        "initiator_user_id": initiator_user_id,
                        "reviewer_user_id": reviewer_user_id,
                        "reason": "Maker-Checker violation: Evaluator/author cannot approve their own submission.",
                    },
                )
            except Exception as e:
                logger.warning(f"Failed to log self-approval attempt to ledger: {e}")

            raise SelfApprovalForbiddenError(
                f"Maker-Checker violation: User '{reviewer_user_id}' cannot review/approve their own submission."
            )

        now = utcnow()

        # Update finding if target entity is finding
        finding = db.query(ComplianceFinding).filter(ComplianceFinding.id == compliance_posture_evaluation_id).first()
        if finding:
            if review_action == "APPROVE":
                finding.status = "VALIDATED"
            elif review_action == "REJECT":
                finding.status = "REJECTED"
            else:
                finding.status = "PENDING_REVIEW"
            finding.reviewed_by_user_id = reviewer_user_id
            finding.reviewed_at = now

        review_payload = {
            "posture_evaluation_id": compliance_posture_evaluation_id,
            "reviewer_id": reviewer_user_id,
            "review_action": review_action,
            "review_comment": review_comment,
            "reviewed_at": now.isoformat(),
        }
        review_hash = calculate_compliance_hash(COMPLIANCE_REVIEW_DOMAIN_PREFIX, review_payload)

        # Check if posture evaluation exists, or link dummy/finding
        posture_eval = (
            db.query(CompliancePostureEvaluation)
            .filter(CompliancePostureEvaluation.id == compliance_posture_evaluation_id)
            .first()
        )
        posture_eval_id = posture_eval.id if posture_eval else compliance_posture_evaluation_id

        review = ComplianceReview(
            compliance_posture_evaluation_id=posture_eval_id,
            review_action=review_action,
            review_comment=review_comment,
            reviewer_user_id=reviewer_user_id,
            review_hash=review_hash,
            reviewed_at=now,
        )
        db.add(review)
        db.flush()

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="COMPLIANCE_REVIEW_COMPLETED",
                actor_id=reviewer_user_id,
                actor_username=reviewer_user_id,
                payload={
                    "entity_type": "COMPLIANCE_REVIEW",
                    "entity_id": review.id,
                    "target_entity_id": compliance_posture_evaluation_id,
                    "action": review_action,
                    "review_hash": review_hash,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to log review to ledger: {e}")

        logger.info(f"Dual-control review recorded for {compliance_posture_evaluation_id} by {reviewer_user_id} -> {review_action}")
        return review
