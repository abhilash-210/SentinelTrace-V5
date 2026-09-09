"""
services/investigation_governance_service.py
--------------------------------------------
Maker-Checker Dual-Control Governance Engine for Investigation Case Resolution.

Sprint 12A — Unified SOC Investigation & Security Case Management.
Core Invariant: "AN INVESTIGATOR CANNOT APPROVE THEIR OWN RESOLUTION. SELF-APPROVAL STRICTLY FORBIDDEN (HTTP 409)."
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.security_investigation import (
    SecurityInvestigationCase,
    InvestigationReview,
    InvestigationCaseResolution,
    RESOLUTION_DOMAIN_PREFIX,
    compute_canonical_hash,
)
from app.services.governance_ledger_service import GovernanceLedgerService


class SelfInvestigationApprovalForbiddenError(Exception):
    """Raised when an investigator attempts to approve their own resolution request."""
    pass


class InvestigationGovernanceService:
    """
    Manages maker-checker dual-control resolution and governance sign-off for SOC investigation cases.
    """

    @staticmethod
    def propose_resolution(
        db: Session,
        case_id: str,
        proposer_user_id: str,
        proposed_resolution: str,
        proposed_notes: Optional[str] = None,
    ) -> InvestigationReview:
        """
        Investigator submits a case resolution proposal. Transitions case to AWAITING_REVIEW.
        """
        case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found.")

        if case.status in ("RESOLVED", "CLOSED"):
            raise ValueError(f"Cannot propose resolution on case with status '{case.status}'.")

        valid_res = proposed_resolution.upper().strip()
        if valid_res not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_ACTIVITY", "SECURITY_INCIDENT", "INCONCLUSIVE", "INSUFFICIENT_EVIDENCE"):
            raise ValueError(f"Invalid resolution type '{proposed_resolution}'.")

        # Create review request
        review = InvestigationReview(
            case_id=case_id,
            proposed_by_user_id=proposer_user_id,
            proposed_resolution=valid_res,
            proposed_notes=proposed_notes,
            decision="PENDING",
            governance_hash=compute_canonical_hash(
                "SENTINELTRACE_INVESTIGATION_REVIEW_V1",
                {
                    "case_id": case_id,
                    "proposer": proposer_user_id,
                    "resolution": valid_res,
                },
            ),
        )
        db.add(review)

        # Update case status
        case.status = "AWAITING_REVIEW"
        case.resolution = valid_res
        case.resolution_notes = proposed_notes
        db.flush()

        # Log to Governance Ledger
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="INVESTIGATION_RESOLUTION_PROPOSED",
                actor_user_id=proposer_user_id,
                details={
                    "case_id": case.id,
                    "case_number": case.case_number,
                    "proposed_resolution": valid_res,
                    "review_id": review.id,
                },
            )
        except Exception:
            pass

        return review

    @staticmethod
    def review_resolution(
        db: Session,
        case_id: str,
        reviewer_user_id: str,
        decision: str,
        review_notes: Optional[str] = None,
    ) -> Tuple[InvestigationReview, Optional[InvestigationCaseResolution]]:
        """
        Independent reviewer evaluates the proposed case resolution.
        Enforces: proposed_by_user_id != reviewer_user_id.
        """
        case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == case_id).first()
        if not case:
            raise ValueError(f"Investigation case '{case_id}' not found.")

        pending_review = (
            db.query(InvestigationReview)
            .filter(
                InvestigationReview.case_id == case_id,
                InvestigationReview.decision == "PENDING",
            )
            .order_by(InvestigationReview.created_at.desc())
            .first()
        )

        if not pending_review:
            raise ValueError(f"No pending resolution review found for case '{case_id}'.")

        # SEPARATION OF DUTIES CHECK
        if pending_review.proposed_by_user_id == reviewer_user_id:
            raise SelfInvestigationApprovalForbiddenError(
                "Self-approval forbidden: Investigator cannot approve their own case resolution proposal."
            )

        dec_upper = decision.upper().strip()
        if dec_upper not in ("APPROVED", "CHANGES_REQUESTED", "REJECTED"):
            raise ValueError(f"Invalid review decision '{decision}'.")

        pending_review.reviewer_user_id = reviewer_user_id
        pending_review.decision = dec_upper
        pending_review.review_notes = review_notes
        pending_review.reviewed_at = datetime.now(timezone.utc)
        pending_review.governance_hash = compute_canonical_hash(
            "SENTINELTRACE_INVESTIGATION_REVIEW_DECISION_V1",
            {
                "case_id": case_id,
                "review_id": pending_review.id,
                "decision": dec_upper,
                "reviewer": reviewer_user_id,
            },
        )

        final_resolution: Optional[InvestigationCaseResolution] = None

        if dec_upper == "APPROVED":
            case.status = "RESOLVED"
            case.closed_at = datetime.now(timezone.utc)

            # Create immutable resolution seal
            final_resolution = InvestigationCaseResolution(
                case_id=case_id,
                resolution_type=pending_review.proposed_resolution,
                summary=pending_review.proposed_notes or f"Investigation {case.case_number} resolved as {pending_review.proposed_resolution}.",
                containment_verified=True,
                root_cause_summary=review_notes or "Root cause established through multi-domain telemetry.",
                resolved_by=pending_review.proposed_by_user_id,
                reviewer_id=reviewer_user_id,
                resolved_at=datetime.now(timezone.utc),
                resolution_hash="",
            )
            final_resolution.resolution_hash = final_resolution.compute_resolution_hash()
            db.add(final_resolution)
            db.flush()

            # Append to Governance Ledger
            try:
                ledger_entry = GovernanceLedgerService.append_entry(
                    db=db,
                    event_type="INVESTIGATION_CASE_RESOLVED",
                    actor_user_id=reviewer_user_id,
                    details={
                        "case_id": case.id,
                        "case_number": case.case_number,
                        "resolution_type": pending_review.proposed_resolution,
                        "resolved_by": pending_review.proposed_by_user_id,
                        "reviewer_id": reviewer_user_id,
                        "resolution_hash": final_resolution.resolution_hash,
                    },
                )
                if ledger_entry:
                    final_resolution.ledger_reference = str(ledger_entry.id)
            except Exception:
                pass

        elif dec_upper == "CHANGES_REQUESTED":
            case.status = "INVESTIGATING"
        elif dec_upper == "REJECTED":
            case.status = "INVESTIGATING"

        db.flush()
        return pending_review, final_resolution
