"""
routers/remediation.py
----------------------
FastAPI router for Prioritized Remediation Candidates, Priority Explanations,
Hypothetical Impact Simulations, and Auditable Lifecycle Transitions.

Sprint 7B — Security Posture Risk Correlation, Prioritized Remediation & Executive Risk Intelligence.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.auth import require_permission, get_current_user
from app.core.rbac import Permission
from app.models.user import User
from app.schemas.remediation import (
    RemediationCandidateResponse,
    RemediationDetailResponse,
    RemediationSimulationRequest,
    RemediationSimulationResponse,
    RemediationStatusUpdateRequest,
    RemediationGenerationRequest,
    RemediationGenerationSummaryResponse,
    RemediationProvenanceTraceResponse,
)
from app.services.remediation_service import RemediationService

router = APIRouter(
    prefix="/api/v1/remediations",
    tags=["Prioritized Remediation & Executive Risk Intelligence"],
)


@router.get(
    "",
    response_model=List[RemediationCandidateResponse],
    summary="List remediation candidates",
    description="Retrieve all proposed remediation candidates with optional filtering by priority, severity, status, and type.",
)
def list_remediations(
    priority: Optional[str] = Query(None, description="Filter by classification: IMMEDIATE, URGENT, HIGH, MEDIUM, LOW"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: GENERATED, RECOMMENDED, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, VERIFIED, REJECTED"),
    remediation_type: Optional[str] = Query(None, description="Filter by type: SEMANTIC_POLICY_REVIEW, DETECTION_RULE_REVIEW, etc."),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REMEDIATION_READ)),
):
    candidates = RemediationService.list_remediations(
        db,
        priority=priority,
        severity=severity,
        status=status_filter,
        remediation_type=remediation_type,
    )
    return [c.to_dict() for c in candidates]


@router.get(
    "/{remediation_id}",
    response_model=RemediationDetailResponse,
    summary="Get remediation candidate details",
    description="Retrieve detailed remediation record including itemized mathematical priority factor breakdown and action history.",
)
def get_remediation_detail(
    remediation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REMEDIATION_READ)),
):
    candidate = RemediationService.get_remediation_by_id(db, remediation_id)
    if not candidate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation candidate '{remediation_id}' not found.",
        )

    reasoning = candidate.deterministic_reasoning or {}
    explanation = None
    if reasoning and "factors" in reasoning:
        explanation = {
            "base_priority": reasoning.get("base_score", 0),
            "calculated_score": reasoning.get("raw_score", candidate.priority_score),
            "final_score": candidate.priority_score,
            "priority_classification": candidate.priority_classification,
            "factors": reasoning.get("factors", []),
            "mathematical_formula": reasoning.get("mathematical_formula", ""),
            "summary": reasoning.get("summary", ""),
        }

    return {
        **candidate.to_dict(),
        "priority_explanation": explanation,
        "actions": [a.to_dict() for a in candidate.actions],
    }


@router.post(
    "/generate",
    response_model=RemediationGenerationSummaryResponse,
    summary="Generate deterministic remediation candidates",
    description="Generates actionable, evidence-backed remediation candidates from current security posture and risk correlations.",
)
def generate_remediations(
    payload: RemediationGenerationRequest = RemediationGenerationRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REMEDIATION_GENERATE)),
):
    candidates = RemediationService.generate_remediation_candidates(
        db,
        force_regenerate=payload.force_regenerate,
        created_by=current_user.username,
    )

    immediate = sum(1 for c in candidates if c.priority_classification == "IMMEDIATE")
    urgent = sum(1 for c in candidates if c.priority_classification == "URGENT")
    high = sum(1 for c in candidates if c.priority_classification == "HIGH")
    total_gain = sum(c.expected_risk_reduction for c in candidates)

    return {
        "candidates_generated": len(candidates),
        "immediate_priority_count": immediate,
        "urgent_priority_count": urgent,
        "high_priority_count": high,
        "total_expected_posture_gain": round(total_gain, 2),
        "remediations": [c.to_dict() for c in candidates],
    }


@router.post(
    "/{remediation_id}/simulate",
    response_model=RemediationSimulationResponse,
    summary="Simulate hypothetical risk reduction",
    description="Executes a functional in-memory hypothetical simulation of posture improvement without modifying production state.",
)
def simulate_remediation(
    remediation_id: str,
    payload: RemediationSimulationRequest = RemediationSimulationRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REMEDIATION_SIMULATE)),
):
    try:
        return RemediationService.simulate_remediation_impact(
            db,
            remediation_id=remediation_id,
            hypothetical_action=payload.hypothetical_action,
            target_rule_ids=payload.target_rule_ids,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.patch(
    "/{remediation_id}/status",
    response_model=RemediationDetailResponse,
    summary="Update remediation candidate lifecycle status",
    description="Executes an auditable lifecycle status transition (e.g. GENERATED -> RECOMMENDED -> ACKNOWLEDGED -> IN_PROGRESS -> RESOLVED -> VERIFIED).",
)
def update_remediation_status(
    remediation_id: str,
    payload: RemediationStatusUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REMEDIATION_MANAGE)),
):
    try:
        updated = RemediationService.update_remediation_status(
            db,
            remediation_id=remediation_id,
            new_status=payload.status.value,
            performed_by=current_user.username,
            reason=payload.reason,
        )
        return {
            **updated.to_dict(),
            "actions": [a.to_dict() for a in updated.actions],
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/{remediation_id}/trace",
    response_model=RemediationProvenanceTraceResponse,
    summary="Get 16+ stage end-to-end remediation provenance trace",
    description="Constructs the complete verifiable provenance chain from raw evidence vault to Merkle inclusion proof.",
)
def get_remediation_trace(
    remediation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_READ)),
):
    try:
        return RemediationService.get_remediation_provenance_trace(db, remediation_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
