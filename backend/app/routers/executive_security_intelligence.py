"""
routers/executive_security_intelligence.py
-----------------------------------------
FastAPI router for Unified Executive Security Intelligence &
Executive Risk Posture Command Center.

Sprint 10A — Unified Security Intelligence & Executive Risk Posture Command Center.
Prefix: /api/v1/executive-security
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.models.executive_security_intelligence import (
    ExecutiveSecurityPostureEvaluation,
    ExecutivePostureDomainScore,
    ExecutiveRiskDriver,
    ExecutivePostureTrendSnapshot,
    ExecutiveSecurityInsight,
)
from app.schemas.executive_security_intelligence import (
    ExecutivePostureEvaluationCreateRequest,
    ExecutivePostureEvaluationCreateResponse,
    ExecutivePostureEvaluationResponse,
    ExecutiveDomainScoreResponse,
    ExecutiveRiskDriverResponse,
    ExecutiveInsightResponse,
    ExecutiveExplanationResponse,
    ExecutiveTrendSnapshotResponse,
    ExecutiveKPIResponse,
    ExecutiveProvenanceResponse,
    ExecutiveLedgerVerificationResponse,
)
from app.services.executive_security_intelligence_service import ExecutiveSecurityIntelligenceService
from app.services.executive_provenance_service import ExecutiveProvenanceService

router = APIRouter(
    prefix="/api/v1/executive-security",
    tags=["Executive Security Intelligence"],
)


@router.post(
    "/evaluations",
    response_model=ExecutivePostureEvaluationCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Deterministic Executive Posture Evaluation",
)
def create_evaluation(
    request: Optional[ExecutivePostureEvaluationCreateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_EVALUATE)),
):
    """
    Triggers a deterministic point-in-time executive posture evaluation across all 10 security domains.
    Creates an immutable evaluation sealed with SHA-256 and appended to the Governance Ledger.
    """
    notes = request.notes if request else ""
    force_fresh = request.force_fresh if request else False

    eval_record, hard_overrides, ledger_entry = ExecutiveSecurityIntelligenceService.evaluate_posture(
        db=db,
        actor_id=str(current_user.id),
        actor_username=current_user.username,
        notes=notes,
        force_fresh=force_fresh,
    )

    return {
        "message": f"Executive security posture evaluated: {eval_record.overall_posture_status} ({eval_record.overall_security_score:.1f}/100)",
        "evaluation": eval_record,
        "hard_overrides_applied": hard_overrides,
        "ledger_entry_hash": ledger_entry.entry_hash if ledger_entry else None,
        "ledger_sequence_number": ledger_entry.sequence_number if ledger_entry else None,
    }


@router.get(
    "/evaluations/latest",
    response_model=ExecutivePostureEvaluationResponse,
    summary="Get Latest Executive Posture Evaluation",
)
def get_latest_evaluation(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_READ)),
):
    """Returns the most recent executive security posture evaluation."""
    latest = ExecutiveSecurityIntelligenceService.get_latest_evaluation(db)
    if not latest:
        # Automatically generate initial evaluation if database has none
        latest, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=db,
            actor_id=str(current_user.id),
            actor_username=current_user.username,
            notes="Initial baseline executive posture evaluation",
        )
    return latest


@router.get(
    "/evaluations",
    response_model=List[ExecutivePostureEvaluationResponse],
    summary="List Historical Executive Posture Evaluations",
)
def list_evaluations(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_READ)),
):
    """Returns historical list of immutable executive posture evaluations."""
    return ExecutiveSecurityIntelligenceService.list_evaluations(
        db=db, limit=limit, offset=offset, status=status
    )


@router.get(
    "/evaluations/{evaluation_id}",
    response_model=ExecutivePostureEvaluationResponse,
    summary="Get Detailed Executive Posture Evaluation by ID",
)
def get_evaluation(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_READ)),
):
    """Returns a specific executive security posture evaluation."""
    eval_record = ExecutiveSecurityIntelligenceService.get_evaluation_by_id(db, evaluation_id)
    if not eval_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Executive posture evaluation '{evaluation_id}' not found.",
        )
    return eval_record


@router.get(
    "/evaluations/{evaluation_id}/explain",
    response_model=ExecutiveExplanationResponse,
    summary="Explain Executive Posture Determination",
)
def explain_evaluation(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_EXPLAIN)),
):
    """
    Answers: 'WHY IS THE SECURITY POSTURE THIS STATUS?'
    Returns deterministic explanation tree, domain deductions, top risk drivers, and posture change delta.
    """
    explanation = ExecutiveSecurityIntelligenceService.explain_evaluation(db, evaluation_id)
    if not explanation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Executive posture evaluation '{evaluation_id}' not found.",
        )
    return explanation


@router.get(
    "/evaluations/{evaluation_id}/domains",
    response_model=List[ExecutiveDomainScoreResponse],
    summary="Get Domain Score Breakdown for Evaluation",
)
def get_evaluation_domains(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_READ)),
):
    """Returns the 10 domain scores and deductions for a given evaluation."""
    eval_record = ExecutiveSecurityIntelligenceService.get_evaluation_by_id(db, evaluation_id)
    if not eval_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Executive posture evaluation '{evaluation_id}' not found.",
        )
    return eval_record.domain_scores


@router.get(
    "/evaluations/{evaluation_id}/drivers",
    response_model=List[ExecutiveRiskDriverResponse],
    summary="Get Ranked Risk Drivers for Evaluation",
)
def get_evaluation_drivers(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_READ)),
):
    """Returns ranked deterministic risk drivers for a given evaluation."""
    eval_record = ExecutiveSecurityIntelligenceService.get_evaluation_by_id(db, evaluation_id)
    if not eval_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Executive posture evaluation '{evaluation_id}' not found.",
        )
    return eval_record.risk_drivers


@router.get(
    "/evaluations/{evaluation_id}/insights",
    response_model=List[ExecutiveInsightResponse],
    summary="Get Deterministic Insights for Evaluation",
)
def get_evaluation_insights(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_READ)),
):
    """Returns rule-based deterministic executive insights for a given evaluation."""
    eval_record = ExecutiveSecurityIntelligenceService.get_evaluation_by_id(db, evaluation_id)
    if not eval_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Executive posture evaluation '{evaluation_id}' not found.",
        )
    return eval_record.insights


@router.get(
    "/trends",
    response_model=List[ExecutiveTrendSnapshotResponse],
    summary="Get Posture Trend Snapshots",
)
def get_trends(
    hours: Optional[int] = Query(default=None, ge=1),
    days: Optional[int] = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_TREND_READ)),
):
    """Returns time-series trend snapshots of overall score, risk, and platform health."""
    return ExecutiveSecurityIntelligenceService.get_trends(
        db=db, hours=hours, days=days, limit=limit
    )


@router.get(
    "/kpis",
    response_model=ExecutiveKPIResponse,
    summary="Get Executive Security KPI Matrix",
)
def get_kpis(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_READ)),
):
    """Returns executive KPI summary cards across platform health, risk, and cryptographic status."""
    return ExecutiveSecurityIntelligenceService.get_kpis(db)


@router.get(
    "/provenance/{evaluation_id}",
    response_model=ExecutiveProvenanceResponse,
    summary="Get 20-Stage Cross-Domain Provenance Trace",
)
def get_provenance(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_PROVENANCE_READ)),
):
    """
    Returns 20-stage cross-domain cryptographic lineage from Raw Evidence (Stage 1)
    to Governance Ledger & Merkle Proof (Stage 20).
    """
    res = ExecutiveProvenanceService.trace_posture_provenance(db, evaluation_id)
    if res.get("overall_posture_status") == "NOT_FOUND":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Executive posture evaluation '{evaluation_id}' not found for provenance trace.",
        )
    return res


@router.get(
    "/critical-drivers",
    response_model=List[ExecutiveRiskDriverResponse],
    summary="Get Currently Active Critical Risk Drivers",
)
def get_critical_drivers(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_READ)),
):
    """Returns active CRITICAL and HIGH severity risk drivers from the latest evaluation."""
    latest = ExecutiveSecurityIntelligenceService.get_latest_evaluation(db)
    if not latest:
        return []
    return [
        d for d in latest.risk_drivers if d.severity in ("CRITICAL", "HIGH") and d.active
    ]


@router.get(
    "/ledger/{evaluation_id}",
    response_model=ExecutiveLedgerVerificationResponse,
    summary="Verify Governance Ledger & Merkle Inclusion Proof",
)
def verify_ledger(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EXECUTIVE_SECURITY_READ)),
):
    """
    Verifies cryptographic immutability, ledger hash-chain integrity,
    and Merkle inclusion proof for a posture evaluation.
    """
    res = ExecutiveSecurityIntelligenceService.get_ledger_verification(db, evaluation_id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Executive posture evaluation '{evaluation_id}' not found.",
        )
    return res
