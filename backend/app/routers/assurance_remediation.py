"""
routers/assurance_remediation.py
---------------------------------
FastAPI router for Continuous Assurance Governance, Root Cause Analysis,
Deterministic Remediation Recommendations, Maker-Checker Plan Review,
Human Execution Attestation, Post-Remediation Verification, and 18-Stage Provenance.

Sprint 9B — Continuous Assurance Governance, Remediation & Recovery Verification.
Prefix: /api/v1/assurance-remediation
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.models.assurance_remediation import (
    AssuranceRemediationCase,
    AssuranceRootCauseAnalysis,
    AssuranceRemediationRecommendation,
    AssuranceRemediationPlan,
    AssuranceRemediationApproval,
    AssuranceRemediationExecution,
    AssuranceRecoveryVerification,
    AssuranceRecoveryRecord,
)
from app.schemas.assurance_remediation import (
    AssuranceRemediationCaseCreate,
    AssuranceRemediationCaseResponse,
    RootCauseAnalysisCreate,
    RootCauseAnalysisResponse,
    RemediationRecommendationResponse,
    RemediationPlanCreate,
    RemediationPlanSubmit,
    RemediationPlanReview,
    RemediationPlanResponse,
    ExecutionAttestationCreate,
    ExecutionAttestationResponse,
    RecoveryVerificationResponse,
    RecoveryConfirmationRequest,
    AssuranceRecoveryRecordResponse,
    AssuranceRemediationKPIs,
    AssuranceRecoveryTrendResponse,
    AssuranceRecoveryTrendItem,
    AssuranceRemediationTraceResponse,
)
from app.services.assurance_remediation_service import (
    AssuranceRemediationService,
    SelfApprovalForbiddenException,
    InvalidStateTransitionException,
)

router = APIRouter(
    prefix="/api/v1/assurance-remediation",
    tags=["Continuous Assurance Governance & Remediation"],
)


# ── CASE MANAGEMENT ───────────────────────────────────────────────────────────

@router.post(
    "/cases/from-alert/{alert_id}",
    response_model=AssuranceRemediationCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create remediation case from assurance alert",
)
def create_case_from_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_CREATE)),
):
    try:
        case = AssuranceRemediationService.create_remediation_case_from_assurance_alert(
            db=db,
            assurance_alert_id=alert_id,
            user_id=str(current_user.username or current_user.id),
        )
        return case
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post(
    "/cases",
    response_model=AssuranceRemediationCaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create manual assurance remediation case",
)
def create_manual_case(
    payload: AssuranceRemediationCaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_CREATE)),
):
    try:
        case = AssuranceRemediationService.create_remediation_case_manual(
            db=db,
            title=payload.title,
            description=payload.description,
            affected_domain=payload.affected_domain,
            severity=payload.severity,
            priority=payload.priority,
            assurance_alert_id=payload.assurance_alert_id,
            platform_assurance_evaluation_id=payload.platform_assurance_evaluation_id,
            user_id=str(current_user.username or current_user.id),
        )
        return case
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get(
    "/cases",
    response_model=List[AssuranceRemediationCaseResponse],
    summary="List remediation cases with filtering",
)
def list_cases(
    status_filter: Optional[str] = Query(None, alias="status"),
    domain: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_READ)),
):
    query = db.query(AssuranceRemediationCase)
    if status_filter:
        query = query.filter(AssuranceRemediationCase.status == status_filter.upper())
    if domain:
        query = query.filter(AssuranceRemediationCase.affected_domain == domain)
    if severity:
        query = query.filter(AssuranceRemediationCase.severity == severity.upper())
    if priority:
        query = query.filter(AssuranceRemediationCase.priority == priority.upper())

    cases = query.order_by(desc(AssuranceRemediationCase.created_at)).offset(offset).limit(limit).all()
    return cases


@router.get(
    "/cases/{case_id}",
    response_model=AssuranceRemediationCaseResponse,
    summary="Get remediation case details",
)
def get_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_READ)),
):
    case = db.query(AssuranceRemediationCase).filter(AssuranceRemediationCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return case


@router.get(
    "/cases/{case_id}/timeline",
    summary="Get append-only case timeline",
)
def get_case_timeline(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_READ)),
):
    case = db.query(AssuranceRemediationCase).filter(AssuranceRemediationCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return {"case_id": case.id, "case_number": case.case_number, "timeline": case.timeline or []}


# ── ROOT CAUSE ANALYSIS ───────────────────────────────────────────────────────

@router.post(
    "/cases/{case_id}/root-cause",
    response_model=RootCauseAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or submit root cause analysis",
)
def create_root_cause(
    case_id: str,
    payload: RootCauseAnalysisCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_ROOT_CAUSE_ANALYZE)),
):
    try:
        rca = AssuranceRemediationService.create_root_cause_analysis(
            db=db,
            case_id=case_id,
            root_cause_category=payload.root_cause_category,
            root_cause_key=payload.root_cause_key,
            hypothesis=payload.hypothesis,
            evidence_summary=payload.evidence_summary,
            confidence=payload.confidence,
            created_by_user_id=str(current_user.username or current_user.id),
            reviewed_by_user_id=payload.reviewed_by_user_id,
        )
        return rca
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get(
    "/cases/{case_id}/root-cause",
    response_model=List[RootCauseAnalysisResponse],
    summary="Retrieve root cause analyses for case",
)
def get_root_causes(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_READ)),
):
    rcas = (
        db.query(AssuranceRootCauseAnalysis)
        .filter(AssuranceRootCauseAnalysis.remediation_case_id == case_id)
        .order_by(desc(AssuranceRootCauseAnalysis.analysis_version))
        .all()
    )
    return rcas


# ── RECOMMENDATIONS ───────────────────────────────────────────────────────────

@router.post(
    "/cases/{case_id}/recommendations/generate",
    response_model=List[RemediationRecommendationResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Generate deterministic remediation recommendations",
)
def generate_recommendations(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_RECOMMEND)),
):
    try:
        recs = AssuranceRemediationService.generate_remediation_recommendations(
            db=db,
            case_id=case_id,
            user_id=str(current_user.username or current_user.id),
        )
        return recs
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get(
    "/cases/{case_id}/recommendations",
    response_model=List[RemediationRecommendationResponse],
    summary="Get recommendations for case",
)
def get_recommendations(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_READ)),
):
    recs = (
        db.query(AssuranceRemediationRecommendation)
        .filter(AssuranceRemediationRecommendation.remediation_case_id == case_id)
        .order_by(desc(AssuranceRemediationRecommendation.confidence_score))
        .all()
    )
    return recs


# ── REMEDIATION PLANS & MAKER-CHECKER ─────────────────────────────────────────

@router.post(
    "/cases/{case_id}/plans",
    response_model=RemediationPlanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create draft remediation plan",
)
def create_plan(
    case_id: str,
    payload: RemediationPlanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_PLAN)),
):
    try:
        plan = AssuranceRemediationService.create_remediation_plan(
            db=db,
            case_id=case_id,
            title=payload.title,
            description=payload.description,
            proposed_actions=payload.proposed_actions,
            expected_outcome=payload.expected_outcome,
            rollback_strategy=payload.rollback_strategy,
            estimated_risk=payload.estimated_risk,
            requires_dual_control=payload.requires_dual_control,
            proposed_by_user_id=str(current_user.username or current_user.id),
        )
        return plan
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/plans/{plan_id}/submit",
    response_model=RemediationPlanResponse,
    summary="Submit remediation plan for review",
)
def submit_plan(
    plan_id: str,
    payload: Optional[RemediationPlanSubmit] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_PLAN)),
):
    try:
        plan = AssuranceRemediationService.submit_remediation_plan(
            db=db,
            plan_id=plan_id,
            user_id=str(current_user.username or current_user.id),
            notes=payload.notes if payload else None,
        )
        return plan
    except InvalidStateTransitionException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/plans/{plan_id}/review",
    summary="Independent Maker-Checker review of remediation plan",
)
def review_plan(
    plan_id: str,
    payload: RemediationPlanReview,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_REVIEW)),
):
    try:
        approval = AssuranceRemediationService.review_remediation_plan(
            db=db,
            plan_id=plan_id,
            reviewer_user_id=str(current_user.username or current_user.id),
            decision=payload.decision,
            review_notes=payload.review_notes,
        )
        return approval.to_dict()
    except SelfApprovalForbiddenException as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="SELF_APPROVAL_FORBIDDEN: Proposer cannot approve own remediation plan",
        )
    except InvalidStateTransitionException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/plans/{plan_id}/authorize",
    response_model=RemediationPlanResponse,
    summary="Authorize approved plan for execution",
)
def authorize_plan(
    plan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_REVIEW)),
):
    try:
        plan = AssuranceRemediationService.authorize_remediation_plan(
            db=db,
            plan_id=plan_id,
            user_id=str(current_user.username or current_user.id),
        )
        return plan
    except InvalidStateTransitionException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ── EXECUTION ATTESTATION ─────────────────────────────────────────────────────

@router.post(
    "/plans/{plan_id}/execution",
    response_model=ExecutionAttestationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record human-attested remediation execution",
)
def record_execution(
    plan_id: str,
    payload: ExecutionAttestationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_EXECUTE)),
):
    try:
        execution = AssuranceRemediationService.record_remediation_execution(
            db=db,
            plan_id=plan_id,
            execution_reference=payload.execution_reference,
            execution_summary=payload.execution_summary,
            executed_actions=payload.executed_actions,
            executed_by_user_id=str(current_user.username or current_user.id),
            external_ticket_id=payload.external_ticket_id,
            started_at=payload.started_at,
            completed_at=payload.completed_at,
            execution_status=payload.execution_status,
            attestation=payload.attestation,
        )
        return execution
    except InvalidStateTransitionException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ── RECOVERY VERIFICATION & CONFIRMATION ──────────────────────────────────────

@router.post(
    "/cases/{case_id}/verify-recovery",
    response_model=RecoveryVerificationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger post-remediation assurance recovery verification",
)
def verify_recovery(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_RECOVERY_VERIFY)),
):
    try:
        verification = AssuranceRemediationService.verify_assurance_recovery(
            db=db,
            case_id=case_id,
            user_id=str(current_user.username or current_user.id),
        )
        return verification
    except InvalidStateTransitionException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/cases/{case_id}/recovery",
    response_model=List[RecoveryVerificationResponse],
    summary="Get recovery verifications for case",
)
def get_case_verifications(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_READ)),
):
    verifs = (
        db.query(AssuranceRecoveryVerification)
        .filter(AssuranceRecoveryVerification.remediation_case_id == case_id)
        .order_by(desc(AssuranceRecoveryVerification.verified_at))
        .all()
    )
    return verifs


@router.post(
    "/cases/{case_id}/confirm-recovery",
    response_model=AssuranceRecoveryRecordResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Confirm final recovery decision",
)
def confirm_recovery(
    case_id: str,
    payload: Optional[RecoveryConfirmationRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_RECOVERY_CONFIRM)),
):
    try:
        record = AssuranceRemediationService.confirm_recovery(
            db=db,
            case_id=case_id,
            confirmed_by_user_id=str(current_user.username or current_user.id),
            reasoning=payload.reasoning if payload else "",
        )
        return record
    except InvalidStateTransitionException as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ── ANALYTICS & KPIS ──────────────────────────────────────────────────────────

@router.get(
    "/kpis/summary",
    response_model=AssuranceRemediationKPIs,
    summary="Summary KPIs for assurance remediation governance",
)
def get_kpis(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_READ)),
):
    return AssuranceRemediationService.get_kpis_summary(db=db)


@router.get(
    "/trends",
    response_model=AssuranceRecoveryTrendResponse,
    summary="Time-series recovery score delta trends",
)
def get_recovery_trends(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_READ)),
):
    trends = AssuranceRemediationService.get_recovery_trends(db=db, limit=limit)
    trend_items = [AssuranceRecoveryTrendItem(**t) for t in trends]
    return AssuranceRecoveryTrendResponse(trends=trend_items, total_count=len(trend_items))


# ── 18-STAGE PROVENANCE TRACE ─────────────────────────────────────────────────

@router.get(
    "/cases/{case_id}/trace",
    response_model=AssuranceRemediationTraceResponse,
    summary="End-to-end 18-stage assurance recovery provenance trace",
)
def get_provenance_trace(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_REMEDIATION_AUDIT)),
):
    try:
        trace = AssuranceRemediationService.build_18_stage_provenance_trace(db=db, case_id=case_id)
        return trace
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
