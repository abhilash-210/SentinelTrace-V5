"""
routers/detection_rule_trust.py
-------------------------------
FastAPI API router for Detection Rule Trust Evaluation & Semantic Drift Binding.

Sprint 6B — Detection Rule Trust Evaluation & Semantic Drift Binding.
Endpoints:
- POST   /api/v1/detection-rules/{rule_id}/evaluate-trust
- POST   /api/v1/semantic-drift-alerts/{alert_id}/evaluate-rule-impact
- GET    /api/v1/detection-rule-trust
- GET    /api/v1/detection-rule-trust/kpis/summary
- GET    /api/v1/detection-rule-trust/{evaluation_id}
- GET    /api/v1/detection-rules/{rule_id}/trust-history
- GET    /api/v1/detection-rule-trust/{evaluation_id}/trace
- GET    /api/v1/detection-trust-alerts
- GET    /api/v1/detection-trust-alerts/{alert_id}
- PATCH  /api/v1/detection-trust-alerts/{alert_id}/status
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.schemas.detection_rule_trust import (
    DetectionRuleTrustEvaluationResponse,
    DetectionTrustAlertResponse,
    DetectionTrustAlertStatusUpdate,
    EndToEndTrustTraceResponse,
    TrustEvaluationCreateRequest,
    TrustKPISummaryResponse,
)
from app.services.detection_rule_trust_service import DetectionRuleTrustService
from app.services.detection_trust_alert_service import DetectionTrustAlertService

router = APIRouter(
    prefix="/api/v1",
    tags=["Detection Rule Trust & Semantic Drift Binding"],
)


# ── 1. Evaluate Rule Trust (Manual / Direct) ──────────────────────────────────
@router.post(
    "/detection-rules/{rule_id}/evaluate-trust",
    response_model=DetectionRuleTrustEvaluationResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate detection rule trustworthiness",
    description=(
        "Evaluates the trustworthiness of a detection rule against its canonical field "
        "dependencies and latest semantic interpretations. Returns an immutable evaluation record."
    ),
)
def evaluate_rule_trust(
    rule_id: str,
    payload: Optional[TrustEvaluationCreateRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_TRUST_EVALUATE)),
):
    try:
        norm_id = payload.normalized_event_id if payload else None
        interp_id = payload.interpretation_id if payload else None
        canon_field = payload.canonical_field if payload else None

        eval_record = DetectionRuleTrustService.evaluate_rule_trust(
            db=db,
            rule_id=rule_id,
            canonical_field=canon_field,
            normalized_event_id=norm_id,
            interpretation_id=interp_id,
        )
        return eval_record.to_dict()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Trust evaluation failed: {str(e)}",
        )


# ── 2. Evaluate Rule Impact from Semantic Drift Alert ──────────────────────────
@router.post(
    "/semantic-drift-alerts/{alert_id}/evaluate-rule-impact",
    response_model=List[DetectionRuleTrustEvaluationResponse],
    status_code=status.HTTP_200_OK,
    summary="Evaluate downstream detection rule impact for a semantic drift alert",
    description=(
        "Identifies the affected canonical field from a semantic drift alert, queries "
        "the dependency DAG for dependent detection rules, computes trust scores, and generates alerts."
    ),
)
def evaluate_drift_alert_rule_impact(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_TRUST_EVALUATE)),
):
    try:
        evaluations = DetectionRuleTrustService.evaluate_rules_for_drift_alert(
            db=db,
            alert_id=alert_id,
        )
        return [e.to_dict() for e in evaluations]
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Drift alert impact evaluation failed: {str(e)}",
        )


# ── 3. Trust KPIs Summary ──────────────────────────────────────────────────────
@router.get(
    "/detection-rule-trust/kpis/summary",
    response_model=TrustKPISummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get aggregated detection rule trust KPIs",
    description="Returns high-level statistics for rule trust states and open alerts.",
)
def get_trust_kpi_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_TRUST_READ)),
):
    return DetectionRuleTrustService.get_trust_kpis(db)


# ── 4. List Trust Evaluations ──────────────────────────────────────────────────
@router.get(
    "/detection-rule-trust",
    response_model=List[DetectionRuleTrustEvaluationResponse],
    status_code=status.HTTP_200_OK,
    summary="List detection rule trust evaluations",
    description="Query historical immutable trust evaluation records with filtering and pagination.",
)
def list_trust_evaluations(
    rule_id: Optional[str] = Query(None, description="Filter by detection rule ID"),
    trust_status: Optional[str] = Query(None, description="Filter by trust state: TRUSTED, DEGRADED, AT_RISK, INVALID, UNKNOWN"),
    canonical_field: Optional[str] = Query(None, description="Filter by canonical field name"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level: NONE, LOW, MEDIUM, HIGH, CRITICAL"),
    limit: int = Query(50, ge=1, le=200, description="Max results to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_TRUST_READ)),
):
    evals = DetectionRuleTrustService.list_evaluations(
        db=db,
        rule_id=rule_id,
        trust_status=trust_status,
        canonical_field=canonical_field,
        risk_level=risk_level,
        limit=limit,
        offset=offset,
    )
    return [e.to_dict() for e in evals]


# ── 5. Get Single Trust Evaluation Detail ──────────────────────────────────────
@router.get(
    "/detection-rule-trust/{evaluation_id}",
    response_model=DetectionRuleTrustEvaluationResponse,
    status_code=status.HTTP_200_OK,
    summary="Get detailed trust evaluation record",
    description="Fetches a single trust evaluation by its unique evaluation ID.",
)
def get_trust_evaluation(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_TRUST_READ)),
):
    eval_record = DetectionRuleTrustService.get_evaluation_by_id(db, evaluation_id)
    if not eval_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Trust evaluation '{evaluation_id}' not found.",
        )
    return eval_record.to_dict()


# ── 6. Get Rule Trust History ──────────────────────────────────────────────────
@router.get(
    "/detection-rules/{rule_id}/trust-history",
    response_model=List[DetectionRuleTrustEvaluationResponse],
    status_code=status.HTTP_200_OK,
    summary="Get chronological trust evaluation history for a rule",
    description="Retrieves the immutable audit history of all trust evaluations for a specific detection rule.",
)
def get_rule_trust_history(
    rule_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_TRUST_READ)),
):
    evals = DetectionRuleTrustService.get_rule_trust_history(db, rule_id, limit=limit)
    return [e.to_dict() for e in evals]


# ── 7. End-to-End Trust Trace Provenance ───────────────────────────────────────
@router.get(
    "/detection-rule-trust/{evaluation_id}/trace",
    response_model=EndToEndTrustTraceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get end-to-end semantic trust provenance chain",
    description=(
        "Returns the complete 10-stage traceability chain connecting Raw Evidence, "
        "Normalized Event, Semantic Interpretation, Semantic Drift Alert, Canonical Field, "
        "Rule Dependency, Detection Rule, Trust Evaluation, and Detection Trust Alert."
    ),
)
def get_trust_provenance_trace(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.AUDIT_READ)),
):
    try:
        trace = DetectionRuleTrustService.get_trust_trace(db, evaluation_id)
        return trace
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Trace retrieval failed: {str(e)}",
        )


# ── 8. List Detection Trust Alerts ─────────────────────────────────────────────
@router.get(
    "/detection-trust-alerts",
    response_model=List[DetectionTrustAlertResponse],
    status_code=status.HTTP_200_OK,
    summary="List detection trust alerts",
    description="Query detection trust alerts with status, severity, and rule filters.",
)
def list_detection_trust_alerts(
    rule_id: Optional[str] = Query(None, description="Filter by detection rule ID"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    status: Optional[str] = Query(None, description="Filter by status: OPEN, ACKNOWLEDGED, RESOLVED"),
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_TRUST_ALERT_READ)),
):
    alerts = DetectionTrustAlertService.list_alerts(
        db=db,
        rule_id=rule_id,
        severity=severity,
        status=status,
        alert_type=alert_type,
        limit=limit,
        offset=offset,
    )
    return [a.to_dict() for a in alerts]


# ── 9. Get Single Trust Alert Detail ───────────────────────────────────────────
@router.get(
    "/detection-trust-alerts/{alert_id}",
    response_model=DetectionTrustAlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Get detection trust alert details",
    description="Fetch single trust alert by its unique alert ID.",
)
def get_detection_trust_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_TRUST_ALERT_READ)),
):
    alert = DetectionTrustAlertService.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection trust alert '{alert_id}' not found.",
        )
    return alert.to_dict()


# ── 10. Update Trust Alert Status (Triage) ─────────────────────────────────────
@router.patch(
    "/detection-trust-alerts/{alert_id}/status",
    response_model=DetectionTrustAlertResponse,
    status_code=status.HTTP_200_OK,
    summary="Update detection trust alert status",
    description="Acknowledge or resolve an active detection trust alert.",
)
def update_detection_trust_alert_status(
    alert_id: str,
    payload: DetectionTrustAlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_TRUST_ALERT_READ)),
):
    valid_statuses = ("OPEN", "ACKNOWLEDGED", "RESOLVED")
    if payload.status.upper() not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{payload.status}'. Must be one of {valid_statuses}.",
        )

    alert = DetectionTrustAlertService.update_alert_status(
        db=db,
        alert_id=alert_id,
        new_status=payload.status,
    )
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection trust alert '{alert_id}' not found.",
        )
    return alert.to_dict()
