"""
routers/security_assurance.py
------------------------------
FastAPI router for Continuous Security Assurance, Platform Health Intelligence,
Domain Scoring, Hard Failure Overrides, Metric Definitions, Alerts, and 17-Stage Provenance.

Sprint 9A — Continuous Security Assurance & Platform Health Intelligence.
Prefix: /api/v1/security-assurance
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.models.security_assurance import (
    AssuranceDomainEvaluation,
    PlatformAssuranceEvaluation,
    AssuranceAlert,
    AssuranceMetricDefinition,
    AssuranceTrendSnapshot,
)
from app.schemas.security_assurance import (
    AssuranceDomainEvaluationResponse,
    PlatformAssuranceEvaluationResponse,
    DomainEvaluationRequest,
    PlatformEvaluationRequest,
    AssuranceAlertResponse,
    AssuranceAlertStatusUpdate,
    AssuranceMetricDefinitionResponse,
    AssuranceKPISummary,
    AssuranceHistoryResponse,
    AssuranceProvenanceTraceResponse,
)
from app.services.security_assurance_service import SecurityAssuranceService

router = APIRouter(
    prefix="/api/v1/security-assurance",
    tags=["Continuous Security Assurance & Platform Health Intelligence"],
)


# ── 1. Platform Evaluation Endpoints ─────────────────────────────────────────

@router.post(
    "/evaluate",
    response_model=PlatformAssuranceEvaluationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Run complete platform security assurance evaluation",
    description="Executes a deterministic continuous assurance evaluation across all 7 domains, applies hard failure overrides, seals the snapshot cryptographically, and generates deduplicated alerts.",
)
def evaluate_platform(
    request: Optional[PlatformEvaluationRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_EVALUATE)),
):
    notes = request.notes if request else None
    return SecurityAssuranceService.evaluate_platform(db=db, notes=notes)


@router.get(
    "/latest",
    response_model=PlatformAssuranceEvaluationResponse,
    summary="Get latest platform assurance snapshot",
    description="Retrieves the most recent sealed platform security assurance snapshot.",
)
def get_latest_platform_assurance(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_READ)),
):
    latest = SecurityAssuranceService.get_latest_assurance(db=db)
    if not latest:
        # If no evaluation exists yet, execute first baseline evaluation
        latest = SecurityAssuranceService.evaluate_platform(db=db)
    return latest


@router.get(
    "/history",
    response_model=AssuranceHistoryResponse,
    summary="Get platform assurance historical trend",
    description="Retrieves historical platform evaluations and time-series snapshots for trend visualization.",
)
def get_assurance_history(
    start_date: Optional[datetime] = Query(None, description="Start filter timestamp"),
    end_date: Optional[datetime] = Query(None, description="End filter timestamp"),
    limit: int = Query(50, ge=1, le=200, description="Max snapshots to return"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_READ)),
):
    evals, trends = SecurityAssuranceService.get_assurance_history(
        db=db, start_date=start_date, end_date=end_date, limit=limit
    )
    return AssuranceHistoryResponse(
        total_evaluations=len(evals),
        evaluations=evals,
        trend_snapshots=trends,
    )


@router.get(
    "/kpis/summary",
    response_model=AssuranceKPISummary,
    summary="Get Security Assurance Command Center KPIs",
    description="Returns aggregate real-time assurance metrics, health counts, critical domains, and alert totals.",
)
def get_kpis_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_READ)),
):
    return SecurityAssuranceService.get_kpi_summary(db=db)


# ── 2. Domain Endpoints ──────────────────────────────────────────────────────

@router.post(
    "/domains/{domain_name}/evaluate",
    response_model=AssuranceDomainEvaluationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Evaluate single assurance domain",
    description="Executes a deterministic evaluation of a single domain and creates an immutable domain snapshot.",
)
def evaluate_domain(
    domain_name: str,
    request: Optional[DomainEvaluationRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_EVALUATE)),
):
    notes = request.notes if request else None
    return SecurityAssuranceService.evaluate_domain(db=db, domain_name=domain_name, notes=notes)


@router.get(
    "/domains/latest",
    response_model=List[AssuranceDomainEvaluationResponse],
    summary="Get latest snapshot for all 7 domains",
    description="Retrieves the most recent point-in-time evaluation snapshot for each of the 7 assurance domains.",
)
def get_latest_domain_evaluations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_READ)),
):
    latest_domains = []
    for d in SecurityAssuranceService.DOMAINS:
        rec = (
            db.query(AssuranceDomainEvaluation)
            .filter(AssuranceDomainEvaluation.domain_name == d)
            .order_by(desc(AssuranceDomainEvaluation.evaluation_timestamp))
            .first()
        )
        if rec:
            latest_domains.append(rec)
        else:
            # Evaluate on-demand if missing
            rec = SecurityAssuranceService.evaluate_domain(db, d)
            latest_domains.append(rec)
    return latest_domains


@router.get(
    "/domains/{domain_name}/history",
    response_model=List[AssuranceDomainEvaluationResponse],
    summary="Get domain evaluation history",
    description="Retrieves historical evaluations for a specific domain.",
)
def get_domain_history(
    domain_name: str,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_READ)),
):
    domain_name = domain_name.upper()
    evals = (
        db.query(AssuranceDomainEvaluation)
        .filter(AssuranceDomainEvaluation.domain_name == domain_name)
        .order_by(desc(AssuranceDomainEvaluation.evaluation_timestamp))
        .limit(limit)
        .all()
    )
    return evals


# ── 3. Metric Definitions ────────────────────────────────────────────────────

@router.get(
    "/metrics/definitions",
    response_model=List[AssuranceMetricDefinitionResponse],
    summary="List assurance metric catalog definitions",
    description="Returns the deterministic catalog of assurance metric definitions, weights, and classification thresholds.",
)
def list_metric_definitions(
    domain_name: Optional[str] = Query(None, description="Optional domain filter"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_READ)),
):
    SecurityAssuranceService.seed_default_metric_definitions(db)
    query = db.query(AssuranceMetricDefinition)
    if domain_name:
        query = query.filter(AssuranceMetricDefinition.domain_name == domain_name.upper())
    return query.order_by(AssuranceMetricDefinition.domain_name, AssuranceMetricDefinition.metric_key).all()


# ── 4. Assurance Alerts ──────────────────────────────────────────────────────

@router.get(
    "/alerts",
    response_model=List[AssuranceAlertResponse],
    summary="List assurance alerts",
    description="Retrieves assurance alerts with optional filters for status, severity, and domain.",
)
def list_assurance_alerts(
    status: Optional[str] = Query(None, description="Filter by status: OPEN, ACKNOWLEDGED, RESOLVED"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    domain: Optional[str] = Query(None, description="Filter by assurance domain"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_ALERT_READ)),
):
    query = db.query(AssuranceAlert)
    if status:
        query = query.filter(AssuranceAlert.status == status.upper())
    if severity:
        query = query.filter(AssuranceAlert.severity == severity.upper())
    if domain:
        query = query.filter(AssuranceAlert.domain_name == domain.upper())

    return query.order_by(desc(AssuranceAlert.last_detected_at)).limit(limit).all()


@router.patch(
    "/alerts/{alert_id}/status",
    response_model=AssuranceAlertResponse,
    summary="Triage assurance alert status",
    description="Transitions an assurance alert through the governance lifecycle: OPEN -> ACKNOWLEDGED -> RESOLVED.",
)
def triage_assurance_alert(
    alert_id: str,
    update: AssuranceAlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_ALERT_TRIAGE)),
):
    return SecurityAssuranceService.triage_alert(
        db=db,
        alert_id=alert_id,
        new_status=update.status.value,
        user_id=current_user.user_id,
        notes=update.notes,
    )


# ── 5. Specific Evaluation & Provenance Trace ────────────────────────────────

@router.get(
    "/{evaluation_id}",
    response_model=PlatformAssuranceEvaluationResponse,
    summary="Get platform evaluation details",
    description="Retrieves a specific platform assurance evaluation snapshot with full domain breakdown and cryptographic seal.",
)
def get_evaluation_details(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_READ)),
):
    record = (
        db.query(PlatformAssuranceEvaluation)
        .filter(PlatformAssuranceEvaluation.id == evaluation_id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail=f"Platform evaluation '{evaluation_id}' not found")
    return record


@router.get(
    "/{evaluation_id}/trace",
    response_model=AssuranceProvenanceTraceResponse,
    summary="Get 17-stage assurance provenance trace",
    description="Constructs the complete 17-stage assurance provenance trace connecting raw evidence through normalization, drift, detection trust, risk posture, incidents, and cryptographic sealing.",
)
def get_assurance_trace(
    evaluation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ASSURANCE_AUDIT)),
):
    return SecurityAssuranceService.get_assurance_provenance_trace(db=db, evaluation_id=evaluation_id)
