"""
routers/risk_correlations.py
----------------------------
FastAPI router for Security Posture Risk Correlations, Concentration Clusters, and Graph DAGs.

Sprint 7B — Security Posture Risk Correlation, Prioritized Remediation & Executive Risk Intelligence.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.auth import require_permission, get_current_user
from app.core.rbac import Permission
from app.models.user import User
from app.schemas.risk_correlation import (
    RiskCorrelationResponse,
    RiskCorrelationDetailResponse,
    RiskCorrelationGraphResponse,
    RiskClusterResponse,
    RiskAnalysisRequest,
    RiskAnalysisSummaryResponse,
)
from app.services.risk_correlation_service import RiskCorrelationService

router = APIRouter(
    prefix="/api/v1/risk-correlations",
    tags=["Risk Correlations & Concentration Analysis"],
)


@router.get(
    "",
    response_model=List[RiskCorrelationResponse],
    summary="List risk correlations",
    description="Retrieve all deterministic risk correlations with optional filtering by severity, type, and status.",
)
def list_risk_correlations(
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    correlation_type: Optional[str] = Query(None, description="Filter by type: SINGLE_SIGNAL, MULTI_SIGNAL, DEPENDENCY_CHAIN, PROTECTED_FIELD_CHAIN, TRUST_DEGRADATION_CHAIN, CRITICAL_RISK_CLUSTER"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: ACTIVE, INVESTIGATING, MITIGATED, CLOSED"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RISK_CORRELATION_READ)),
):
    correlations = RiskCorrelationService.list_correlations(
        db,
        severity=severity,
        correlation_type=correlation_type,
        status=status_filter,
    )
    return [c.to_dict() for c in correlations]


@router.get(
    "/clusters",
    response_model=List[RiskClusterResponse],
    summary="List risk concentration clusters",
    description="Retrieve aggregated risk concentration clusters grouped by shared canonical fields and dependencies.",
)
def list_risk_clusters(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RISK_CORRELATION_READ)),
):
    return RiskCorrelationService.detect_risk_clusters(db)


@router.get(
    "/{correlation_id}",
    response_model=RiskCorrelationDetailResponse,
    summary="Get risk correlation details",
    description="Retrieve detailed risk correlation record including all graph members.",
)
def get_risk_correlation(
    correlation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RISK_CORRELATION_READ)),
):
    corr = RiskCorrelationService.get_correlation_by_id(db, correlation_id)
    if not corr:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk correlation '{correlation_id}' not found.",
        )
    return {
        **corr.to_dict(),
        "members": [m.to_dict() for m in corr.members],
    }


@router.get(
    "/{correlation_id}/graph",
    response_model=RiskCorrelationGraphResponse,
    summary="Get root-cause contribution graph",
    description="Constructs the complete directed graph representing the causal chain and downstream impact.",
)
def get_correlation_graph(
    correlation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RISK_CORRELATION_READ)),
):
    corr = RiskCorrelationService.get_correlation_by_id(db, correlation_id)
    if not corr:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk correlation '{correlation_id}' not found.",
        )
    return RiskCorrelationService.build_correlation_graph(db, correlation_id)


@router.post(
    "/analyze",
    response_model=RiskAnalysisSummaryResponse,
    summary="Trigger deterministic risk correlation analysis",
    description="Triggers deterministic evaluation of security telemetry, drift alerts, and trust evaluations.",
)
def analyze_risk_correlations(
    payload: RiskAnalysisRequest = RiskAnalysisRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RISK_CORRELATION_ANALYZE)),
):
    correlations = RiskCorrelationService.correlate_security_risks(
        db, force_reanalyze=payload.force_reanalyze
    )
    clusters = RiskCorrelationService.detect_risk_clusters(db)

    critical_chains = sum(1 for c in correlations if c.severity == "CRITICAL")
    rules_total = sum(c.affected_rule_count for c in correlations)

    return {
        "correlations_identified": len(correlations),
        "clusters_detected": len(clusters),
        "critical_risk_chains": critical_chains,
        "affected_rules_total": rules_total,
        "analysis_timestamp": str(correlations[0].created_at) if correlations else "",
        "correlations": [c.to_dict() for c in correlations],
    }
