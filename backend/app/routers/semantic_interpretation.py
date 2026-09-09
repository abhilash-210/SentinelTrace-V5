"""
routers/semantic_interpretation.py
----------------------------------
Semantic Interpretation Engine & Semantic Drift Detection API endpoints.

Sprint 3B — Semantic Interpretation Engine & Semantic Drift Detection.
Provides:
- On-demand vendor-scoped semantic policy evaluation of normalized events
- Defensive semantic drift and risk alerts
- Explainable end-to-end evidence traceability
- Safe idempotent interpretation
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import require_permission
from app.database import get_db
from app.models.user import User
from app.schemas.semantic_interpretation import (
    SemanticDriftAlertListResponse,
    SemanticDriftAlertResponse,
    SemanticInterpretationListResponse,
    SemanticInterpretationResponse,
    SemanticTraceResponse,
)
from app.services.semantic_interpretation_service import SemanticInterpretationService
from app.services.semantic_policy_service import SemanticPolicyService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Semantic Interpretation & Drift Engine"])


@router.post(
    "/api/v1/normalized-events/{normalized_event_id}/interpret",
    response_model=SemanticInterpretationResponse,
    status_code=status.HTTP_200_OK,
    summary="Interpret Normalized Security Event",
    description=(
        "**Core Pipeline**: Applies the active vendor-scoped Semantic Policy to a normalized event.\n\n"
        "**Guarantees**:\n"
        "- Preserved raw evidence and canonical normalized event remain 100% immutable\n"
        "- Strictly isolated vendor policy matching (no global mapping assumptions)\n"
        "- Deterministic semantic confidence scoring with explainable reasons\n"
        "- Automatic detection of semantic drift, ambiguity, and protected field risks\n"
        "- Idempotent derivation for identical event and policy versions"
    ),
    responses={
        200: {"description": "Derived semantic interpretation record and drift alerts"},
        401: {"description": "Unauthorized - Missing or invalid token"},
        403: {"description": "Forbidden - Requires SEMANTIC_INTERPRET permission"},
        404: {"description": "Normalized event not found"},
        500: {"description": "Interpretation engine failure"},
    },
)
def interpret_normalized_event(
    normalized_event_id: str,
    current_user: User = Depends(require_permission("SEMANTIC_INTERPRET")),
    db: Session = Depends(get_db),
) -> SemanticInterpretationResponse:
    """Run vendor-scoped semantic interpretation on a normalized security event."""
    # Ensure default policies and protected fields are seeded
    SemanticPolicyService.seed_defaults(db)

    try:
        interpretation = SemanticInterpretationService.interpret_normalized_event(
            db=db,
            normalized_event_id=normalized_event_id,
        )
        return SemanticInterpretationResponse(**interpretation.to_dict())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error("Interpretation failed for %s: %s", normalized_event_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Semantic interpretation failed for event '{normalized_event_id}'.",
        ) from exc


@router.get(
    "/api/v1/semantic-interpretations",
    response_model=SemanticInterpretationListResponse,
    summary="List Semantic Interpretations",
    description="Retrieve paginated semantic interpretation records with optional status, risk, policy, and vendor filters.",
)
def list_semantic_interpretations(
    limit: int = Query(default=50, ge=1, le=100, description="Items per page"),
    offset: int = Query(default=0, ge=0, description="Items to skip"),
    status: Optional[str] = Query(default=None, description="Filter by status ('INTERPRETED', 'UNMAPPED', 'AMBIGUOUS', 'CONFLICT')"),
    risk_level: Optional[str] = Query(default=None, description="Filter by risk ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')"),
    policy_id: Optional[str] = Query(default=None, description="Filter by semantic policy ID"),
    vendor_name: Optional[str] = Query(default=None, description="Filter by vendor name"),
    current_user: User = Depends(require_permission("NORMALIZED_EVENT_READ")),
    db: Session = Depends(get_db),
) -> SemanticInterpretationListResponse:
    """List paginated semantic interpretations."""
    items, total = SemanticInterpretationService.list_interpretations(
        db=db,
        limit=limit,
        offset=offset,
        status=status,
        risk_level=risk_level,
        policy_id=policy_id,
        vendor_name=vendor_name,
    )
    return SemanticInterpretationListResponse(
        items=[SemanticInterpretationResponse(**item.to_dict()) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/api/v1/semantic-interpretations/{interpretation_id}",
    response_model=SemanticInterpretationResponse,
    summary="Get Semantic Interpretation Details",
    description="Retrieve full details and linked drift alerts for a specific semantic interpretation record.",
    responses={
        200: {"description": "Semantic interpretation details"},
        404: {"description": "Interpretation not found"},
    },
)
def get_semantic_interpretation(
    interpretation_id: str,
    current_user: User = Depends(require_permission("NORMALIZED_EVENT_READ")),
    db: Session = Depends(get_db),
) -> SemanticInterpretationResponse:
    """Retrieve semantic interpretation record by ID."""
    interp = SemanticInterpretationService.get_interpretation_by_id(db, interpretation_id)
    if not interp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Semantic interpretation '{interpretation_id}' not found.",
        )
    return SemanticInterpretationResponse(**interp.to_dict())


@router.get(
    "/api/v1/semantic-interpretations/{interpretation_id}/trace",
    response_model=SemanticTraceResponse,
    summary="Get End-to-End Semantic Audit Trace",
    description=(
        "Retrieve the complete, verifiable audit trace spanning:\n"
        "**Raw Evidence** $\\rightarrow$ **Normalized Event** $\\rightarrow$ **Source Profile** $\\rightarrow$ "
        "**Vendor** $\\rightarrow$ **Semantic Policy** $\\rightarrow$ **Policy Rule** $\\rightarrow$ "
        "**Interpretation Decision** $\\rightarrow$ **Drift Alerts**"
    ),
    responses={
        200: {"description": "Full explainable semantic audit trace"},
        404: {"description": "Interpretation not found"},
    },
)
def get_semantic_trace(
    interpretation_id: str,
    current_user: User = Depends(require_permission("AUDIT_READ")),
    db: Session = Depends(get_db),
) -> SemanticTraceResponse:
    """Retrieve complete explainable audit trace for an interpretation."""
    trace = SemanticInterpretationService.get_full_semantic_trace(db, interpretation_id)
    if not trace:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Semantic trace for interpretation '{interpretation_id}' not found.",
        )
    return SemanticTraceResponse(**trace)


@router.get(
    "/api/v1/semantic-drift-alerts",
    response_model=SemanticDriftAlertListResponse,
    summary="List Semantic Drift Alerts",
    description="Retrieve paginated semantic drift and anomaly alerts.",
)
def list_semantic_drift_alerts(
    limit: int = Query(default=50, ge=1, le=100, description="Items per page"),
    offset: int = Query(default=0, ge=0, description="Items to skip"),
    severity: Optional[str] = Query(default=None, description="Filter by severity ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')"),
    status: Optional[str] = Query(default=None, description="Filter by status ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')"),
    drift_type: Optional[str] = Query(default=None, description="Filter by drift type"),
    current_user: User = Depends(require_permission("DRIFT_ALERT_READ")),
    db: Session = Depends(get_db),
) -> SemanticDriftAlertListResponse:
    """List paginated semantic drift alerts."""
    items, total = SemanticInterpretationService.list_drift_alerts(
        db=db,
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
        drift_type=drift_type,
    )
    return SemanticDriftAlertListResponse(
        items=[SemanticDriftAlertResponse(**item.to_dict()) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/api/v1/semantic-drift-alerts/{alert_id}",
    response_model=SemanticDriftAlertResponse,
    summary="Get Specific Semantic Drift Alert",
    description="Retrieve details of a single semantic drift alert.",
    responses={
        200: {"description": "Semantic drift alert details"},
        404: {"description": "Drift alert not found"},
    },
)
def get_semantic_drift_alert(
    alert_id: str,
    current_user: User = Depends(require_permission("DRIFT_ALERT_READ")),
    db: Session = Depends(get_db),
) -> SemanticDriftAlertResponse:
    """Retrieve a single drift alert by ID."""
    alert = SemanticInterpretationService.get_drift_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Semantic drift alert '{alert_id}' not found.",
        )
    return SemanticDriftAlertResponse(**alert.to_dict())

