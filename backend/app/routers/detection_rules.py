"""
routers/detection_rules.py
----------------------------
REST API Router for the Detection Rule Registry & Canonical Field
Dependency Mapping.

Sprint 6A — Detection Rule Registry & Canonical Field Dependency Mapping.

Provides:
- GET  /api/v1/detection-rules                     (Paginated list with filters)
- POST /api/v1/detection-rules                     (Create new rule — always DRAFT)
- GET  /api/v1/detection-rules/canonical-fields     (Known canonical field catalog)
- GET  /api/v1/detection-rules/dependency-graph     (Full DAG for visualization)
- GET  /api/v1/detection-rules/impact/{field_name}  (Impact analysis per field)
- GET  /api/v1/detection-rules/{rule_id}            (Single rule detail)
- POST /api/v1/detection-rules/{rule_id}/dependencies (Add dependency to rule)
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, require_any_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.schemas.detection_rule import (
    DependencyGraphResponse,
    DetectionRuleCreateRequest,
    DetectionRuleDetailResponse,
    DetectionRuleDependencyCreate,
    DetectionRuleDependencyResponse,
    DetectionRuleListResponse,
    DetectionRuleSummaryResponse,
    FieldImpactAnalysisResponse,
)
from app.services.detection_rule_service import DetectionRuleService

logger = logging.getLogger("sentinel.routers.detection_rules")

router = APIRouter(
    prefix="/api/v1/detection-rules",
    tags=["Detection Rule Registry"],
)


@router.get(
    "/canonical-fields",
    summary="List Known Canonical Fields",
    description="Returns the catalog of canonical field names from the OCSF-aligned normalized event schema.",
)
def list_canonical_fields(
    current_user: User = Depends(
        require_any_permission([Permission.DETECTION_RULE_READ, Permission.SEMANTIC_POLICY_READ])
    ),
):
    """Return all known canonical fields."""
    fields = DetectionRuleService.get_canonical_fields()
    return {"canonical_fields": fields, "total": len(fields)}


@router.get(
    "/dependency-graph",
    response_model=DependencyGraphResponse,
    summary="Detection Rule Dependency Graph",
    description=(
        "Returns the complete dependency graph (nodes and edges) linking detection rules "
        "to canonical fields. Used for visual DAG rendering and impact analysis."
    ),
)
def get_dependency_graph(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_permission([Permission.DETECTION_RULE_READ, Permission.AUDIT_READ])
    ),
):
    """Build and return the dependency graph for visualization."""
    return DetectionRuleService.get_dependency_graph(db)


@router.get(
    "/impact/{field_name}",
    response_model=FieldImpactAnalysisResponse,
    summary="Canonical Field Impact Analysis",
    description=(
        "Analyzes which detection rules depend on a specific canonical field. "
        "Used to understand the downstream impact when a semantic policy changes "
        "the interpretation of this field."
    ),
)
def get_field_impact(
    field_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_permission([Permission.DETECTION_RULE_READ, Permission.AUDIT_READ])
    ),
):
    """Impact analysis for a canonical field."""
    result = DetectionRuleService.get_field_impact(db, field_name)
    return result


@router.get(
    "",
    response_model=DetectionRuleListResponse,
    summary="List Detection Rules",
    description="Retrieves a paginated list of detection rules with optional status, vendor, and severity filters.",
)
def list_detection_rules(
    limit: int = Query(50, ge=1, le=500, description="Max rules to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: DRAFT, ACTIVE, DEPRECATED"),
    vendor_name: Optional[str] = Query(None, description="Filter by vendor name"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_permission([Permission.DETECTION_RULE_READ])
    ),
):
    """List paginated detection rules."""
    items, total = DetectionRuleService.get_rules(
        db=db,
        limit=limit,
        offset=offset,
        status=status_filter,
        vendor_name=vendor_name,
        severity=severity,
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }


@router.post(
    "",
    response_model=DetectionRuleDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Detection Rule",
    description=(
        "Creates a new detection rule in DRAFT status. "
        "Optionally registers canonical field dependencies at creation time. "
        "New rules MUST always start as DRAFT — status override is rejected."
    ),
)
def create_detection_rule(
    payload: DetectionRuleCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_permission([Permission.DETECTION_RULE_CREATE])
    ),
):
    """Create a new detection rule (always DRAFT)."""
    deps = None
    if payload.dependencies:
        deps = [d.model_dump() for d in payload.dependencies]

    result = DetectionRuleService.create_rule(
        db=db,
        rule_name=payload.rule_name,
        vendor_name=payload.vendor_name,
        description=payload.description,
        severity=payload.severity,
        mitre_tactic=payload.mitre_tactic,
        mitre_technique=payload.mitre_technique,
        created_by=current_user.user_id,
        dependencies=deps,
    )
    return result


@router.get(
    "/{rule_id}",
    response_model=DetectionRuleDetailResponse,
    summary="Get Detection Rule Detail",
    description="Retrieves a single detection rule with all canonical field dependencies.",
)
def get_detection_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_permission([Permission.DETECTION_RULE_READ])
    ),
):
    """Get single detection rule detail."""
    rule = DetectionRuleService.get_rule_by_id(db, rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )
    return rule


@router.post(
    "/{rule_id}/dependencies",
    response_model=DetectionRuleDependencyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add Canonical Field Dependency",
    description="Registers a new canonical field dependency for an existing detection rule.",
)
def add_rule_dependency(
    rule_id: str,
    payload: DetectionRuleDependencyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_any_permission([Permission.DETECTION_RULE_CREATE])
    ),
):
    """Add a dependency edge to a detection rule."""
    result = DetectionRuleService.add_dependency(
        db=db,
        rule_id=rule_id,
        canonical_field=payload.canonical_field,
        dependency_type=payload.dependency_type,
        description=payload.description,
    )
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )
    return result
