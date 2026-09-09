"""
routers/semantic_policy.py
--------------------------
Semantic Policy Registry and Protected Semantic Fields API endpoints.

Sprint 3A — Semantic Policy Registry & Backend Management.
Provides:
- Vendor-scoped Semantic Policy listings and detailed inspection
- Isolated rule resolution without global assumptions
- Protected security-sensitive semantic field definitions
- Strict DRAFT policy creation endpoint
"""

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import require_permission
from app.database import get_db
from app.models.user import User
from app.schemas.semantic_policy import (
    ProtectedSemanticFieldResponse,
    SemanticPolicyCreateRequest,
    SemanticPolicyDetailResponse,
    SemanticPolicySummaryResponse,
)
from app.services.semantic_policy_service import SemanticPolicyService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Semantic Policy Registry"])


@router.get(
    "/api/v1/semantic-policies",
    response_model=List[SemanticPolicySummaryResponse],
    summary="List Semantic Policies",
    description=(
        "Retrieve all registered vendor-scoped Semantic Policies with version, status, and rule count.\n\n"
        "**Core Architectural Rule**: Semantic mappings are scoped exclusively to specific policies and "
        "vendor source profiles. No global or unscoped semantic mappings exist."
    ),
)
def list_semantic_policies(
    current_user: User = Depends(require_permission("SEMANTIC_POLICY_READ")),
    db: Session = Depends(get_db),
) -> List[SemanticPolicySummaryResponse]:
    """Retrieve all semantic policies."""
    SemanticPolicyService.seed_defaults(db)
    policies = SemanticPolicyService.get_all_policies(db)
    return [SemanticPolicySummaryResponse(**p) for p in policies]


@router.get(
    "/api/v1/semantic-policies/compare",
    summary="Compare Two Semantic Policy Versions",
    description="Deterministically compares two semantic policy versions and identifies unchanged, added, removed, and changed semantic rules with impact levels.",
)
def compare_semantic_policies(
    source_policy_id: str,
    target_policy_id: str,
    current_user: User = Depends(require_permission("SEMANTIC_POLICY_COMPARE")),
    db: Session = Depends(get_db),
):
    """Read-only comparison between two semantic policy versions."""
    SemanticPolicyService.seed_defaults(db)
    try:
        diff = SemanticPolicyService.compare_policies(db, source_policy_id, target_policy_id)
        return diff
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/api/v1/semantic-policies/{policy_id}",
    response_model=SemanticPolicyDetailResponse,
    summary="Get Semantic Policy Details",
    description="Retrieve complete metadata and all policy-scoped semantic rules for a specific policy.",
    responses={
        200: {"description": "Semantic policy details with associated mapping rules"},
        404: {"description": "Semantic policy not found"},
    },
)
def get_semantic_policy(
    policy_id: str,
    current_user: User = Depends(require_permission("SEMANTIC_POLICY_READ")),
    db: Session = Depends(get_db),
) -> SemanticPolicyDetailResponse:
    """Retrieve a single semantic policy and its rules by policy_id."""
    SemanticPolicyService.seed_defaults(db)
    policy = SemanticPolicyService.get_policy_by_id(db, policy_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Semantic policy '{policy_id}' not found.",
        )
    return SemanticPolicyDetailResponse(**policy)


@router.get(
    "/api/v1/protected-fields",
    response_model=List[ProtectedSemanticFieldResponse],
    summary="List Protected Semantic Fields",
    description=(
        "Retrieve all security-sensitive canonical fields (e.g. `action.result`, `severity`, `authentication.outcome`).\n\n"
        "These fields represent critical security telemetry and require elevated governance controls."
    ),
)
def list_protected_fields(
    current_user: User = Depends(require_permission("SEMANTIC_POLICY_READ")),
    db: Session = Depends(get_db),
) -> List[ProtectedSemanticFieldResponse]:
    """Retrieve all protected semantic fields."""
    SemanticPolicyService.seed_defaults(db)
    fields = SemanticPolicyService.get_all_protected_fields(db)
    return [ProtectedSemanticFieldResponse(**f) for f in fields]


@router.post(
    "/api/v1/semantic-policies",
    response_model=SemanticPolicyDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create New Semantic Policy",
    description=(
        "Register a new Semantic Policy with vendor/source-profile scoping.\n\n"
        "**Governance Rule**: All new semantic policies are initialized in `DRAFT` status and cannot "
        "be directly created as `ACTIVE` without formal approval workflow."
    ),
    responses={
        201: {"description": "Semantic policy created successfully in DRAFT state"},
        400: {"description": "Validation failure or duplicate policy_id"},
        401: {"description": "Unauthorized - Missing or invalid token"},
        403: {"description": "Forbidden - Requires SEMANTIC_POLICY_CREATE permission"},
    },
)
def create_semantic_policy(
    request: SemanticPolicyCreateRequest,
    current_user: User = Depends(require_permission("SEMANTIC_POLICY_CREATE")),
    db: Session = Depends(get_db),
) -> SemanticPolicyDetailResponse:
    """Create a new semantic policy in DRAFT status."""
    try:
        new_policy = SemanticPolicyService.create_policy(db, request)
        return SemanticPolicyDetailResponse(**new_policy)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        logger.error("Failed to create semantic policy: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register semantic policy.",
        ) from exc

