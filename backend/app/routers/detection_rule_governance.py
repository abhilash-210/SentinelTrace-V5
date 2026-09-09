"""
routers/detection_rule_governance.py
------------------------------------
FastAPI router for Detection Rule Governance, Dual-Control Approval,
Rule Versioning, Version Impact Analysis, and Immutable Governance Audit Trails.

Sprint 6C — Detection Rule Governance, Approval Workflow & Version Impact Management.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.schemas.detection_rule_governance import (
    DetectionRuleGovernanceEventResponse,
    DetectionRuleReviewActionRequest,
    DetectionRuleTrustSimulationResponse,
    DetectionRuleVersionCreateRequest,
    DetectionRuleVersionImpactResponse,
    DetectionRuleVersionResponse,
    EndToEndGovernanceTraceResponse,
)
from app.services.detection_rule_governance_service import DetectionRuleGovernanceService

router = APIRouter(
    prefix="/api/v1",
    tags=["Detection Rule Governance & Dual-Control Approval"],
)


# ── 1. Create Rule Version (DRAFT) ────────────────────────────────────────────
@router.post(
    "/detection-rules/{rule_id}/versions",
    response_model=DetectionRuleVersionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new draft version for a detection rule",
    description=(
        "Creates a new immutable candidate DRAFT version snapshot for a governed detection rule. "
        "Calculates deterministic version hash and records a governance audit event."
    ),
)
def create_rule_version(
    rule_id: str,
    payload: DetectionRuleVersionCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_VERSION_CREATE)),
):
    try:
        dep_dicts = [d.model_dump() for d in payload.dependencies]
        version = DetectionRuleGovernanceService.create_rule_version(
            db=db,
            rule_id=rule_id,
            user_id=current_user.user_id,
            user_role=current_user.role,
            rule_name=payload.rule_name,
            vendor_name=payload.vendor_name,
            description=payload.description,
            query_signature=payload.query_signature,
            severity=payload.severity,
            mitre_techniques=payload.mitre_techniques,
            dependencies=dep_dicts,
            parent_version_id=payload.parent_version_id,
        )
        return version.to_dict()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Version creation failed: {str(e)}",
        )


# ── 2. Submit Version for Dual-Control Review ─────────────────────────────────
@router.post(
    "/detection-rule-versions/{version_id}/submit",
    response_model=DetectionRuleVersionResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit draft version for dual-control maker-checker review",
    description=(
        "Submits a DRAFT detection rule version for review. Transitions status to PENDING_REVIEW, "
        "generates deterministic impact analysis, and creates an approval request."
    ),
)
def submit_version_for_review(
    version_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_SUBMIT_REVIEW)),
):
    try:
        version, _, _ = DetectionRuleGovernanceService.submit_for_review(
            db=db,
            version_id=version_id,
            user_id=current_user.user_id,
            user_role=current_user.role,
        )
        return version.to_dict()
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Submission failed: {str(e)}",
        )


# ── 3. Maker-Checker Review Decision (APPROVE / REJECT) ───────────────────────
@router.post(
    "/detection-rule-versions/{version_id}/review",
    response_model=DetectionRuleVersionResponse,
    status_code=status.HTTP_200_OK,
    summary="Review candidate rule version (Dual-Control Maker-Checker)",
    description=(
        "Performs independent maker-checker review. Enforces strict invariant: "
        "creator_user_id != reviewer_user_id. Returns 409 Conflict if author attempts self-approval."
    ),
)
def review_rule_version(
    version_id: str,
    payload: DetectionRuleReviewActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_REVIEW)),
):
    try:
        version = DetectionRuleGovernanceService.review_rule_version(
            db=db,
            version_id=version_id,
            reviewer_id=current_user.user_id,
            reviewer_role=current_user.role,
            decision=payload.decision,
            comment=payload.comment,
            risk_acknowledged=payload.risk_acknowledged,
            risk_comment=payload.risk_acknowledgement_comment,
        )
        return version.to_dict()
    except PermissionError as e:
        # Self-approval forbidden returns 409 Conflict
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Review failed: {str(e)}",
        )


# ── 4. Activate Rule Version ──────────────────────────────────────────────────
@router.post(
    "/detection-rule-versions/{version_id}/activate",
    response_model=DetectionRuleVersionResponse,
    status_code=status.HTTP_200_OK,
    summary="Activate approved detection rule version in production",
    description=(
        "Atomically activates an APPROVED rule version. Enforces single ACTIVE version invariant "
        "by atomically superseding previous active versions. Synchronizes live detection rule registry."
    ),
)
def activate_rule_version(
    version_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_ACTIVATE)),
):
    try:
        version = DetectionRuleGovernanceService.activate_rule_version(
            db=db,
            version_id=version_id,
            user_id=current_user.user_id,
            user_role=current_user.role,
        )
        return version.to_dict()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Activation failed: {str(e)}",
        )


# ── 5. Disable Rule Version ───────────────────────────────────────────────────
@router.post(
    "/detection-rule-versions/{version_id}/disable",
    response_model=DetectionRuleVersionResponse,
    status_code=status.HTTP_200_OK,
    summary="Disable an active detection rule version",
    description="Transitions an ACTIVE version to DISABLED and logs an immutable governance event.",
)
def disable_rule_version(
    version_id: str,
    reason: Optional[str] = Query(None, description="Administrative justification for deactivation"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_DISABLE)),
):
    try:
        version = DetectionRuleGovernanceService.disable_rule_version(
            db=db,
            version_id=version_id,
            user_id=current_user.user_id,
            user_role=current_user.role,
            reason=reason,
        )
        return version.to_dict()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Disabling version failed: {str(e)}",
        )


# ── 6. List Rule Versions ─────────────────────────────────────────────────────
@router.get(
    "/detection-rule-versions",
    response_model=List[DetectionRuleVersionResponse],
    status_code=status.HTTP_200_OK,
    summary="List governed detection rule versions",
    description="Query detection rule versions with filtering by rule ID, status, creator, or reviewer.",
)
def list_rule_versions(
    rule_id: Optional[str] = Query(None, description="Filter by detection rule ID"),
    status: Optional[str] = Query(None, description="Filter by status: DRAFT, PENDING_REVIEW, APPROVED, REJECTED, ACTIVE, SUPERSEDED, DISABLED"),
    created_by: Optional[str] = Query(None, description="Filter by author user ID"),
    reviewed_by: Optional[str] = Query(None, description="Filter by reviewer user ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_VERSION_READ)),
):
    versions = DetectionRuleGovernanceService.list_versions(
        db=db,
        rule_id=rule_id,
        status=status,
        created_by=created_by,
        reviewed_by=reviewed_by,
        limit=limit,
        offset=offset,
    )
    return [v.to_dict() for v in versions]


# ── 7. Get Single Version Detail ──────────────────────────────────────────────
@router.get(
    "/detection-rule-versions/{version_id}",
    response_model=DetectionRuleVersionResponse,
    status_code=status.HTTP_200_OK,
    summary="Get single detection rule version snapshot",
    description="Fetch single immutable version record by its version ID.",
)
def get_rule_version(
    version_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_VERSION_READ)),
):
    version = DetectionRuleGovernanceService.get_version_by_id(db, version_id)
    if not version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule version '{version_id}' not found.",
        )
    return version.to_dict()


# ── 8. Compare Two Rule Versions (Impact Analysis) ────────────────────────────
@router.get(
    "/detection-rule-versions/{version_id}/compare/{target_version_id}",
    response_model=DetectionRuleVersionImpactResponse,
    status_code=status.HTTP_200_OK,
    summary="Compare two detection rule versions and compute deterministic impact",
    description=(
        "Performs side-by-side comparison between baseline source version and candidate target version. "
        "Analyzes query modifications, severity shifts, dependency additions/removals, and protected fields."
    ),
)
def compare_rule_versions(
    version_id: str,
    target_version_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_GOVERNANCE_READ)),
):
    try:
        impact = DetectionRuleGovernanceService.compare_rule_versions(
            db=db,
            source_version_id=version_id,
            target_version_id=target_version_id,
        )
        return impact.to_dict()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Comparison failed: {str(e)}",
        )


# ── 8B. Get Stored Version Impact ─────────────────────────────────────────────
@router.get(
    "/detection-rule-versions/{version_id}/impact",
    response_model=DetectionRuleVersionImpactResponse,
    status_code=status.HTTP_200_OK,
    summary="Get stored impact analysis for a detection rule version",
    description="Returns the deterministic version comparison and blast-radius impact analysis for candidate version.",
)
def get_version_impact(
    version_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_GOVERNANCE_READ)),
):
    try:
        impact = DetectionRuleGovernanceService.get_version_impact(db, version_id)
        return impact.to_dict()
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Impact retrieval failed: {str(e)}",
        )


# ── 9. Pre-Approval Trust Simulation ──────────────────────────────────────────
@router.get(
    "/detection-rule-versions/{version_id}/trust-simulation",
    response_model=DetectionRuleTrustSimulationResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulate hypothetical trust score before approval",
    description=(
        "Evaluates candidate version dependencies against known semantic drift and protected assets. "
        "Provides hypothetical trust posture without mutating runtime trust tables."
    ),
)
def get_version_trust_simulation(
    version_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_GOVERNANCE_READ)),
):
    try:
        sim = DetectionRuleGovernanceService.simulate_version_trust(db, version_id)
        return sim
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Trust simulation failed: {str(e)}",
        )


# ── 10. End-to-End Governance Provenance Trace ────────────────────────────────
@router.get(
    "/detection-rule-versions/{version_id}/governance-trace",
    response_model=EndToEndGovernanceTraceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get complete 15-stage governance provenance trace",
    description=(
        "Returns the complete 15-stage cryptographic and governance provenance chain "
        "from Rule Creation, Version Hashing, Impact Analysis, Simulation, Dual-Control Review, "
        "to Activation, Supersession, and Immutable Audit Log."
    ),
)
def get_governance_provenance_trace(
    version_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_GOVERNANCE_READ)),
):
    try:
        trace = DetectionRuleGovernanceService.get_governance_trace(db, version_id)
        return trace
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Governance trace retrieval failed: {str(e)}",
        )


# ── 11. List Governance Audit Events ──────────────────────────────────────────
@router.get(
    "/detection-rule-governance/events",
    response_model=List[DetectionRuleGovernanceEventResponse],
    status_code=status.HTTP_200_OK,
    summary="List immutable detection rule governance audit events",
    description="Retrieve chronological append-only governance events with tamper-evident SHA-256 event hashes.",
)
def list_governance_events(
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    version_id: Optional[str] = Query(None, description="Filter by version ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.DETECTION_RULE_GOVERNANCE_READ)),
):
    events = DetectionRuleGovernanceService.list_governance_events(
        db=db,
        rule_id=rule_id,
        version_id=version_id,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )
    return [ev.to_dict() for ev in events]
