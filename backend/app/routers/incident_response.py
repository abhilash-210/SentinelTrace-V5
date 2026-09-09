"""
routers/incident_response.py
----------------------------
FastAPI router for Incident Response Governance, Playbooks, Deterministic Recommendations,
Containment Requests Lifecycle, Dual-Control Review, Execution Attestations,
Response Verifications, and 17-Stage Cryptographic Provenance.

Sprint 8B — Incident Response Governance, Containment Decision Engine & Human Authorization.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.schemas.incident_response import (
    ContainmentApprovalResponse,
    ContainmentRequestCreate,
    ContainmentRequestResponse,
    ContainmentReviewRequest,
    ExecutionAttestationRequest,
    ExecutionResponse,
    PlaybookResponse,
    RecommendationListResponse,
    RecommendationResponse,
    ResponseTraceResponse,
    VerificationRequest,
    VerificationResponse,
)
from app.services.incident_response_service import IncidentResponseService

router = APIRouter(
    tags=["Incident Response Governance & Containment Engine"],
)


# ── 1. Response Playbooks ───────────────────────────────────────────────────

@router.get(
    "/api/v1/incident-response/playbooks",
    response_model=List[PlaybookResponse],
    summary="List response playbooks",
    description="Lists all deterministic incident response playbooks and their ordered containment actions.",
)
def list_playbooks(
    active_only: bool = Query(True, description="Filter for active playbooks only"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_RESPONSE_READ)),
):
    return IncidentResponseService.list_playbooks(db=db, active_only=active_only)


@router.get(
    "/api/v1/incident-response/playbooks/{playbook_id}",
    response_model=PlaybookResponse,
    summary="Get playbook details",
    description="Retrieves a specific playbook and its complete sequence of containment actions and dual-control flags.",
)
def get_playbook(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_RESPONSE_READ)),
):
    playbook = IncidentResponseService.get_playbook(db=db, playbook_id=playbook_id)
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Playbook '{playbook_id}' not found")
    return playbook


@router.post(
    "/api/v1/incident-response/seed-playbooks",
    summary="Seed default response playbooks",
    description="Idempotently seeds standard incident response playbooks.",
)
def seed_playbooks(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_RESPONSE_RECOMMEND)),
):
    return IncidentResponseService.seed_defaults(db)


# ── 2. Response Recommendations ─────────────────────────────────────────────

@router.post(
    "/api/v1/incidents/{incident_id}/recommendations",
    response_model=List[RecommendationResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Generate deterministic response recommendations",
    description="Matches playbooks and computes explainable, priority-ranked response recommendations for an incident.",
)
def generate_recommendations(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_RESPONSE_RECOMMEND)),
):
    return IncidentResponseService.generate_recommendations(
        db=db,
        incident_id=incident_id,
        current_user=current_user,
    )


@router.get(
    "/api/v1/incidents/{incident_id}/recommendations",
    response_model=List[RecommendationResponse],
    summary="Get recommendations for incident",
    description="Retrieves existing deterministic recommendations for a security incident.",
)
def get_recommendations(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_RESPONSE_READ)),
):
    return IncidentResponseService.get_recommendations_for_incident(db=db, incident_id=incident_id)


# ── 3. Containment Requests Lifecycle ───────────────────────────────────────

@router.post(
    "/api/v1/incidents/{incident_id}/containment-requests",
    response_model=ContainmentRequestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Propose containment request",
    description="Allows a Security Analyst (Maker) to author and propose a formal containment request for an incident.",
)
def create_containment_request(
    incident_id: str,
    req: ContainmentRequestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_CONTAINMENT_PROPOSE)),
):
    return IncidentResponseService.create_containment_request(
        db=db,
        incident_id=incident_id,
        action_type=req.action_type,
        action_description=req.action_description,
        impact_level=req.impact_level,
        risk_justification=req.risk_justification,
        current_user=current_user,
        recommendation_id=req.recommendation_id,
    )


@router.post(
    "/api/v1/containment-requests/{request_id}/submit",
    response_model=ContainmentRequestResponse,
    summary="Submit containment request for independent review",
    description="Transitions a proposed containment request to PENDING_REVIEW state.",
)
def submit_containment_request(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_CONTAINMENT_PROPOSE)),
):
    return IncidentResponseService.submit_for_review(
        db=db,
        request_id=request_id,
        current_user=current_user,
    )


@router.post(
    "/api/v1/containment-requests/{request_id}/review",
    response_model=ContainmentRequestResponse,
    summary="Review containment request (Maker-Checker)",
    description="Allows an independent reviewer (Checker) to APPROVE or REJECT a containment request. Proposer self-approval is forbidden.",
)
def review_containment_request(
    request_id: str,
    req: ContainmentReviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_CONTAINMENT_REVIEW)),
):
    return IncidentResponseService.review_request(
        db=db,
        request_id=request_id,
        decision=req.decision,
        reason=req.reason,
        current_user=current_user,
    )


@router.get(
    "/api/v1/containment-requests",
    response_model=List[ContainmentRequestResponse],
    summary="List containment requests",
    description="Lists containment requests with optional filtering by incident ID, status, or impact level.",
)
def list_containment_requests(
    incident_id: Optional[str] = Query(None, description="Filter by incident ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    impact_level: Optional[str] = Query(None, description="Filter by impact level"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_RESPONSE_READ)),
):
    return IncidentResponseService.list_containment_requests(
        db=db,
        incident_id=incident_id,
        status=status_filter,
        impact_level=impact_level,
    )


@router.get(
    "/api/v1/containment-requests/{request_id}",
    response_model=ContainmentRequestResponse,
    summary="Get containment request detail",
    description="Retrieves a single containment request with its full dual-control approvals, execution attestations, and verification records.",
)
def get_containment_request(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_RESPONSE_READ)),
):
    req = IncidentResponseService.get_containment_request(db=db, request_id=request_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Containment request '{request_id}' not found")
    return req


# ── 4. Execution Attestation ────────────────────────────────────────────────

@router.post(
    "/api/v1/containment-requests/{request_id}/attest-execution",
    response_model=ContainmentRequestResponse,
    summary="Attest human containment execution",
    description="Attests that an approved containment action was executed by an authorized human operator in external infrastructure/EDR/IAM.",
)
def attest_execution(
    request_id: str,
    req: ExecutionAttestationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_RESPONSE_EXECUTE)),
):
    return IncidentResponseService.attest_execution(
        db=db,
        request_id=request_id,
        execution_status=req.execution_status,
        execution_reference=req.execution_reference,
        execution_notes=req.execution_notes,
        current_user=current_user,
    )


# ── 5. Response Verification ────────────────────────────────────────────────

@router.post(
    "/api/v1/containment-requests/{request_id}/verify",
    response_model=ContainmentRequestResponse,
    summary="Verify containment response effectiveness",
    description="Records post-containment telemetry verification confirming adversary activity cessation or containment outcome.",
)
def verify_response(
    request_id: str,
    req: VerificationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_RESPONSE_VERIFY)),
):
    return IncidentResponseService.verify_response(
        db=db,
        request_id=request_id,
        verification_status=req.verification_status,
        verification_method=req.verification_method,
        verification_evidence=req.verification_evidence,
        current_user=current_user,
        verification_notes=req.verification_notes,
    )


# ── 6. 17-Stage Provenance Trace ────────────────────────────────────────────

@router.get(
    "/api/v1/incidents/{incident_id}/response-trace",
    response_model=ResponseTraceResponse,
    summary="Get 17-stage incident response provenance trace",
    description="Traces full 17-stage cryptographic and governance lineage from raw evidence through incident response and Merkle proof.",
)
def get_incident_response_trace(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_RESPONSE_AUDIT)),
):
    return IncidentResponseService.get_incident_response_trace(db=db, incident_id=incident_id)
