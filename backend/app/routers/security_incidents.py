"""
routers/security_incidents.py
------------------------------
FastAPI router for Security Incidents, Deterministic Correlation, Lifecycle Transitions,
Signal/Evidence Linking, Analyst Findings, Timeline Events, Summaries, and 13-Stage Provenance.

Sprint 8A — Security Incident Correlation & Investigation Foundation.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.schemas.security_incident import (
    IncidentAssignmentRequest,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentEvidenceLinkRequest,
    IncidentEvidenceLinkResponse,
    IncidentFindingCreateRequest,
    IncidentFindingResponse,
    IncidentFindingUpdateRequest,
    IncidentResponse,
    IncidentSignalCreateRequest,
    IncidentSignalResponse,
    IncidentStatusUpdateRequest,
    IncidentSummaryResponse,
    IncidentTimelineResponse,
    IncidentTraceResponse,
)
from app.services.incident_service import IncidentService

router = APIRouter(
    prefix="/api/v1/incidents",
    tags=["Security Incidents & SOC Investigation"],
)


@router.get(
    "",
    response_model=List[IncidentResponse],
    summary="List security incidents",
    description="Retrieve security incidents with optional filtering by severity, priority, status, type, or assigned analyst.",
)
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    priority: Optional[str] = Query(None, description="Filter by priority: P1, P2, P3, P4"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: OPEN, TRIAGING, INVESTIGATING, etc."),
    incident_type: Optional[str] = Query(None, description="Filter by type: SEMANTIC_RISK, DETECTION_TRUST, etc."),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned analyst user ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_READ)),
):
    incidents = IncidentService.list_incidents(
        db=db,
        severity=severity,
        priority=priority,
        status=status_filter,
        incident_type=incident_type,
        assigned_to=assigned_to,
        limit=limit,
        offset=offset,
    )
    return [i.to_dict() for i in incidents]


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create manual incident",
    description="Allows Security Analysts or Admins to manually create a formal Security Incident.",
)
def create_manual_incident(
    req: IncidentCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_CREATE)),
):
    try:
        inc = IncidentService.create_manual_incident(
            db=db,
            title=req.title,
            description=req.description,
            incident_type=req.incident_type.value,
            severity=req.severity.value,
            priority=req.priority.value if req.priority else None,
            source_correlation_id=req.source_correlation_id,
            source_cluster_key=req.source_cluster_key,
            root_cause_summary=req.root_cause_summary,
            confidence=req.confidence,
            assigned_to_user_id=req.assigned_to_user_id,
            actor_user_id=current_user.user_id,
            actor_username=current_user.username,
        )
        return inc.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/from-correlation/{correlation_id}",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate incident from risk correlation",
    description="Deterministically generates or returns an active deduplicated Security Incident from a Risk Correlation.",
)
def create_incident_from_correlation(
    correlation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_CREATE)),
):
    try:
        inc = IncidentService.create_incident_from_correlation(
            db=db,
            correlation_id=correlation_id,
            actor_user_id=current_user.user_id,
            actor_username=current_user.username,
        )
        return inc.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    summary="Get incident details",
    description="Retrieve complete incident metadata, signals, linked evidence, analyst findings, and timeline events.",
)
def get_incident_detail(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_READ)),
):
    try:
        incident = IncidentService.get_incident(db, incident_id)
        signals = [s.to_dict() for s in incident.signals]
        evidence = [e.to_dict() for e in incident.evidence_links]
        findings = [f.to_dict() for f in incident.findings]
        timeline = [t.to_dict() for t in incident.timeline_events]

        return {
            "incident": incident.to_dict(),
            "signals": signals,
            "evidence": evidence,
            "findings": findings,
            "timeline": timeline,
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.patch(
    "/{incident_id}/assign",
    response_model=IncidentResponse,
    summary="Assign incident to analyst",
    description="Assigns or unassigns a security analyst to this incident and records an append-only timeline event.",
)
def assign_incident(
    incident_id: str,
    req: IncidentAssignmentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_ASSIGN)),
):
    try:
        inc = IncidentService.assign_incident(
            db=db,
            incident_id=incident_id,
            assigned_to_user_id=req.assigned_to_user_id,
            actor_user_id=current_user.user_id,
            actor_username=current_user.username,
        )
        return inc.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.patch(
    "/{incident_id}/status",
    response_model=IncidentResponse,
    summary="Update incident lifecycle status",
    description="Transitions incident lifecycle status. Enforces state machine rules and records append-only timeline event.",
)
def update_incident_status(
    incident_id: str,
    req: IncidentStatusUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_STATUS_UPDATE)),
):
    try:
        inc = IncidentService.change_incident_status(
            db=db,
            incident_id=incident_id,
            new_status=req.status.value,
            reason=req.reason,
            actor_user_id=current_user.user_id,
            actor_username=current_user.username,
        )
        return inc.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{incident_id}/signals",
    response_model=IncidentSignalResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Link security signal to incident",
    description="Links a security signal (drift alert, trust alert, risk correlation, etc.) to an investigation.",
)
def link_signal(
    incident_id: str,
    req: IncidentSignalCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_SIGNAL_LINK)),
):
    try:
        sig = IncidentService.link_signal(
            db=db,
            incident_id=incident_id,
            signal_type=req.signal_type.value,
            signal_id=req.signal_id,
            relationship_type=req.relationship_type.value,
            actor_user_id=current_user.user_id,
            actor_username=current_user.username,
        )
        return sig.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{incident_id}/evidence",
    response_model=IncidentEvidenceLinkResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Link upstream evidence to incident",
    description="Links immutable upstream evidence (raw log, interpretation, Merkle batch, etc.) by reference without data mutation.",
)
def link_evidence(
    incident_id: str,
    req: IncidentEvidenceLinkRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_EVIDENCE_LINK)),
):
    try:
        ev_link = IncidentService.link_evidence(
            db=db,
            incident_id=incident_id,
            evidence_type=req.evidence_type.value,
            evidence_id=req.evidence_id,
            relationship=req.relationship.value,
            actor_user_id=current_user.user_id,
            actor_username=current_user.username,
        )
        return ev_link.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/{incident_id}/evidence",
    response_model=List[IncidentEvidenceLinkResponse],
    summary="List linked evidence records",
    description="Retrieves all immutable evidence references linked to this investigation.",
)
def list_incident_evidence(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_READ)),
):
    try:
        evidence_links = IncidentService.list_incident_evidence(db=db, incident_id=incident_id)
        return [e.to_dict() for e in evidence_links]
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/{incident_id}/findings",
    response_model=IncidentFindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add analyst investigation finding",
    description="Authors a deterministic investigation finding with strict analyst attribution.",
)
def create_finding(
    incident_id: str,
    req: IncidentFindingCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_FINDING_CREATE)),
):
    try:
        finding = IncidentService.create_finding(
            db=db,
            incident_id=incident_id,
            finding_type=req.finding_type.value,
            title=req.title,
            description=req.description,
            confidence=req.confidence,
            actor_user_id=current_user.user_id,
            actor_username=current_user.username,
        )
        return finding.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch(
    "/{incident_id}/findings/{finding_id}",
    response_model=IncidentFindingResponse,
    summary="Review and update finding status",
    description="Allows authorized reviewers or analysts to confirm or reject an investigation finding.",
)
def review_finding(
    incident_id: str,
    finding_id: str,
    req: IncidentFindingUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_FINDING_REVIEW)),
):
    try:
        finding = IncidentService.update_finding_status(
            db=db,
            incident_id=incident_id,
            finding_id=finding_id,
            new_status=req.status.value,
            comment=req.comment,
            actor_user_id=current_user.user_id,
            actor_username=current_user.username,
        )
        return finding.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/{incident_id}/timeline",
    response_model=List[IncidentTimelineResponse],
    summary="Get incident investigation timeline",
    description="Retrieves the append-only investigation timeline.",
)
def get_incident_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_READ)),
):
    try:
        events = IncidentService.get_incident_timeline(db=db, incident_id=incident_id)
        return [t.to_dict() for t in events]
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{incident_id}/summary",
    response_model=IncidentSummaryResponse,
    summary="Get comprehensive incident investigation summary",
    description="Aggregates metadata, impact metrics, signals, evidence, findings, root cause candidates, and trust context.",
)
def get_incident_summary(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_READ)),
):
    try:
        return IncidentService.get_incident_investigation_summary(db=db, incident_id=incident_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{incident_id}/trace",
    response_model=IncidentTraceResponse,
    summary="Get 13-stage investigation provenance trace",
    description="Generates verifiable 13-stage investigation provenance chain from raw evidence through governance ledger.",
)
def get_incident_provenance_trace(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENT_AUDIT_READ)),
):
    try:
        return IncidentService.get_incident_provenance_trace(db=db, incident_id=incident_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
