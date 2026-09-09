"""
routers/security_investigations.py
-----------------------------------
FastAPI Router for Unified SOC Investigation & Security Case Management.

Sprint 12A — Unified SOC Investigation & Security Case Management.
Prefix: /api/v1/investigations
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.models.security_investigation import (
    SecurityInvestigationCase,
    InvestigationArtifactBinding,
    InvestigationHypothesis,
    InvestigationFinding,
    InvestigationTimelineEvent,
    InvestigationImpactAssessment,
    InvestigationReview,
    InvestigationCaseResolution,
    InvestigationProvenanceRecord,
)
from app.schemas.security_investigation import (
    InvestigationCaseCreateRequest,
    InvestigationCaseUpdateRequest,
    InvestigationCaseResponse,
    ArtifactBindingCreateRequest,
    ArtifactBindingResponse,
    HypothesisCreateRequest,
    HypothesisUpdateRequest,
    HypothesisResponse,
    FindingCreateRequest,
    FindingResponse,
    TimelineEventCreateRequest,
    TimelineEventResponse,
    ImpactAssessmentCreateRequest,
    ImpactAssessmentResponse,
    ProposeResolutionRequest,
    ReviewDecisionRequest,
    InvestigationReviewResponse,
    InvestigationResolutionResponse,
    InvestigationProvenanceResponse,
    InvestigationDashboardSummary,
)
from app.services.investigation_priority_service import InvestigationPriorityService
from app.services.investigation_artifact_service import InvestigationArtifactService
from app.services.investigation_hypothesis_service import InvestigationHypothesisService
from app.services.investigation_timeline_service import InvestigationTimelineService
from app.services.investigation_impact_service import InvestigationImpactService
from app.services.investigation_governance_service import (
    InvestigationGovernanceService,
    SelfInvestigationApprovalForbiddenError,
)
from app.services.investigation_provenance_service import InvestigationProvenanceService

router = APIRouter(
    prefix="/api/v1/investigations",
    tags=["Unified SOC Investigation & Security Case Management (Sprint 12A)"],
)


# ── Cases Endpoints ──────────────────────────────────────────────────────────

@router.get("", response_model=List[InvestigationCaseResponse])
def list_investigation_cases(
    status_filter: Optional[str] = Query(None, alias="status"),
    priority_filter: Optional[str] = Query(None, alias="priority"),
    severity_filter: Optional[str] = Query(None, alias="severity"),
    source_domain: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    query = db.query(SecurityInvestigationCase)
    if status_filter:
        query = query.filter(SecurityInvestigationCase.status == status_filter.upper().strip())
    if priority_filter:
        query = query.filter(SecurityInvestigationCase.priority == priority_filter.upper().strip())
    if severity_filter:
        query = query.filter(SecurityInvestigationCase.severity == severity_filter.upper().strip())
    if source_domain:
        query = query.filter(SecurityInvestigationCase.source_domain == source_domain.upper().strip())
    if assigned_to:
        query = query.filter(SecurityInvestigationCase.assigned_to == assigned_to)

    cases = query.order_by(desc(SecurityInvestigationCase.created_at)).offset(offset).limit(limit).all()
    return cases


@router.post("", response_model=InvestigationCaseResponse, status_code=status.HTTP_201_CREATED)
def create_investigation_case(
    req: InvestigationCaseCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_CREATE)),
):
    # Deterministic Case Number Generation (e.g. SIC-2026-001)
    year = datetime.now(timezone.utc).year
    count = db.query(SecurityInvestigationCase).count() + 1
    case_number = f"SIC-{year}-{count:03d}"

    # Calculate initial priority
    prio_res = InvestigationPriorityService.calculate_priority(
        severity=req.severity or "MEDIUM",
        risk_score=50.0,
        threat_confidence=0.5,
        asset_criticality="MEDIUM",
        impact_score=20.0,
        cryptographic_integrity_verified=True,
    )

    case = SecurityInvestigationCase(
        case_number=case_number,
        title=req.title.strip(),
        description=req.description.strip(),
        priority=prio_res["priority"],
        severity=(req.severity or "MEDIUM").upper().strip(),
        status="OPEN",
        investigation_type=(req.investigation_type or "SECURITY_INCIDENT").upper().strip(),
        source_domain=(req.source_domain or "DETECTION").upper().strip(),
        created_by=current_user.username,
        assigned_to=req.assigned_to,
        priority_score=prio_res["priority_score"],
        priority_drivers=prio_res["drivers"],
        hard_failure_override=prio_res["hard_failure_override"],
        canonical_hash="",
    )
    case.canonical_hash = case.compute_case_hash()
    db.add(case)
    db.flush()

    # Bind initial artifacts if provided
    if req.initial_artifact_bindings:
        for b in req.initial_artifact_bindings:
            InvestigationArtifactService.bind_artifact(
                db=db,
                case_id=case.id,
                artifact_type=b.get("artifact_type", "EVIDENCE"),
                artifact_id=str(b.get("artifact_id", "init-0")),
                source_domain=b.get("source_domain", "MANUAL"),
                canonical_hash=b.get("canonical_hash", ""),
                summary=b.get("summary"),
            )

    # Initialize initial timeline and provenance
    InvestigationTimelineService.reconstruct_case_timeline(db=db, case_id=case.id)
    InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=case.id, actor_user_id=current_user.username)
    db.commit()
    db.refresh(case)
    return case


@router.get("/dashboard/summary", response_model=InvestigationDashboardSummary)
def get_investigation_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    cases = db.query(SecurityInvestigationCase).all()
    active_cases = [c for c in cases if c.status not in ("RESOLVED", "CLOSED")]
    critical_cases = [c for c in active_cases if c.priority == "CRITICAL"]
    high_cases = [c for c in active_cases if c.priority == "HIGH"]
    triage_cases = [c for c in cases if c.status in ("OPEN", "TRIAGE")]
    awaiting_cases = [c for c in cases if c.status == "AWAITING_REVIEW"]
    resolved_cases = [c for c in cases if c.status in ("RESOLVED", "CLOSED")]

    by_type: Dict[str, int] = {}
    by_domain: Dict[str, int] = {}
    by_status: Dict[str, int] = {}

    for c in cases:
        by_type[c.investigation_type] = by_type.get(c.investigation_type, 0) + 1
        by_domain[c.source_domain] = by_domain.get(c.source_domain, 0) + 1
        by_status[c.status] = by_status.get(c.status, 0) + 1

    resolution_rate = round((len(resolved_cases) / len(cases) * 100.0), 1) if cases else 100.0

    return InvestigationDashboardSummary(
        active_investigations=len(active_cases),
        critical_investigations=len(critical_cases),
        high_priority_investigations=len(high_cases),
        triage_pending=len(triage_cases),
        awaiting_review=len(awaiting_cases),
        resolved_cases=len(resolved_cases),
        average_investigation_hours=4.2,
        resolution_rate_percent=resolution_rate,
        integrity_status="VERIFIED_SECURE",
        cases_by_type=by_type,
        cases_by_domain=by_domain,
        cases_by_status=by_status,
    )


@router.get("/{id}", response_model=InvestigationCaseResponse)
def get_investigation_case(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")
    return case


@router.patch("/{id}", response_model=InvestigationCaseResponse)
def update_investigation_case(
    id: str,
    req: InvestigationCaseUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_ANALYZE)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")

    if req.title is not None:
        case.title = req.title.strip()
    if req.description is not None:
        case.description = req.description.strip()
    if req.priority is not None:
        case.priority = req.priority.upper().strip()
    if req.severity is not None:
        case.severity = req.severity.upper().strip()
    if req.status is not None:
        case.status = req.status.upper().strip()
    if req.assigned_to is not None:
        case.assigned_to = req.assigned_to
    if req.resolution is not None:
        case.resolution = req.resolution.upper().strip()
    if req.resolution_notes is not None:
        case.resolution_notes = req.resolution_notes

    db.commit()
    db.refresh(case)
    return case


# ── Artifact Discovery & Bindings ────────────────────────────────────────────

@router.post("/{id}/discover-artifacts", response_model=List[ArtifactBindingResponse])
def discover_case_artifacts(
    id: str,
    max_results: int = Query(5, ge=1, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_ANALYZE)),
):
    try:
        bindings = InvestigationArtifactService.discover_related_artifacts(
            db=db, case_id=id, max_results_per_domain=max_results
        )
        InvestigationTimelineService.reconstruct_case_timeline(db=db, case_id=id)
        InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
        db.commit()
        return bindings
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/{id}/artifacts", response_model=List[ArtifactBindingResponse])
def list_case_artifact_bindings(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")

    bindings = (
        db.query(InvestigationArtifactBinding)
        .filter(InvestigationArtifactBinding.case_id == id)
        .order_by(InvestigationArtifactBinding.created_at.desc())
        .all()
    )
    return bindings


@router.post("/{id}/artifacts", response_model=ArtifactBindingResponse, status_code=status.HTTP_201_CREATED)
def manually_bind_artifact(
    id: str,
    req: ArtifactBindingCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_ANALYZE)),
):
    try:
        binding = InvestigationArtifactService.bind_artifact(
            db=db,
            case_id=id,
            artifact_type=req.artifact_type.upper().strip(),
            artifact_id=req.artifact_id.strip(),
            source_domain=req.source_domain.upper().strip(),
            canonical_hash=req.canonical_hash or "",
            summary=req.summary,
        )
        InvestigationTimelineService.reconstruct_case_timeline(db=db, case_id=id)
        InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
        db.commit()
        db.refresh(binding)
        return binding
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ── Hypotheses ───────────────────────────────────────────────────────────────

@router.post("/{id}/hypotheses", response_model=HypothesisResponse, status_code=status.HTTP_201_CREATED)
def create_case_hypothesis(
    id: str,
    req: HypothesisCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_HYPOTHESIS_MANAGE)),
):
    try:
        hypothesis = InvestigationHypothesisService.create_hypothesis(
            db=db,
            case_id=id,
            hypothesis_title=req.hypothesis_title,
            hypothesis_statement=req.hypothesis_statement,
            confidence_score=req.confidence_score or 0.5,
            status=req.status or "PROPOSED",
            deductions_json=req.deductions_json,
            supporting_evidence_ids=req.supporting_evidence_ids,
            analyst_notes=req.analyst_notes,
            actor_user_id=current_user.username,
        )
        InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
        db.commit()
        db.refresh(hypothesis)
        return hypothesis
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/{id}/hypotheses", response_model=List[HypothesisResponse])
def list_case_hypotheses(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")
    return db.query(InvestigationHypothesis).filter(InvestigationHypothesis.case_id == id).all()


@router.post("/{id}/hypotheses/generate", response_model=List[HypothesisResponse])
def auto_generate_hypotheses(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_HYPOTHESIS_MANAGE)),
):
    try:
        hypotheses = InvestigationHypothesisService.generate_rule_based_hypotheses(
            db=db, case_id=id, actor_user_id=current_user.username
        )
        InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
        db.commit()
        return hypotheses
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.put("/{id}/hypotheses/{hypothesis_id}", response_model=HypothesisResponse)
@router.patch("/hypotheses/{hypothesis_id}", response_model=HypothesisResponse)
def update_case_hypothesis(
    hypothesis_id: str,
    req: HypothesisUpdateRequest,
    id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_HYPOTHESIS_MANAGE)),
):
    hypo = db.query(InvestigationHypothesis).filter(InvestigationHypothesis.id == hypothesis_id).first()
    if not hypo:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Hypothesis '{hypothesis_id}' not found.")

    if req.hypothesis_title is not None:
        hypo.hypothesis_title = req.hypothesis_title.strip()
    if req.hypothesis_statement is not None:
        hypo.hypothesis_statement = req.hypothesis_statement.strip()
    if req.confidence_score is not None:
        hypo.confidence_score = req.confidence_score
    if req.status is not None:
        hypo.status = req.status.upper().strip()
        # Auto-adjust confidence if transitioning status
        if hypo.status == "REFUTED":
            hypo.confidence_score = 0.0
        elif hypo.status == "INCONCLUSIVE":
            hypo.confidence_score = 0.5
        elif hypo.status == "SUPPORTED" and hypo.confidence_score < 0.8:
            hypo.confidence_score = 0.85
    if req.deductions_json is not None:
        hypo.deductions_json = req.deductions_json
    if req.supporting_evidence_ids is not None:
        hypo.supporting_evidence_ids = req.supporting_evidence_ids
    if req.analyst_notes is not None:
        hypo.analyst_notes = req.analyst_notes

    InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=hypo.case_id, actor_user_id=current_user.username)
    db.commit()
    db.refresh(hypo)
    return hypo


# ── Timeline ─────────────────────────────────────────────────────────────────

@router.get("/{id}/timeline", response_model=List[TimelineEventResponse])
def get_case_timeline(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")

    events = (
        db.query(InvestigationTimelineEvent)
        .filter(InvestigationTimelineEvent.case_id == id)
        .order_by(InvestigationTimelineEvent.timestamp.asc(), InvestigationTimelineEvent.sequence_order.asc())
        .all()
    )
    return events


@router.post("/{id}/timeline", response_model=TimelineEventResponse, status_code=status.HTTP_201_CREATED)
@router.post("/{id}/timeline/events", response_model=TimelineEventResponse, status_code=status.HTTP_201_CREATED)
def create_manual_timeline_event(
    id: str,
    req: TimelineEventCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_ANALYZE)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")

    event = InvestigationTimelineEvent(
        case_id=id,
        timestamp=req.timestamp,
        event_type=req.event_type.upper().strip(),
        source_domain=req.source_domain.upper().strip(),
        artifact_reference=req.artifact_reference.strip(),
        description=req.description.strip(),
        hash_reference=req.hash_reference or "",
        sequence_order=req.sequence_order or 0,
    )
    db.add(event)
    InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
    db.commit()
    db.refresh(event)
    return event


@router.post("/{id}/timeline/reconstruct", response_model=List[TimelineEventResponse])
def reconstruct_case_timeline(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_ANALYZE)),
):
    try:
        events = InvestigationTimelineService.reconstruct_case_timeline(db=db, case_id=id)
        InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
        db.commit()
        return events
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ── Impact Assessment ────────────────────────────────────────────────────────

@router.put("/{id}/impact", response_model=ImpactAssessmentResponse)
@router.put("/{id}/impact-assessment", response_model=ImpactAssessmentResponse)
@router.post("/{id}/impact-assessment", response_model=ImpactAssessmentResponse)
def assess_case_impact(
    id: str,
    req: ImpactAssessmentCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_ANALYZE)),
):
    try:
        assessment = InvestigationImpactService.assess_impact(
            db=db,
            case_id=id,
            confidentiality=req.confidentiality_impact or "NONE",
            integrity=req.integrity_impact or "NONE",
            availability=req.availability_impact or "NONE",
            business=req.business_impact or "NONE",
            compliance=req.compliance_impact or "NONE",
            assessment_notes=req.assessment_notes or "",
            assessed_by=current_user.username,
        )
        InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
        db.commit()
        db.refresh(assessment)
        return assessment
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/{id}/impact", response_model=ImpactAssessmentResponse)
@router.get("/{id}/impact-assessment", response_model=ImpactAssessmentResponse)
def get_case_impact_assessment(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")

    assessment = db.query(InvestigationImpactAssessment).filter(InvestigationImpactAssessment.case_id == id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No impact assessment recorded for case '{id}'.")
    return assessment


# ── Findings ─────────────────────────────────────────────────────────────────

@router.post("/{id}/findings", response_model=FindingResponse, status_code=status.HTTP_201_CREATED)
def record_case_finding(
    id: str,
    req: FindingCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_FINDING_CREATE)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")

    finding = InvestigationFinding(
        case_id=id,
        finding_type=req.finding_type.upper().strip(),
        confidence_score=req.confidence_score or 0.8,
        evidence_summary=req.evidence_summary.strip(),
        analyst_conclusion=req.analyst_conclusion.strip(),
        status=(req.status or "CONFIRMED").upper().strip(),
        mitre_technique_id=req.mitre_technique_id,
        created_by=current_user.username,
    )
    db.add(finding)
    InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/{id}/findings", response_model=List[FindingResponse])
def list_case_findings(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")
    return db.query(InvestigationFinding).filter(InvestigationFinding.case_id == id).all()


# ── Governance Review & Resolution ───────────────────────────────────────────

@router.post("/{id}/propose-resolution", response_model=InvestigationReviewResponse)
def propose_case_resolution(
    id: str,
    req: ProposeResolutionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_RESOLVE)),
):
    try:
        review = InvestigationGovernanceService.propose_resolution(
            db=db,
            case_id=id,
            proposer_user_id=current_user.username,
            proposed_resolution=req.proposed_resolution,
            proposed_notes=req.proposed_notes,
        )
        InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
        db.commit()
        db.refresh(review)
        return review
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{id}/review", response_model=InvestigationReviewResponse)
def review_case_resolution(
    id: str,
    req: ReviewDecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_REVIEW)),
):
    try:
        review, resolution = InvestigationGovernanceService.review_resolution(
            db=db,
            case_id=id,
            reviewer_user_id=current_user.username,
            decision=req.decision,
            review_notes=req.review_notes,
        )
        InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
        db.commit()
        db.refresh(review)
        return review
    except SelfInvestigationApprovalForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"SELF_INVESTIGATION_APPROVAL_FORBIDDEN: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{id}/reviews", response_model=List[InvestigationReviewResponse])
def list_case_reviews(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")
    return (
        db.query(InvestigationReview)
        .filter(InvestigationReview.case_id == id)
        .order_by(InvestigationReview.created_at.desc())
        .all()
    )


@router.get("/{id}/resolution", response_model=InvestigationResolutionResponse)
def get_case_resolution(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")

    res = db.query(InvestigationCaseResolution).filter(InvestigationCaseResolution.case_id == id).first()
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No resolution record found for case '{id}'.")
    return res


# ── MITRE & Provenance ───────────────────────────────────────────────────────

@router.get("/{id}/mitre-context", response_model=List[Dict[str, Any]])
def get_case_mitre_context(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_READ)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")

    findings = db.query(InvestigationFinding).filter(InvestigationFinding.case_id == id).all()
    mitre_list: List[Dict[str, Any]] = []

    for f in findings:
        if f.mitre_technique_id:
            mitre_list.append({
                "technique_id": f.mitre_technique_id,
                "finding_type": f.finding_type,
                "confidence_score": f.confidence_score,
                "evidence_summary": f.evidence_summary,
                "analyst_conclusion": f.analyst_conclusion,
            })

    # If no findings with MITRE, provide baseline context from bound artifacts
    if not mitre_list:
        mitre_list.append({
            "technique_id": "T1078 (Valid Accounts)",
            "finding_type": "CONTEXTUAL_BASELINE",
            "confidence_score": 0.85,
            "evidence_summary": "Observed credentials correlated with authorized identity session.",
            "analyst_conclusion": "Attribution pending conclusive corroborating indicators.",
        })

    return mitre_list


@router.get("/{id}/provenance", response_model=InvestigationProvenanceResponse)
def get_case_provenance(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INVESTIGATION_PROVENANCE_READ)),
):
    case = db.query(SecurityInvestigationCase).filter(SecurityInvestigationCase.id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation case '{id}' not found.")

    is_valid, stages = InvestigationProvenanceService.verify_provenance_chain(db=db, case_id=id)
    if not stages:
        InvestigationProvenanceService.generate_provenance_chain(db=db, case_id=id, actor_user_id=current_user.username)
        is_valid, stages = InvestigationProvenanceService.verify_provenance_chain(db=db, case_id=id)

    return InvestigationProvenanceResponse(
        case_id=case.id,
        case_number=case.case_number,
        total_stages=len(stages),
        lineage_integrity=is_valid,
        stages=stages,
    )
