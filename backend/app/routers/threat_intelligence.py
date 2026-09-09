"""
routers/threat_intelligence.py
------------------------------
FastAPI Router for Threat Intelligence Integration, Adversary Context,
Deterministic IOC Correlation, Trust Scoring & 15-Stage Provenance.

Sprint 11B — Threat Intelligence Integration, Adversary Context & Security Intelligence Correlation.
Prefix: /api/v1/threat-intelligence
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.auth import get_current_user, require_permission
from app.core.rbac import Permission
from app.database import get_db
from app.models.user import User
from app.models.threat_intelligence import (
    ThreatIntelligenceSource,
    ThreatIntelligenceArtifact,
    ThreatIndicator,
    ThreatActor,
    ThreatCampaign,
    ThreatActorCampaignMapping,
    ThreatMitreMapping,
    ThreatIntelligenceCorrelation,
    ThreatIntelligenceTrustEvaluation,
    ThreatIntelligenceInsight,
    ThreatProvenanceRecord,
)
from app.schemas.threat_intelligence import (
    ThreatIntelligenceSourceCreate,
    ThreatIntelligenceSourceUpdate,
    ThreatIntelligenceSourceResponse,
    ThreatIntelligenceArtifactCreate,
    ThreatIntelligenceArtifactResponse,
    ThreatIndicatorCreate,
    ThreatIndicatorUpdate,
    ThreatIndicatorResponse,
    ThreatActorCreate,
    ThreatActorResponse,
    ThreatCampaignCreate,
    ThreatCampaignResponse,
    ThreatActorCampaignMappingCreate,
    ThreatActorCampaignMappingResponse,
    ThreatMitreMappingCreate,
    ThreatMitreMappingResponse,
    ThreatCorrelationExecuteRequest,
    ThreatIntelligenceCorrelationResponse,
    ThreatTrustEvaluationResponse,
    ThreatIntelligenceInsightResponse,
    ThreatProvenanceRecordResponse,
    ThreatIntelligenceDashboardSummary,
    ThreatIntelligenceLandscape,
)
from app.services.threat_indicator_service import ThreatIndicatorService
from app.services.threat_intelligence_trust_service import ThreatIntelligenceTrustService
from app.services.threat_actor_campaign_service import ThreatActorCampaignService
from app.services.threat_mitre_mapping_service import ThreatMitreMappingService
from app.services.threat_intelligence_correlation_service import ThreatIntelligenceCorrelationService
from app.services.threat_intelligence_provenance_service import ThreatIntelligenceProvenanceService

router = APIRouter(
    prefix="/api/v1/threat-intelligence",
    tags=["Threat Intelligence & Adversary Context"],
)


# ── Dashboard & Summary ───────────────────────────────────────────────────────
@router.get(
    "/dashboard/summary",
    response_model=ThreatIntelligenceDashboardSummary,
    summary="Get Threat Intelligence Command Center KPI metrics",
)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    return ThreatIntelligenceCorrelationService.get_dashboard_summary(db)


@router.get(
    "/dashboard/threat-landscape",
    response_model=ThreatIntelligenceLandscape,
    summary="Get aggregated threat landscape, distributions, and insights",
)
def get_threat_landscape(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    return ThreatIntelligenceCorrelationService.get_threat_landscape(db)


# ── Sources ───────────────────────────────────────────────────────────────────
@router.get(
    "/sources",
    response_model=List[ThreatIntelligenceSourceResponse],
    summary="List registered threat intelligence feeds and sources",
)
def list_sources(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    return db.query(ThreatIntelligenceSource).order_by(desc(ThreatIntelligenceSource.created_at)).all()


@router.post(
    "/sources",
    response_model=ThreatIntelligenceSourceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new threat intelligence source feed",
)
def create_source(
    payload: ThreatIntelligenceSourceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCE_MANAGE)),
):
    existing = db.query(ThreatIntelligenceSource).filter(
        ThreatIntelligenceSource.source_name == payload.source_name
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Threat intelligence source '{payload.source_name}' already registered.",
        )

    source = ThreatIntelligenceSource(
        source_name=payload.source_name,
        source_type=payload.source_type.upper(),
        description=payload.description,
        provider=payload.provider,
        trust_level=payload.trust_level.upper(),
        is_active=payload.is_active,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


@router.get(
    "/sources/{source_id}",
    response_model=ThreatIntelligenceSourceResponse,
    summary="Get source feed details",
)
def get_source(
    source_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    source = db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source not found.")
    return source


@router.patch(
    "/sources/{source_id}",
    response_model=ThreatIntelligenceSourceResponse,
    summary="Update threat intelligence source configuration",
)
def update_source(
    source_id: str,
    payload: ThreatIntelligenceSourceUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_SOURCE_MANAGE)),
):
    source = db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.id == source_id).first()
    if not source:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source not found.")

    if payload.source_name is not None:
        source.source_name = payload.source_name
    if payload.description is not None:
        source.description = payload.description
    if payload.provider is not None:
        source.provider = payload.provider
    if payload.trust_level is not None:
        source.trust_level = payload.trust_level.upper()
    if payload.is_active is not None:
        source.is_active = payload.is_active

    db.commit()
    db.refresh(source)
    return source


# ── Artifacts ─────────────────────────────────────────────────────────────────
@router.get(
    "/artifacts",
    response_model=List[ThreatIntelligenceArtifactResponse],
    summary="List ingested threat intelligence artifacts",
)
def list_artifacts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    return db.query(ThreatIntelligenceArtifact).order_by(desc(ThreatIntelligenceArtifact.created_at)).all()


@router.post(
    "/artifacts",
    response_model=ThreatIntelligenceArtifactResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a new threat intelligence artifact",
)
def create_artifact(
    payload: ThreatIntelligenceArtifactCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_INGEST)),
):
    source = db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.id == payload.source_id).first()
    if not source:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source ID does not exist.")

    existing = db.query(ThreatIntelligenceArtifact).filter(
        ThreatIntelligenceArtifact.artifact_reference == payload.artifact_reference
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Artifact '{payload.artifact_reference}' already exists.",
        )

    artifact = ThreatIntelligenceArtifact(
        artifact_reference=payload.artifact_reference,
        source_id=payload.source_id,
        artifact_type=payload.artifact_type.upper(),
        raw_content_reference=payload.raw_content_reference,
        normalized_content=payload.normalized_content or {},
        content_hash="",
        integrity_status="VALID",
        confidence_score=payload.confidence_score,
        trust_status="TRUSTED",
        first_seen=payload.first_seen,
        last_seen=payload.last_seen,
        expires_at=payload.expires_at,
    )
    artifact.content_hash = artifact.compute_content_hash()

    db.add(artifact)
    db.commit()
    db.refresh(artifact)

    # Initial trust evaluation
    ThreatIntelligenceTrustService.evaluate_artifact_trust(db, artifact.id, actor_user_id=current_user.username)
    db.commit()
    db.refresh(artifact)

    return artifact


@router.get(
    "/artifacts/{artifact_id}",
    response_model=ThreatIntelligenceArtifactResponse,
    summary="Get threat intelligence artifact details",
)
def get_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    art = db.query(ThreatIntelligenceArtifact).filter(ThreatIntelligenceArtifact.id == artifact_id).first()
    if not art:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found.")
    return art


# ── Indicators (IOCs) ─────────────────────────────────────────────────────────
@router.get(
    "/indicators",
    response_model=List[ThreatIndicatorResponse],
    summary="List canonical IOC indicators with optional filters",
)
def list_indicators(
    indicator_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    q = db.query(ThreatIndicator)
    if indicator_type:
        q = q.filter(ThreatIndicator.indicator_type == indicator_type.upper())
    if severity:
        q = q.filter(ThreatIndicator.severity == severity.upper())
    if status_filter:
        q = q.filter(ThreatIndicator.status == status_filter.upper())
    return q.order_by(desc(ThreatIndicator.created_at)).all()


@router.post(
    "/indicators",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register or normalize a threat indicator IOC",
)
def create_indicator(
    payload: ThreatIndicatorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INDICATOR_MANAGE)),
):
    try:
        indicator = ThreatIndicatorService.register_indicator(
            db=db,
            indicator_value=payload.indicator_value,
            indicator_type=payload.indicator_type,
            artifact_id=payload.artifact_id,
            confidence_score=payload.confidence_score,
            severity=payload.severity,
            expires_at=payload.expires_at,
            actor_user_id=current_user.username,
        )
        db.commit()
        db.refresh(indicator)
        return indicator
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/indicators/{indicator_id}",
    response_model=ThreatIndicatorResponse,
    summary="Get indicator IOC details",
)
def get_indicator(
    indicator_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    ind = db.query(ThreatIndicator).filter(ThreatIndicator.id == indicator_id).first()
    if not ind:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found.")
    return ind


@router.patch(
    "/indicators/{indicator_id}",
    response_model=ThreatIndicatorResponse,
    summary="Update indicator status or confidence",
)
def update_indicator(
    indicator_id: str,
    payload: ThreatIndicatorUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INDICATOR_MANAGE)),
):
    ind = db.query(ThreatIndicator).filter(ThreatIndicator.id == indicator_id).first()
    if not ind:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Indicator not found.")

    if payload.confidence_score is not None:
        ind.confidence_score = payload.confidence_score
    if payload.severity is not None:
        ind.severity = payload.severity.upper()
    if payload.status is not None:
        ind.status = payload.status.upper()
    if payload.expires_at is not None:
        ind.expires_at = payload.expires_at
    if payload.is_active is not None:
        ind.is_active = payload.is_active

    ind.indicator_hash = ind.compute_indicator_hash()
    db.commit()
    db.refresh(ind)
    return ind


# ── Trust Evaluation ──────────────────────────────────────────────────────────
@router.post(
    "/artifacts/{artifact_id}/evaluate-trust",
    response_model=ThreatTrustEvaluationResponse,
    summary="Evaluate deterministic trust score and deductions for an artifact",
)
def evaluate_artifact_trust(
    artifact_id: str,
    force_crypto_failure: bool = Query(False),
    conflicting_intelligence: bool = Query(False),
    missing_cross_validation: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_EVALUATE)),
):
    try:
        eval_record = ThreatIntelligenceTrustService.evaluate_artifact_trust(
            db=db,
            artifact_id=artifact_id,
            force_crypto_failure=force_crypto_failure,
            conflicting_intelligence=conflicting_intelligence,
            missing_cross_validation=missing_cross_validation,
            actor_user_id=current_user.username,
        )
        db.commit()
        db.refresh(eval_record)
        return eval_record
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/artifacts/{artifact_id}/trust",
    response_model=List[ThreatTrustEvaluationResponse],
    summary="Get trust evaluation history for an artifact",
)
def get_artifact_trust(
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    return db.query(ThreatIntelligenceTrustEvaluation).filter(
        ThreatIntelligenceTrustEvaluation.artifact_id == artifact_id
    ).order_by(desc(ThreatIntelligenceTrustEvaluation.created_at)).all()


# ── Threat Actors ─────────────────────────────────────────────────────────────
@router.get(
    "/actors",
    response_model=List[ThreatActorResponse],
    summary="List registered adversary threat actor profiles",
)
def list_actors(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    return db.query(ThreatActor).order_by(desc(ThreatActor.created_at)).all()


@router.post(
    "/actors",
    response_model=ThreatActorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new adversary threat actor profile",
)
def create_actor(
    payload: ThreatActorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_ACTOR_MANAGE)),
):
    actor = ThreatActorCampaignService.create_actor(
        db=db,
        actor_name=payload.actor_name,
        aliases=payload.aliases,
        description=payload.description,
        motivation=payload.motivation,
        sophistication=payload.sophistication,
        origin_context=payload.origin_context,
        confidence_score=payload.confidence_score,
        status=payload.status,
        actor_user_id=current_user.username,
    )
    db.commit()
    db.refresh(actor)
    return actor


@router.get(
    "/actors/{actor_id}",
    response_model=ThreatActorResponse,
    summary="Get threat actor profile",
)
def get_actor(
    actor_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    actor = db.query(ThreatActor).filter(ThreatActor.id == actor_id).first()
    if not actor:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found.")
    return actor


# ── Campaigns ─────────────────────────────────────────────────────────────────
@router.get(
    "/campaigns",
    response_model=List[ThreatCampaignResponse],
    summary="List active threat campaigns",
)
def list_campaigns(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    return db.query(ThreatCampaign).order_by(desc(ThreatCampaign.created_at)).all()


@router.post(
    "/campaigns",
    response_model=ThreatCampaignResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new adversary campaign",
)
def create_campaign(
    payload: ThreatCampaignCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_CAMPAIGN_MANAGE)),
):
    campaign = ThreatActorCampaignService.create_campaign(
        db=db,
        campaign_reference=payload.campaign_reference,
        campaign_name=payload.campaign_name,
        description=payload.description,
        actor_id=payload.actor_id,
        severity=payload.severity,
        status=payload.status,
        confidence_score=payload.confidence_score,
        actor_user_id=current_user.username,
    )
    db.commit()
    db.refresh(campaign)
    return campaign


@router.get(
    "/campaigns/{campaign_id}",
    response_model=ThreatCampaignResponse,
    summary="Get threat campaign details",
)
def get_campaign(
    campaign_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    cmp = db.query(ThreatCampaign).filter(ThreatCampaign.id == campaign_id).first()
    if not cmp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found.")
    return cmp


# ── Actor-Campaign Mapping ────────────────────────────────────────────────────
@router.post(
    "/actor-campaign-mappings",
    response_model=ThreatActorCampaignMappingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Map a threat actor to a campaign",
)
def map_actor_campaign(
    payload: ThreatActorCampaignMappingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_ACTOR_MANAGE)),
):
    mapping = ThreatActorCampaignService.map_actor_to_campaign(
        db=db,
        actor_id=payload.actor_id,
        campaign_id=payload.campaign_id,
        relationship_type=payload.relationship_type,
        confidence_score=payload.confidence_score,
    )
    db.commit()
    db.refresh(mapping)
    return mapping


# ── MITRE Mappings ────────────────────────────────────────────────────────────
@router.get(
    "/mitre-mappings",
    response_model=List[ThreatMitreMappingResponse],
    summary="List MITRE ATT&CK taxonomy mappings",
)
def list_mitre_mappings(
    campaign_id: Optional[str] = Query(None),
    indicator_id: Optional[str] = Query(None),
    artifact_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_READ)),
):
    q = db.query(ThreatMitreMapping)
    if campaign_id:
        q = q.filter(ThreatMitreMapping.campaign_id == campaign_id)
    if indicator_id:
        q = q.filter(ThreatMitreMapping.indicator_id == indicator_id)
    if artifact_id:
        q = q.filter(ThreatMitreMapping.artifact_id == artifact_id)
    return q.order_by(desc(ThreatMitreMapping.created_at)).all()


@router.post(
    "/mitre-mappings",
    response_model=ThreatMitreMappingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a MITRE ATT&CK mapping",
)
def create_mitre_mapping(
    payload: ThreatMitreMappingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_MITRE_MAP)),
):
    mapping = ThreatMitreMappingService.create_mapping(
        db=db,
        tactic_id=payload.tactic_id,
        technique_id=payload.technique_id,
        subtechnique_id=payload.subtechnique_id,
        artifact_id=payload.artifact_id,
        indicator_id=payload.indicator_id,
        campaign_id=payload.campaign_id,
        mapping_confidence=payload.mapping_confidence,
        mapping_source=payload.mapping_source,
        actor_user_id=current_user.username,
    )
    db.commit()
    db.refresh(mapping)
    return mapping


# ── Correlation ───────────────────────────────────────────────────────────────
@router.post(
    "/correlations/execute",
    response_model=Optional[ThreatIntelligenceCorrelationResponse],
    summary="Execute deterministic IOC correlation against an observable event",
)
def execute_correlation(
    payload: ThreatCorrelationExecuteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_CORRELATION_EXECUTE)),
):
    try:
        corr = ThreatIntelligenceCorrelationService.correlate_observable(
            db=db,
            event_reference=payload.event_reference,
            observable_value=payload.observable_value,
            observable_type=payload.observable_type,
            normalized_event_id=payload.normalized_event_id,
            actor_user_id=current_user.username,
        )
        if not corr:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No matching IOC found in registry for observable '{payload.observable_value}'.",
            )
        db.commit()
        db.refresh(corr)
        return corr
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/correlations",
    response_model=List[ThreatIntelligenceCorrelationResponse],
    summary="List recorded IOC event correlations",
)
def list_correlations(
    status_filter: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_CORRELATION_READ)),
):
    q = db.query(ThreatIntelligenceCorrelation)
    if status_filter:
        q = q.filter(ThreatIntelligenceCorrelation.status == status_filter.upper())
    return q.order_by(desc(ThreatIntelligenceCorrelation.created_at)).all()


@router.get(
    "/correlations/{correlation_id}",
    response_model=ThreatIntelligenceCorrelationResponse,
    summary="Get correlation details",
)
def get_correlation(
    correlation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_CORRELATION_READ)),
):
    corr = db.query(ThreatIntelligenceCorrelation).filter(ThreatIntelligenceCorrelation.id == correlation_id).first()
    if not corr:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Correlation not found.")
    return corr


# ── Provenance ────────────────────────────────────────────────────────────────
@router.get(
    "/artifacts/{artifact_id}/provenance",
    response_model=List[ThreatProvenanceRecordResponse],
    summary="Get 15-stage unbroken cryptographic provenance lineage for an artifact",
)
def get_artifact_provenance(
    artifact_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTELLIGENCE_PROVENANCE_READ)),
):
    try:
        records = ThreatIntelligenceProvenanceService.get_provenance_chain(db, artifact_id)
        return records
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
