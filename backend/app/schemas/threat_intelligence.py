"""
schemas/threat_intelligence.py
------------------------------
Pydantic v2 schemas for Threat Intelligence Integration, Adversary Context,
and Security Intelligence Correlation.

Sprint 11B — Threat Intelligence Integration, Adversary Context & Security Intelligence Correlation.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ── Threat Intelligence Source ────────────────────────────────────────────────
class ThreatIntelligenceSourceBase(BaseModel):
    source_name: str = Field(..., min_length=2, max_length=128)
    source_type: str = Field(..., description="INTERNAL, COMMERCIAL, OPEN_SOURCE, GOVERNMENT, SECURITY_RESEARCH, MANUAL")
    description: Optional[str] = None
    provider: str = Field(..., min_length=2, max_length=128)
    trust_level: str = Field(default="UNVERIFIED", description="TRUSTED, CONDITIONALLY_TRUSTED, UNVERIFIED, UNTRUSTED")
    is_active: bool = True


class ThreatIntelligenceSourceCreate(ThreatIntelligenceSourceBase):
    pass


class ThreatIntelligenceSourceUpdate(BaseModel):
    source_name: Optional[str] = None
    description: Optional[str] = None
    provider: Optional[str] = None
    trust_level: Optional[str] = None
    is_active: Optional[bool] = None


class ThreatIntelligenceSourceResponse(ThreatIntelligenceSourceBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    last_ingested_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


# ── Threat Intelligence Artifact ──────────────────────────────────────────────
class ThreatIntelligenceArtifactBase(BaseModel):
    artifact_reference: str = Field(..., min_length=2, max_length=128)
    source_id: str
    artifact_type: str = Field(..., description="IOC, MALWARE_REPORT, THREAT_ACTOR_REPORT, CAMPAIGN_REPORT, VULNERABILITY_CONTEXT, TACTICAL_INTELLIGENCE")
    raw_content_reference: Optional[str] = None
    normalized_content: Optional[Dict[str, Any]] = None
    confidence_score: float = Field(default=100.0, ge=0.0, le=100.0)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class ThreatIntelligenceArtifactCreate(ThreatIntelligenceArtifactBase):
    pass


class ThreatIntelligenceArtifactResponse(ThreatIntelligenceArtifactBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    content_hash: str
    integrity_status: str
    trust_status: str
    created_at: datetime


# ── Threat Indicator (IOC) ────────────────────────────────────────────────────
class ThreatIndicatorBase(BaseModel):
    indicator_value: str = Field(..., min_length=1, max_length=512)
    indicator_type: str = Field(..., description="IP_ADDRESS, DOMAIN, URL, FILE_HASH, EMAIL_ADDRESS, HOSTNAME")
    artifact_id: Optional[str] = None
    confidence_score: float = Field(default=100.0, ge=0.0, le=100.0)
    severity: str = Field(default="MEDIUM", description="LOW, MEDIUM, HIGH, CRITICAL")
    status: str = Field(default="ACTIVE", description="ACTIVE, EXPIRED, REVOKED, UNKNOWN")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_active: bool = True


class ThreatIndicatorCreate(ThreatIndicatorBase):
    pass


class ThreatIndicatorUpdate(BaseModel):
    confidence_score: Optional[float] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    expires_at: Optional[datetime] = None
    is_active: Optional[bool] = None


class ThreatIndicatorResponse(ThreatIndicatorBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    normalized_value: str
    indicator_hash: str
    created_at: datetime
    updated_at: datetime


# ── Threat Actor ──────────────────────────────────────────────────────────────
class ThreatActorBase(BaseModel):
    actor_name: str = Field(..., min_length=2, max_length=128)
    aliases: Optional[List[str]] = None
    description: Optional[str] = None
    motivation: Optional[str] = None
    sophistication: Optional[str] = None
    origin_context: Optional[str] = None
    confidence_score: float = Field(default=80.0, ge=0.0, le=100.0)
    status: str = Field(default="ACTIVE")


class ThreatActorCreate(ThreatActorBase):
    pass


class ThreatActorResponse(ThreatActorBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    updated_at: datetime


# ── Threat Campaign ───────────────────────────────────────────────────────────
class ThreatCampaignBase(BaseModel):
    campaign_reference: str = Field(..., min_length=2, max_length=128)
    campaign_name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = None
    actor_id: Optional[str] = None
    status: str = Field(default="ACTIVE")
    severity: str = Field(default="HIGH")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence_score: float = Field(default=80.0, ge=0.0, le=100.0)


class ThreatCampaignCreate(ThreatCampaignBase):
    pass


class ThreatCampaignResponse(ThreatCampaignBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    campaign_hash: str
    created_at: datetime
    updated_at: datetime


# ── Threat Actor-Campaign Mapping ─────────────────────────────────────────────
class ThreatActorCampaignMappingCreate(BaseModel):
    actor_id: str
    campaign_id: str
    relationship_type: str = Field(default="ATTRIBUTED", description="ATTRIBUTED, SUSPECTED, COLLABORATOR")
    confidence_score: float = Field(default=80.0, ge=0.0, le=100.0)


class ThreatActorCampaignMappingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor_id: str
    campaign_id: str
    relationship_type: str
    confidence_score: float
    created_at: datetime


# ── Threat MITRE Mapping ──────────────────────────────────────────────────────
class ThreatMitreMappingCreate(BaseModel):
    artifact_id: Optional[str] = None
    indicator_id: Optional[str] = None
    campaign_id: Optional[str] = None
    tactic_id: str = Field(..., min_length=2, max_length=64)
    technique_id: str = Field(..., min_length=2, max_length=64)
    subtechnique_id: Optional[str] = None
    mapping_confidence: float = Field(default=90.0, ge=0.0, le=100.0)
    mapping_source: str = Field(default="MANUAL")


class ThreatMitreMappingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    artifact_id: Optional[str] = None
    indicator_id: Optional[str] = None
    campaign_id: Optional[str] = None
    tactic_id: str
    technique_id: str
    subtechnique_id: Optional[str] = None
    mapping_confidence: float
    mapping_source: str
    created_at: datetime


# ── Threat Correlation ────────────────────────────────────────────────────────
class ThreatCorrelationExecuteRequest(BaseModel):
    event_reference: str
    normalized_event_id: Optional[str] = None
    observable_value: str
    observable_type: Optional[str] = None


class ThreatIntelligenceCorrelationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    indicator_id: str
    artifact_id: Optional[str] = None
    event_reference: str
    normalized_event_id: Optional[str] = None
    correlation_type: str
    correlation_confidence: float
    match_strength: float
    status: str
    correlation_hash: str
    created_at: datetime


# ── Trust Evaluation ──────────────────────────────────────────────────────────
class ThreatTrustEvaluationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    artifact_id: str
    source_score: float
    freshness_score: float
    completeness_score: float
    cross_validation_score: float
    integrity_score: float
    final_trust_score: float
    trust_status: str
    deductions_json: List[Dict[str, Any]]
    evaluation_hash: str
    created_at: datetime


# ── Insights ──────────────────────────────────────────────────────────────────
class ThreatIntelligenceInsightResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    insight_type: str
    severity: str
    title: str
    description: str
    confidence_score: float
    related_artifact_id: Optional[str] = None
    related_campaign_id: Optional[str] = None
    related_actor_id: Optional[str] = None
    created_at: datetime


# ── Provenance ────────────────────────────────────────────────────────────────
class ThreatProvenanceRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    artifact_id: str
    provenance_stage: str
    stage_order: int
    entity_type: str
    entity_reference: str
    previous_hash: str
    current_hash: str
    ledger_reference: Optional[str] = None
    merkle_reference: Optional[str] = None
    created_at: datetime


# ── Dashboard & Threat Landscape ──────────────────────────────────────────────
class ThreatIntelligenceDashboardSummary(BaseModel):
    global_threat_intel_score: float
    active_ioc_count: int
    high_confidence_threats: int
    active_campaigns_count: int
    correlation_count: int
    intelligence_integrity_status: str
    total_sources: int
    trusted_sources_count: int
    timestamp: datetime


class ThreatIntelligenceLandscape(BaseModel):
    severity_distribution: Dict[str, int]
    indicator_type_distribution: Dict[str, int]
    active_campaigns: List[ThreatCampaignResponse]
    top_threat_actors: List[ThreatActorResponse]
    recent_insights: List[ThreatIntelligenceInsightResponse]
    timestamp: datetime
