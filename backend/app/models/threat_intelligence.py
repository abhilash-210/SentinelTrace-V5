"""
models/threat_intelligence.py
-----------------------------
SQLAlchemy ORM models for Threat Intelligence Integration, Adversary Context,
and Security Intelligence Correlation.

Sprint 11B — Threat Intelligence Integration, Adversary Context & Security Intelligence Correlation.
Core Invariant: "THREAT INTELLIGENCE MUST BE PROVEN, CONTEXTUALIZED, TRACEABLE, AND NEVER BLINDLY TRUSTED."
Zero Trust Threat Intelligence Axioms:
- UNKNOWN IOC != MALICIOUS
- UNKNOWN IOC != SAFE
- STALE INTELLIGENCE != CURRENT INTELLIGENCE
- SOURCE != TRUSTED WITHOUT VERIFICATION
- IOC MATCH != CONFIRMED INCIDENT
- THREAT INTELLIGENCE != AUTONOMOUS ACTION
- UNVERIFIED INTELLIGENCE != HIGH CONFIDENCE
- MISSING PROVENANCE != TRUSTED INTELLIGENCE
- CRYPTOGRAPHIC FAILURE > NUMERICAL TRUST SCORE
"""

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship as orm_relationship
from sqlalchemy.types import JSON

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


ARTIFACT_DOMAIN_PREFIX = "SENTINELTRACE_THREAT_INTELLIGENCE_ARTIFACT_V1"
INDICATOR_DOMAIN_PREFIX = "SENTINELTRACE_THREAT_INDICATOR_V1"
CAMPAIGN_DOMAIN_PREFIX = "SENTINELTRACE_THREAT_CAMPAIGN_V1"
TRUST_EVALUATION_DOMAIN_PREFIX = "SENTINELTRACE_THREAT_TRUST_EVALUATION_V1"
CORRELATION_DOMAIN_PREFIX = "SENTINELTRACE_THREAT_CORRELATION_V1"
PROVENANCE_DOMAIN_PREFIX = "SENTINELTRACE_THREAT_PROVENANCE_V1"


def compute_canonical_hash(prefix: str, payload: Dict[str, Any]) -> str:
    """Deterministic SHA-256 computation over canonical JSON."""
    raw = prefix + ":" + json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ThreatIntelligenceSource(Base):
    """
    4.1 ThreatIntelligenceSource
    Represents a registered threat intelligence feed/source.
    """
    __tablename__ = "threat_intelligence_sources"
    __table_args__ = (
        Index("ix_threat_source_type", "source_type"),
        Index("ix_threat_source_trust", "trust_level"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"tis_{uuid.uuid4().hex[:16]}")
    source_name = Column(String(128), nullable=False, unique=True)
    source_type = Column(String(64), nullable=False)  # INTERNAL, COMMERCIAL, OPEN_SOURCE, GOVERNMENT, SECURITY_RESEARCH, MANUAL
    description = Column(Text, nullable=True)
    provider = Column(String(128), nullable=False)
    trust_level = Column(String(64), nullable=False, default="UNVERIFIED")  # TRUSTED, CONDITIONALLY_TRUSTED, UNVERIFIED, UNTRUSTED
    is_active = Column(Boolean, nullable=False, default=True)
    last_ingested_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # Relationships
    artifacts = orm_relationship("ThreatIntelligenceArtifact", back_populates="source", cascade="all, delete-orphan")


class ThreatIntelligenceArtifact(Base):
    """
    4.2 ThreatIntelligenceArtifact
    Represents an immutable intelligence artifact (IOC bundle, threat report, campaign bulletin).
    """
    __tablename__ = "threat_intelligence_artifacts"
    __table_args__ = (
        Index("ix_threat_artifact_ref", "artifact_reference"),
        Index("ix_threat_artifact_type", "artifact_type"),
        Index("ix_threat_artifact_trust", "trust_status"),
        Index("ix_threat_artifact_hash", "content_hash"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"tia_{uuid.uuid4().hex[:16]}")
    artifact_reference = Column(String(128), nullable=False, unique=True)
    source_id = Column(String(64), ForeignKey("sentinel.threat_intelligence_sources.id"), nullable=False)
    artifact_type = Column(String(64), nullable=False)  # IOC, MALWARE_REPORT, THREAT_ACTOR_REPORT, CAMPAIGN_REPORT, VULNERABILITY_CONTEXT, TACTICAL_INTELLIGENCE
    raw_content_reference = Column(Text, nullable=True)
    normalized_content = Column(JSON, nullable=True)
    content_hash = Column(String(64), nullable=False)
    integrity_status = Column(String(32), nullable=False, default="VALID")  # VALID, TAMPERED, UNKNOWN
    confidence_score = Column(Float, nullable=False, default=100.0)
    trust_status = Column(String(32), nullable=False, default="TRUSTED")  # HIGH_TRUST, TRUSTED, CONDITIONAL, LOW_TRUST, UNTRUSTED
    first_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    # Relationships
    source = orm_relationship("ThreatIntelligenceSource", back_populates="artifacts")
    indicators = orm_relationship("ThreatIndicator", back_populates="artifact", cascade="all, delete-orphan")
    trust_evaluations = orm_relationship("ThreatIntelligenceTrustEvaluation", back_populates="artifact", cascade="all, delete-orphan")
    correlations = orm_relationship("ThreatIntelligenceCorrelation", back_populates="artifact", cascade="all, delete-orphan")
    mitre_mappings = orm_relationship("ThreatMitreMapping", back_populates="artifact", cascade="all, delete-orphan")

    def compute_content_hash(self) -> str:
        payload = {
            "artifact_reference": self.artifact_reference,
            "source_id": self.source_id,
            "artifact_type": self.artifact_type,
            "raw_content_reference": self.raw_content_reference,
            "normalized_content": self.normalized_content,
            "confidence_score": self.confidence_score,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
        return compute_canonical_hash(ARTIFACT_DOMAIN_PREFIX, payload)


class ThreatIndicator(Base):
    """
    4.3 ThreatIndicator
    Canonical IOC registry.
    """
    __tablename__ = "threat_indicators"
    __table_args__ = (
        Index("ix_threat_indicator_type", "indicator_type"),
        Index("ix_threat_indicator_norm_val", "normalized_value"),
        Index("ix_threat_indicator_status", "status"),
        Index("ix_threat_indicator_hash", "indicator_hash"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"ioc_{uuid.uuid4().hex[:16]}")
    indicator_value = Column(String(512), nullable=False)
    indicator_type = Column(String(64), nullable=False)  # IP_ADDRESS, DOMAIN, URL, FILE_HASH, EMAIL_ADDRESS, HOSTNAME
    normalized_value = Column(String(512), nullable=False)
    artifact_id = Column(String(64), ForeignKey("sentinel.threat_intelligence_artifacts.id"), nullable=True)
    confidence_score = Column(Float, nullable=False, default=100.0)
    severity = Column(String(32), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(32), nullable=False, default="ACTIVE")  # ACTIVE, EXPIRED, REVOKED, UNKNOWN
    first_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    indicator_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # Relationships
    artifact = orm_relationship("ThreatIntelligenceArtifact", back_populates="indicators")
    correlations = orm_relationship("ThreatIntelligenceCorrelation", back_populates="indicator", cascade="all, delete-orphan")
    mitre_mappings = orm_relationship("ThreatMitreMapping", back_populates="indicator", cascade="all, delete-orphan")

    def compute_indicator_hash(self) -> str:
        payload = {
            "indicator_type": self.indicator_type,
            "normalized_value": self.normalized_value,
            "artifact_id": self.artifact_id,
            "confidence_score": self.confidence_score,
            "severity": self.severity,
            "status": self.status,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
        return compute_canonical_hash(INDICATOR_DOMAIN_PREFIX, payload)


class ThreatActor(Base):
    """
    4.4 ThreatActor
    Adversary threat actor intelligence profile.
    """
    __tablename__ = "threat_actors"
    __table_args__ = (
        Index("ix_threat_actor_name", "actor_name"),
        Index("ix_threat_actor_status", "status"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"act_{uuid.uuid4().hex[:16]}")
    actor_name = Column(String(128), nullable=False, unique=True)
    aliases = Column(JSON, nullable=True)  # List[str]
    description = Column(Text, nullable=True)
    motivation = Column(String(64), nullable=True)  # FINANCIAL, ESPIONAGE, SABOTAGE, IDEOLOGICAL, UNKNOWN
    sophistication = Column(String(64), nullable=True)  # ADVANCED, INTERMEDIATE, BASIC, UNKNOWN
    origin_context = Column(String(128), nullable=True)
    confidence_score = Column(Float, nullable=False, default=80.0)
    status = Column(String(32), nullable=False, default="ACTIVE")  # ACTIVE, DORMANT, HISTORICAL
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # Relationships
    campaigns = orm_relationship("ThreatCampaign", back_populates="actor")
    actor_campaign_mappings = orm_relationship("ThreatActorCampaignMapping", back_populates="actor", cascade="all, delete-orphan")


class ThreatCampaign(Base):
    """
    4.5 ThreatCampaign
    Targeted malicious campaign or adversary operation.
    """
    __tablename__ = "threat_campaigns"
    __table_args__ = (
        Index("ix_threat_campaign_ref", "campaign_reference"),
        Index("ix_threat_campaign_status", "status"),
        Index("ix_threat_campaign_hash", "campaign_hash"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"cmp_{uuid.uuid4().hex[:16]}")
    campaign_reference = Column(String(128), nullable=False, unique=True)
    campaign_name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    actor_id = Column(String(64), ForeignKey("sentinel.threat_actors.id"), nullable=True)
    status = Column(String(32), nullable=False, default="ACTIVE")  # ACTIVE, CONTAINED, HISTORICAL
    severity = Column(String(32), nullable=False, default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    first_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    confidence_score = Column(Float, nullable=False, default=80.0)
    campaign_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    # Relationships
    actor = orm_relationship("ThreatActor", back_populates="campaigns")
    actor_campaign_mappings = orm_relationship("ThreatActorCampaignMapping", back_populates="campaign", cascade="all, delete-orphan")
    mitre_mappings = orm_relationship("ThreatMitreMapping", back_populates="campaign", cascade="all, delete-orphan")

    def compute_campaign_hash(self) -> str:
        payload = {
            "campaign_reference": self.campaign_reference,
            "campaign_name": self.campaign_name,
            "actor_id": self.actor_id,
            "status": self.status,
            "severity": self.severity,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "confidence_score": self.confidence_score,
        }
        return compute_canonical_hash(CAMPAIGN_DOMAIN_PREFIX, payload)


class ThreatActorCampaignMapping(Base):
    """
    4.6 ThreatActorCampaignMapping
    Maps threat actors to observed campaigns.
    """
    __tablename__ = "threat_actor_campaign_mappings"
    __table_args__ = (
        UniqueConstraint("actor_id", "campaign_id", name="uq_actor_campaign_mapping"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"acm_{uuid.uuid4().hex[:16]}")
    actor_id = Column(String(64), ForeignKey("sentinel.threat_actors.id"), nullable=False)
    campaign_id = Column(String(64), ForeignKey("sentinel.threat_campaigns.id"), nullable=False)
    relationship_type = Column(String(64), nullable=False, default="ATTRIBUTED")  # ATTRIBUTED, SUSPECTED, COLLABORATOR
    confidence_score = Column(Float, nullable=False, default=80.0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    # Relationships
    actor = orm_relationship("ThreatActor", back_populates="actor_campaign_mappings")
    campaign = orm_relationship("ThreatCampaign", back_populates="actor_campaign_mappings")


class ThreatMitreMapping(Base):
    """
    4.7 ThreatMitreMapping
    Maps threat intelligence (artifact, indicator, or campaign) to MITRE ATT&CK framework techniques.
    """
    __tablename__ = "threat_mitre_mappings"
    __table_args__ = (
        Index("ix_threat_mitre_technique", "technique_id"),
        Index("ix_threat_mitre_tactic", "tactic_id"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"tmm_{uuid.uuid4().hex[:16]}")
    artifact_id = Column(String(64), ForeignKey("sentinel.threat_intelligence_artifacts.id"), nullable=True)
    indicator_id = Column(String(64), ForeignKey("sentinel.threat_indicators.id"), nullable=True)
    campaign_id = Column(String(64), ForeignKey("sentinel.threat_campaigns.id"), nullable=True)
    tactic_id = Column(String(64), nullable=False)  # e.g., TA0001 (Initial Access)
    technique_id = Column(String(64), nullable=False)  # e.g., T1566 (Phishing)
    subtechnique_id = Column(String(64), nullable=True)  # e.g., T1566.001
    mapping_confidence = Column(Float, nullable=False, default=90.0)
    mapping_source = Column(String(64), nullable=False, default="MANUAL")  # MANUAL, RULE_DERIVED, VENDOR_REPORT
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    # Relationships
    artifact = orm_relationship("ThreatIntelligenceArtifact", back_populates="mitre_mappings")
    indicator = orm_relationship("ThreatIndicator", back_populates="mitre_mappings")
    campaign = orm_relationship("ThreatCampaign", back_populates="mitre_mappings")


class ThreatIntelligenceCorrelation(Base):
    """
    4.8 ThreatIntelligenceCorrelation
    Represents deterministic IOC correlation against platform security events.
    Zero-Trust Rule: IOC correlation MUST NOT automatically create an incident.
    """
    __tablename__ = "threat_intelligence_correlations"
    __table_args__ = (
        Index("ix_threat_corr_indicator", "indicator_id"),
        Index("ix_threat_corr_event_ref", "event_reference"),
        Index("ix_threat_corr_status", "status"),
        Index("ix_threat_corr_hash", "correlation_hash"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"tic_{uuid.uuid4().hex[:16]}")
    indicator_id = Column(String(64), ForeignKey("sentinel.threat_indicators.id"), nullable=False)
    artifact_id = Column(String(64), ForeignKey("sentinel.threat_intelligence_artifacts.id"), nullable=True)
    event_reference = Column(String(128), nullable=False)
    normalized_event_id = Column(String(64), nullable=True)
    correlation_type = Column(String(64), nullable=False)  # EXACT_MATCH, NORMALIZED_MATCH, PARTIAL_MATCH, CONTEXTUAL_MATCH
    correlation_confidence = Column(Float, nullable=False)  # Clamped 0.0 to 1.0
    match_strength = Column(Float, nullable=False)  # 0.0 to 1.0
    status = Column(String(32), nullable=False, default="OBSERVED")  # OBSERVED, ENRICHED, ESCALATED, DISMISSED, INCONCLUSIVE
    correlation_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    # Relationships
    indicator = orm_relationship("ThreatIndicator", back_populates="correlations")
    artifact = orm_relationship("ThreatIntelligenceArtifact", back_populates="correlations")

    def compute_correlation_hash(self) -> str:
        payload = {
            "indicator_id": self.indicator_id,
            "artifact_id": self.artifact_id,
            "event_reference": self.event_reference,
            "normalized_event_id": self.normalized_event_id,
            "correlation_type": self.correlation_type,
            "correlation_confidence": self.correlation_confidence,
            "match_strength": self.match_strength,
            "status": self.status,
        }
        return compute_canonical_hash(CORRELATION_DOMAIN_PREFIX, payload)


class ThreatIntelligenceTrustEvaluation(Base):
    """
    4.9 ThreatIntelligenceTrustEvaluation
    Deterministic trust scoring breakdown and deduction audit record for an artifact.
    """
    __tablename__ = "threat_trust_evaluations"
    __table_args__ = (
        Index("ix_threat_trust_artifact", "artifact_id"),
        Index("ix_threat_trust_status", "trust_status"),
        Index("ix_threat_trust_hash", "evaluation_hash"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"tte_{uuid.uuid4().hex[:16]}")
    artifact_id = Column(String(64), ForeignKey("sentinel.threat_intelligence_artifacts.id"), nullable=False)
    source_score = Column(Float, nullable=False)
    freshness_score = Column(Float, nullable=False)
    completeness_score = Column(Float, nullable=False)
    cross_validation_score = Column(Float, nullable=False)
    integrity_score = Column(Float, nullable=False)
    final_trust_score = Column(Float, nullable=False)  # Clamped 0.0 to 100.0
    trust_status = Column(String(32), nullable=False)  # HIGH_TRUST, TRUSTED, CONDITIONAL, LOW_TRUST, UNTRUSTED
    deductions_json = Column(JSON, nullable=False, default=list)  # List[Dict[str, Any]]
    evaluation_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    # Relationships
    artifact = orm_relationship("ThreatIntelligenceArtifact", back_populates="trust_evaluations")

    def compute_evaluation_hash(self) -> str:
        payload = {
            "artifact_id": self.artifact_id,
            "source_score": self.source_score,
            "freshness_score": self.freshness_score,
            "completeness_score": self.completeness_score,
            "cross_validation_score": self.cross_validation_score,
            "integrity_score": self.integrity_score,
            "final_trust_score": self.final_trust_score,
            "trust_status": self.trust_status,
            "deductions": self.deductions_json,
        }
        return compute_canonical_hash(TRUST_EVALUATION_DOMAIN_PREFIX, payload)


class ThreatIntelligenceInsight(Base):
    """
    4.10 ThreatIntelligenceInsight
    Deterministic intelligence insights generated for executive and analyst decision support.
    """
    __tablename__ = "threat_intelligence_insights"
    __table_args__ = (
        Index("ix_threat_insight_type", "insight_type"),
        Index("ix_threat_insight_sev", "severity"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"tii_{uuid.uuid4().hex[:16]}")
    insight_type = Column(String(64), nullable=False)  # IOC_CORRELATION, CAMPAIGN_ACTIVITY, ACTOR_PROFILE, TRUST_DEGRADATION, INTEGRITY_ALERT
    severity = Column(String(32), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    confidence_score = Column(Float, nullable=False, default=80.0)
    related_artifact_id = Column(String(64), ForeignKey("sentinel.threat_intelligence_artifacts.id"), nullable=True)
    related_campaign_id = Column(String(64), ForeignKey("sentinel.threat_campaigns.id"), nullable=True)
    related_actor_id = Column(String(64), ForeignKey("sentinel.threat_actors.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)


class ThreatIntelligenceProvenanceRecord(Base):
    """
    4.11 ThreatIntelligenceProvenanceRecord
    Cryptographically traceable 15-stage provenance record linking intelligence to governance ledger.
    """
    __tablename__ = "threat_provenance_records"
    __table_args__ = (
        Index("ix_threat_prov_artifact", "artifact_id"),
        Index("ix_threat_prov_stage_order", "stage_order"),
        Index("ix_threat_prov_hash", "current_hash"),
        {"schema": "sentinel"},
    )

    id = Column(String(64), primary_key=True, default=lambda: f"tip_{uuid.uuid4().hex[:16]}")
    artifact_id = Column(String(64), nullable=False)
    provenance_stage = Column(String(128), nullable=False)
    stage_order = Column(Integer, nullable=False)
    entity_type = Column(String(64), nullable=False)
    entity_reference = Column(String(128), nullable=False)
    previous_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False)
    ledger_reference = Column(String(128), nullable=True)
    merkle_reference = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow)

    def compute_stage_hash(self) -> str:
        payload = {
            "artifact_id": self.artifact_id,
            "provenance_stage": self.provenance_stage,
            "stage_order": self.stage_order,
            "entity_type": self.entity_type,
            "entity_reference": self.entity_reference,
            "previous_hash": self.previous_hash,
            "ledger_reference": self.ledger_reference,
            "merkle_reference": self.merkle_reference,
        }
        return compute_canonical_hash(PROVENANCE_DOMAIN_PREFIX, payload)


# Backward compatibility alias
ThreatProvenanceRecord = ThreatIntelligenceProvenanceRecord

