"""
services/threat_intelligence_correlation_service.py
--------------------------------------------------
Deterministic Threat Intelligence & IOC Event Correlation Engine.

Sprint 11B — Threat Intelligence Integration, Adversary Context & Security Intelligence Correlation.
Core Invariant: "IOC MATCH REPRESENTS CORRELATION EVIDENCE, NOT AUTOMATIC ATTACK CONFIRMATION."
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.threat_intelligence import (
    ThreatIndicator,
    ThreatIntelligenceArtifact,
    ThreatIntelligenceCorrelation,
    ThreatIntelligenceInsight,
    ThreatCampaign,
    ThreatActor,
    ThreatIntelligenceSource,
    CORRELATION_DOMAIN_PREFIX,
    compute_canonical_hash,
)
from app.models.normalized_event import NormalizedEvent
from app.services.threat_indicator_service import ThreatIndicatorService
from app.services.governance_ledger_service import GovernanceLedgerService


def to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class ThreatIntelligenceCorrelationService:
    """
    Executes deterministic observable correlation between security events and threat intelligence IOCs.
    """

    @staticmethod
    def correlate_observable(
        db: Session,
        event_reference: str,
        observable_value: str,
        observable_type: Optional[str] = None,
        normalized_event_id: Optional[str] = None,
        actor_user_id: str = "SYSTEM",
    ) -> Optional[ThreatIntelligenceCorrelation]:
        if not observable_value or not observable_value.strip():
            raise ValueError("Observable value cannot be empty.")

        val = observable_value.strip()

        # Attempt to normalize
        cand_types = [observable_type] if observable_type else ["IP_ADDRESS", "DOMAIN", "URL", "FILE_HASH", "EMAIL_ADDRESS", "HOSTNAME"]
        matched_indicator = None
        match_type = "EXACT_MATCH"
        match_strength = 1.0

        for t in cand_types:
            try:
                norm_type, norm_val = ThreatIndicatorService.normalize_indicator(t, val)
                # Search exact match
                ind = db.query(ThreatIndicator).filter(
                    ThreatIndicator.indicator_type == norm_type,
                    ThreatIndicator.normalized_value == norm_val,
                ).first()
                if ind:
                    matched_indicator = ind
                    match_type = "EXACT_MATCH"
                    match_strength = 1.00
                    break

                # Search partial domain/host match if applicable
                if norm_type in ("DOMAIN", "HOSTNAME"):
                    parts = norm_val.split(".")
                    for i in range(1, len(parts) - 1):
                        parent_candidate = ".".join(parts[i:])
                        ind_partial = db.query(ThreatIndicator).filter(
                            ThreatIndicator.indicator_type == norm_type,
                            ThreatIndicator.normalized_value == parent_candidate,
                        ).first()
                        if ind_partial:
                            matched_indicator = ind_partial
                            match_type = "PARTIAL_MATCH"
                            match_strength = 0.60
                            break
                    if matched_indicator:
                        break
            except ValueError:
                continue

        if not matched_indicator:
            # Check raw fallback
            matched_indicator = db.query(ThreatIndicator).filter(
                ThreatIndicator.indicator_value == val
            ).first()
            if matched_indicator:
                match_type = "NORMALIZED_MATCH"
                match_strength = 0.90

        if not matched_indicator:
            return None

        # Fetch parent artifact for trust factor
        artifact = db.query(ThreatIntelligenceArtifact).filter(
            ThreatIntelligenceArtifact.id == matched_indicator.artifact_id
        ).first() if matched_indicator.artifact_id else None

        # 1. IOC Trust Factor
        trust_status = artifact.trust_status if artifact else "CONDITIONAL"
        if matched_indicator.status == "REVOKED" or matched_indicator.status == "UNKNOWN":
            trust_factor = 0.00
        elif trust_status == "HIGH_TRUST":
            trust_factor = 1.00
        elif trust_status == "TRUSTED":
            trust_factor = 0.90
        elif trust_status == "CONDITIONAL":
            trust_factor = 0.70
        elif trust_status == "LOW_TRUST":
            trust_factor = 0.40
        else:  # UNTRUSTED
            trust_factor = 0.00

        # 2. Freshness Factor
        now = datetime.now(timezone.utc)
        exp_utc = to_utc(matched_indicator.expires_at)
        lseen_utc = to_utc(matched_indicator.last_seen)
        if exp_utc and exp_utc < now:
            freshness_factor = 0.00
        elif lseen_utc:
            age_days = (now - lseen_utc).total_seconds() / 86400.0
            if age_days <= 30:
                freshness_factor = 1.00
            elif age_days <= 90:
                freshness_factor = 0.75
            else:
                freshness_factor = 0.40
        else:
            freshness_factor = 0.75

        # 3. Deterministic Formula
        # Correlation Confidence = Match Strength * IOC Trust Factor * Freshness Factor
        correlation_confidence = match_strength * trust_factor * freshness_factor
        correlation_confidence = max(0.0, min(1.0, correlation_confidence))

        # Status determination (Zero-Trust rule: IOC Match != Confirmed Incident)
        if trust_factor == 0.0 or freshness_factor == 0.0:
            status = "INCONCLUSIVE"
        elif correlation_confidence >= 0.70:
            status = "ENRICHED"
        else:
            status = "OBSERVED"

        correlation = ThreatIntelligenceCorrelation(
            indicator_id=matched_indicator.id,
            artifact_id=artifact.id if artifact else None,
            event_reference=event_reference,
            normalized_event_id=normalized_event_id,
            correlation_type=match_type,
            correlation_confidence=correlation_confidence,
            match_strength=match_strength,
            status=status,
            correlation_hash="",
        )
        correlation.correlation_hash = correlation.compute_correlation_hash()

        db.add(correlation)
        db.flush()

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="THREAT_INTELLIGENCE_CORRELATION_RECORDED",
                actor_user_id=actor_user_id,
                details={
                    "correlation_id": correlation.id,
                    "event_reference": event_reference,
                    "indicator_id": matched_indicator.id,
                    "indicator_value": matched_indicator.normalized_value,
                    "correlation_type": match_type,
                    "confidence": correlation_confidence,
                    "status": status,
                },
            )
        except Exception:
            pass

        return correlation

    @staticmethod
    def get_dashboard_summary(db: Session) -> Dict[str, Any]:
        """
        Calculates command center KPIs.
        """
        active_iocs = db.query(ThreatIndicator).filter(ThreatIndicator.is_active == True).count()
        high_confidence = db.query(ThreatIndicator).filter(
            ThreatIndicator.is_active == True,
            ThreatIndicator.confidence_score >= 80.0,
        ).count()
        active_campaigns = db.query(ThreatCampaign).filter(ThreatCampaign.status == "ACTIVE").count()
        total_correlations = db.query(ThreatIntelligenceCorrelation).count()

        # Global Threat Intel Score = average trust score of active artifacts
        artifacts = db.query(ThreatIntelligenceArtifact).all()
        if artifacts:
            avg_score = sum(a.confidence_score for a in artifacts) / len(artifacts)
            # Check if any artifact is TAMPERED
            has_tampered = any(a.integrity_status != "VALID" for a in artifacts)
            integrity_status = "TAMPERED" if has_tampered else "VALID"
        else:
            avg_score = 100.0
            integrity_status = "VALID"

        sources_count = db.query(ThreatIntelligenceSource).count()
        trusted_sources = db.query(ThreatIntelligenceSource).filter(
            ThreatIntelligenceSource.trust_level == "TRUSTED"
        ).count()

        return {
            "global_threat_intel_score": round(avg_score, 2),
            "active_ioc_count": active_iocs,
            "high_confidence_threats": high_confidence,
            "active_campaigns_count": active_campaigns,
            "correlation_count": total_correlations,
            "intelligence_integrity_status": integrity_status,
            "total_sources": sources_count,
            "trusted_sources_count": trusted_sources,
            "timestamp": datetime.now(timezone.utc),
        }

    @staticmethod
    def get_threat_landscape(db: Session) -> Dict[str, Any]:
        """
        Aggregates threat landscape distributions.
        """
        # Severity distribution
        iocs = db.query(ThreatIndicator).all()
        sev_dist: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        type_dist: Dict[str, int] = {
            "IP_ADDRESS": 0, "DOMAIN": 0, "URL": 0, "FILE_HASH": 0, "EMAIL_ADDRESS": 0, "HOSTNAME": 0
        }
        for i in iocs:
            s = i.severity.upper() if i.severity else "MEDIUM"
            sev_dist[s] = sev_dist.get(s, 0) + 1
            t = i.indicator_type.upper() if i.indicator_type else "IP_ADDRESS"
            type_dist[t] = type_dist.get(t, 0) + 1

        campaigns = db.query(ThreatCampaign).filter(ThreatCampaign.status == "ACTIVE").all()
        actors = db.query(ThreatActor).filter(ThreatActor.status == "ACTIVE").all()
        insights = db.query(ThreatIntelligenceInsight).order_by(ThreatIntelligenceInsight.created_at.desc()).limit(10).all()

        return {
            "severity_distribution": sev_dist,
            "indicator_type_distribution": type_dist,
            "active_campaigns": campaigns,
            "top_threat_actors": actors,
            "recent_insights": insights,
            "timestamp": datetime.now(timezone.utc),
        }
