"""
services/threat_actor_campaign_service.py
-----------------------------------------
Threat Actor Profiles, Campaign Context, and Intelligence Feeds Management.

Sprint 11B — Threat Intelligence Integration, Adversary Context & Security Intelligence Correlation.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.threat_intelligence import (
    ThreatIntelligenceSource,
    ThreatIntelligenceArtifact,
    ThreatIndicator,
    ThreatActor,
    ThreatCampaign,
    ThreatActorCampaignMapping,
    ThreatIntelligenceInsight,
    CAMPAIGN_DOMAIN_PREFIX,
    compute_canonical_hash,
)
from app.services.threat_indicator_service import ThreatIndicatorService
from app.services.threat_intelligence_trust_service import ThreatIntelligenceTrustService
from app.services.governance_ledger_service import GovernanceLedgerService


class ThreatActorCampaignService:
    """
    Manages threat actors, campaigns, attribution mappings, and baseline intelligence seeding.
    """

    @staticmethod
    def create_actor(
        db: Session,
        actor_name: str,
        aliases: Optional[List[str]] = None,
        description: Optional[str] = None,
        motivation: Optional[str] = "ESPIONAGE",
        sophistication: Optional[str] = "ADVANCED",
        origin_context: Optional[str] = "EASTERN_EUROPE",
        confidence_score: float = 85.0,
        status: str = "ACTIVE",
        actor_user_id: str = "SYSTEM",
    ) -> ThreatActor:
        existing = db.query(ThreatActor).filter(ThreatActor.actor_name == actor_name).first()
        if existing:
            return existing

        actor = ThreatActor(
            actor_name=actor_name,
            aliases=aliases or [],
            description=description,
            motivation=motivation,
            sophistication=sophistication,
            origin_context=origin_context,
            confidence_score=max(0.0, min(100.0, confidence_score)),
            status=status,
        )
        db.add(actor)
        db.flush()

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="THREAT_ACTOR_REGISTERED",
                actor_user_id=actor_user_id,
                details={
                    "actor_id": actor.id,
                    "actor_name": actor.actor_name,
                    "motivation": actor.motivation,
                    "confidence_score": actor.confidence_score,
                },
            )
        except Exception:
            pass

        return actor

    @staticmethod
    def create_campaign(
        db: Session,
        campaign_reference: str,
        campaign_name: str,
        description: Optional[str] = None,
        actor_id: Optional[str] = None,
        severity: str = "HIGH",
        status: str = "ACTIVE",
        confidence_score: float = 85.0,
        actor_user_id: str = "SYSTEM",
    ) -> ThreatCampaign:
        existing = db.query(ThreatCampaign).filter(ThreatCampaign.campaign_reference == campaign_reference).first()
        if existing:
            return existing

        now = datetime.now(timezone.utc)
        campaign = ThreatCampaign(
            campaign_reference=campaign_reference,
            campaign_name=campaign_name,
            description=description,
            actor_id=actor_id,
            status=status,
            severity=severity,
            first_seen=now,
            last_seen=now,
            confidence_score=max(0.0, min(100.0, confidence_score)),
            campaign_hash="",
        )
        campaign.campaign_hash = campaign.compute_campaign_hash()

        db.add(campaign)
        db.flush()

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="THREAT_CAMPAIGN_REGISTERED",
                actor_user_id=actor_user_id,
                details={
                    "campaign_id": campaign.id,
                    "campaign_reference": campaign.campaign_reference,
                    "campaign_name": campaign.campaign_name,
                    "campaign_hash": campaign.campaign_hash,
                },
            )
        except Exception:
            pass

        return campaign

    @staticmethod
    def map_actor_to_campaign(
        db: Session,
        actor_id: str,
        campaign_id: str,
        relationship_type: str = "ATTRIBUTED",
        confidence_score: float = 85.0,
    ) -> ThreatActorCampaignMapping:
        existing = db.query(ThreatActorCampaignMapping).filter(
            ThreatActorCampaignMapping.actor_id == actor_id,
            ThreatActorCampaignMapping.campaign_id == campaign_id,
        ).first()
        if existing:
            return existing

        mapping = ThreatActorCampaignMapping(
            actor_id=actor_id,
            campaign_id=campaign_id,
            relationship_type=relationship_type,
            confidence_score=max(0.0, min(100.0, confidence_score)),
        )
        db.add(mapping)
        db.flush()
        return mapping

    @staticmethod
    def seed_default_threat_intelligence(db: Session) -> None:
        """
        Seeds deterministic threat intelligence feeds, artifacts, indicators, actors, and campaigns.
        """
        now = datetime.now(timezone.utc)

        # 1. Sources
        src_internal = db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.source_name == "SentinelTrace Internal CTI").first()
        if not src_internal:
            src_internal = ThreatIntelligenceSource(
                source_name="SentinelTrace Internal CTI",
                source_type="INTERNAL",
                description="Internal incident telemetry and verified threat research.",
                provider="SentinelTrace SOC Labs",
                trust_level="TRUSTED",
                is_active=True,
                last_ingested_at=now,
            )
            db.add(src_internal)
            db.flush()

        src_cisa = db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.source_name == "CISA Automated Indicator Sharing (AIS)").first()
        if not src_cisa:
            src_cisa = ThreatIntelligenceSource(
                source_name="CISA Automated Indicator Sharing (AIS)",
                source_type="GOVERNMENT",
                description="US Government validated cyber threat indicator feed.",
                provider="CISA / DHS",
                trust_level="TRUSTED",
                is_active=True,
                last_ingested_at=now,
            )
            db.add(src_cisa)
            db.flush()

        src_otx = db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.source_name == "Open Threat Exchange Community").first()
        if not src_otx:
            src_otx = ThreatIntelligenceSource(
                source_name="Open Threat Exchange Community",
                source_type="OPEN_SOURCE",
                description="Community aggregated threat intelligence observables.",
                provider="AlienVault OTX",
                trust_level="CONDITIONALLY_TRUSTED",
                is_active=True,
                last_ingested_at=now,
            )
            db.add(src_otx)
            db.flush()

        src_untrusted = db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.source_name == "Unverified Darknet Feed").first()
        if not src_untrusted:
            src_untrusted = ThreatIntelligenceSource(
                source_name="Unverified Darknet Feed",
                source_type="SECURITY_RESEARCH",
                description="Raw scraped darknet pastebin telemetry without cross-validation.",
                provider="Anonymous Scraper",
                trust_level="UNVERIFIED",
                is_active=True,
                last_ingested_at=now,
            )
            db.add(src_untrusted)
            db.flush()

        # 2. Actors
        actor1 = ThreatActorCampaignService.create_actor(
            db=db,
            actor_name="APT-SENTINEL-DEMO",
            aliases=["PHANTOM_TRACE", "DEV-0921", "COBALT_VIPER"],
            description="Nation-state sponsored advanced persistent threat targeting financial and telemetry infrastructure.",
            motivation="ESPIONAGE",
            sophistication="ADVANCED",
            origin_context="NORTHEAST_ASIA",
            confidence_score=92.0,
        )

        actor2 = ThreatActorCampaignService.create_actor(
            db=db,
            actor_name="FIN-RANSOM-SYNDICATE",
            aliases=["CRYPTO_SHADOW", "DARK_HEIST"],
            description="Organized cybercrime group deploying double-extortion ransomware and lateral credential access.",
            motivation="FINANCIAL",
            sophistication="INTERMEDIATE",
            origin_context="TRANSNATIONAL",
            confidence_score=88.0,
        )

        # 3. Campaigns
        cmp1 = ThreatActorCampaignService.create_campaign(
            db=db,
            campaign_reference="CMP-2026-CRED-PHISH",
            campaign_name="Operation SentinelPhish: MFA Bypass & Credential Harvesting",
            description="Targeted spear-phishing campaign deploying adversary-in-the-middle reverse proxy infrastructure.",
            actor_id=actor1.id,
            severity="CRITICAL",
            confidence_score=90.0,
        )

        cmp2 = ThreatActorCampaignService.create_campaign(
            db=db,
            campaign_reference="CMP-2026-LATERAL-STRIKE",
            campaign_name="Operation LateralStrike: Ransomware Propagation & Privilege Escalation",
            description="Lateral movement and process injection campaign targeting corporate domain controllers.",
            actor_id=actor2.id,
            severity="HIGH",
            confidence_score=85.0,
        )

        ThreatActorCampaignService.map_actor_to_campaign(db, actor1.id, cmp1.id, "ATTRIBUTED", 92.0)
        ThreatActorCampaignService.map_actor_to_campaign(db, actor2.id, cmp2.id, "ATTRIBUTED", 88.0)

        # 4. Artifact 1: Phishing Infrastructure Report
        art1 = db.query(ThreatIntelligenceArtifact).filter(ThreatIntelligenceArtifact.artifact_reference == "TIA-2026-001").first()
        if not art1:
            art1 = ThreatIntelligenceArtifact(
                artifact_reference="TIA-2026-001",
                source_id=src_cisa.id,
                artifact_type="IOC",
                raw_content_reference="cisa_advisory_aa26_091a.json",
                normalized_content={
                    "campaign": "Operation SentinelPhish",
                    "tactic": "TA0001",
                    "technique": "T1566.002",
                    "targeted_sectors": ["FINANCE", "DEFENSE", "TECH"],
                },
                content_hash="",
                integrity_status="VALID",
                confidence_score=95.0,
                trust_status="HIGH_TRUST",
                first_seen=now - timedelta(days=5),
                last_seen=now,
                expires_at=now + timedelta(days=90),
            )
            art1.content_hash = art1.compute_content_hash()
            db.add(art1)
            db.flush()

            # Indicators for Art 1
            ThreatIndicatorService.register_indicator(
                db=db,
                indicator_value="198.51.100.42",
                indicator_type="IP_ADDRESS",
                artifact_id=art1.id,
                confidence_score=95.0,
                severity="CRITICAL",
                expires_at=now + timedelta(days=90),
            )
            ThreatIndicatorService.register_indicator(
                db=db,
                indicator_value="auth-sentinel-verify.evilcorp.com",
                indicator_type="DOMAIN",
                artifact_id=art1.id,
                confidence_score=95.0,
                severity="CRITICAL",
                expires_at=now + timedelta(days=90),
            )
            ThreatIndicatorService.register_indicator(
                db=db,
                indicator_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                indicator_type="FILE_HASH",
                artifact_id=art1.id,
                confidence_score=90.0,
                severity="HIGH",
                expires_at=now + timedelta(days=90),
            )

            # Evaluate trust
            ThreatIntelligenceTrustService.evaluate_artifact_trust(db, art1.id)

        # 5. Artifact 2: Open Source Untrusted Artifact (for demonstration of trust degradation)
        art2 = db.query(ThreatIntelligenceArtifact).filter(ThreatIntelligenceArtifact.artifact_reference == "TIA-2026-UNTRUSTED").first()
        if not art2:
            art2 = ThreatIntelligenceArtifact(
                artifact_reference="TIA-2026-UNTRUSTED",
                source_id=src_untrusted.id,
                artifact_type="IOC",
                raw_content_reference="pastebin_dump_9912.txt",
                normalized_content={"dump_source": "pastebin"},
                content_hash="",
                integrity_status="VALID",
                confidence_score=50.0,
                trust_status="CONDITIONAL",
                first_seen=now - timedelta(days=120),  # Stale
                last_seen=now - timedelta(days=120),
                expires_at=now + timedelta(days=10),
            )
            art2.content_hash = art2.compute_content_hash()
            db.add(art2)
            db.flush()

            ThreatIndicatorService.register_indicator(
                db=db,
                indicator_value="203.0.113.88",
                indicator_type="IP_ADDRESS",
                artifact_id=art2.id,
                confidence_score=40.0,
                severity="MEDIUM",
                expires_at=now + timedelta(days=10),
            )

            ThreatIntelligenceTrustService.evaluate_artifact_trust(
                db=db,
                artifact_id=art2.id,
                conflicting_intelligence=True,
                missing_cross_validation=True,
            )

        # 6. Insights
        insight1 = db.query(ThreatIntelligenceInsight).filter(ThreatIntelligenceInsight.title.contains("Active Adversary Phishing Campaign")).first()
        if not insight1:
            insight1 = ThreatIntelligenceInsight(
                insight_type="CAMPAIGN_ACTIVITY",
                severity="CRITICAL",
                title="Active Adversary Phishing Campaign: Operation SentinelPhish",
                description="High-confidence adversary campaign targeting single sign-on portals. 2 critical IOCs actively tracked with verified CISA provenance.",
                confidence_score=92.0,
                related_campaign_id=cmp1.id,
                related_actor_id=actor1.id,
            )
            db.add(insight1)

        db.flush()
