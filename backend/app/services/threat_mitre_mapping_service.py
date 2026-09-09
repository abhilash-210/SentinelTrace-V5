"""
services/threat_mitre_mapping_service.py
----------------------------------------
MITRE ATT&CK Mapping Service for Threat Intelligence Artifacts, Indicators, and Campaigns.

Sprint 11B — Threat Intelligence Integration, Adversary Context & Security Intelligence Correlation.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.threat_intelligence import (
    ThreatMitreMapping,
    ThreatIntelligenceArtifact,
    ThreatIndicator,
    ThreatCampaign,
)
from app.services.governance_ledger_service import GovernanceLedgerService


MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


class ThreatMitreMappingService:
    """
    Manages deterministic MITRE ATT&CK mappings across threat intelligence artifacts.
    """

    @staticmethod
    def create_mapping(
        db: Session,
        tactic_id: str,
        technique_id: str,
        subtechnique_id: Optional[str] = None,
        artifact_id: Optional[str] = None,
        indicator_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        mapping_confidence: float = 90.0,
        mapping_source: str = "MANUAL",
        actor_user_id: str = "SYSTEM",
    ) -> ThreatMitreMapping:
        tactic_clean = tactic_id.upper().strip()
        technique_clean = technique_id.upper().strip()
        subtech_clean = subtechnique_id.upper().strip() if subtechnique_id else None

        # Check existing
        q = db.query(ThreatMitreMapping).filter(
            ThreatMitreMapping.tactic_id == tactic_clean,
            ThreatMitreMapping.technique_id == technique_clean,
        )
        if artifact_id:
            q = q.filter(ThreatMitreMapping.artifact_id == artifact_id)
        if indicator_id:
            q = q.filter(ThreatMitreMapping.indicator_id == indicator_id)
        if campaign_id:
            q = q.filter(ThreatMitreMapping.campaign_id == campaign_id)

        existing = q.first()
        if existing:
            return existing

        mapping = ThreatMitreMapping(
            artifact_id=artifact_id,
            indicator_id=indicator_id,
            campaign_id=campaign_id,
            tactic_id=tactic_clean,
            technique_id=technique_clean,
            subtechnique_id=subtech_clean,
            mapping_confidence=max(0.0, min(100.0, mapping_confidence)),
            mapping_source=mapping_source,
        )
        db.add(mapping)
        db.flush()

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="THREAT_MITRE_MAPPING_CREATED",
                actor_user_id=actor_user_id,
                details={
                    "mapping_id": mapping.id,
                    "tactic_id": tactic_clean,
                    "technique_id": technique_clean,
                    "subtechnique_id": subtech_clean,
                    "confidence": mapping.mapping_confidence,
                },
            )
        except Exception:
            pass

        return mapping

    @staticmethod
    def get_mappings_for_campaign(db: Session, campaign_id: str) -> List[ThreatMitreMapping]:
        return db.query(ThreatMitreMapping).filter(ThreatMitreMapping.campaign_id == campaign_id).all()

    @staticmethod
    def get_mappings_for_indicator(db: Session, indicator_id: str) -> List[ThreatMitreMapping]:
        return db.query(ThreatMitreMapping).filter(ThreatMitreMapping.indicator_id == indicator_id).all()
