"""
services/threat_intelligence_trust_service.py
---------------------------------------------
Deterministic Threat Intelligence Trust Evaluation & Deduction Engine.

Sprint 11B — Threat Intelligence Integration, Adversary Context & Security Intelligence Correlation.
Core Invariant: "THREAT INTELLIGENCE MUST BE PROVEN, CONTEXTUALIZED, TRACEABLE, AND NEVER BLINDLY TRUSTED."
Axiom: CRYPTOGRAPHIC INTEGRITY FAILURE ALWAYS DOMINATES NUMERICAL SCORES.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.threat_intelligence import (
    ThreatIntelligenceSource,
    ThreatIntelligenceArtifact,
    ThreatIntelligenceTrustEvaluation,
    TRUST_EVALUATION_DOMAIN_PREFIX,
    compute_canonical_hash,
)
from app.services.governance_ledger_service import GovernanceLedgerService


def to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class ThreatIntelligenceTrustService:
    """
    Evaluates threat intelligence artifacts deterministically starting at Base 100.0.
    """

    @staticmethod
    def evaluate_artifact_trust(
        db: Session,
        artifact_id: str,
        force_crypto_failure: bool = False,
        conflicting_intelligence: bool = False,
        missing_cross_validation: bool = False,
        actor_user_id: str = "SYSTEM",
    ) -> ThreatIntelligenceTrustEvaluation:
        artifact = db.query(ThreatIntelligenceArtifact).filter(ThreatIntelligenceArtifact.id == artifact_id).first()
        if not artifact:
            raise ValueError(f"Threat intelligence artifact '{artifact_id}' not found.")

        source = db.query(ThreatIntelligenceSource).filter(ThreatIntelligenceSource.id == artifact.source_id).first()

        # Deterministic Scoring starting at Base 100.0
        base_score = 100.0
        deductions: List[Dict[str, Any]] = []

        # 1. Source Trust Assessment
        source_score = 100.0
        if not source or source.trust_level == "UNVERIFIED":
            source_score -= 25.0
            deductions.append({"reason": "UNVERIFIED_SOURCE", "points": 25.0, "details": "Source has unverified trust level."})
        elif source.trust_level == "CONDITIONALLY_TRUSTED":
            source_score -= 10.0
            deductions.append({"reason": "CONDITIONALLY_TRUSTED_SOURCE", "points": 10.0, "details": "Source is conditionally trusted."})
        elif source.trust_level == "UNTRUSTED":
            source_score -= 50.0
            deductions.append({"reason": "UNTRUSTED_SOURCE", "points": 50.0, "details": "Source is classified as untrusted."})

        # 2. Freshness Score
        freshness_score = 100.0
        now = datetime.now(timezone.utc)
        exp = to_utc(artifact.expires_at)
        lseen = to_utc(artifact.last_seen)
        if exp and exp < now:
            freshness_score = 0.0
            deductions.append({"reason": "EXPIRED_INDICATOR", "points": 30.0, "details": "Intelligence artifact or indicators have expired."})
        elif lseen:
            age_days = (now - lseen).total_seconds() / 86400.0
            if age_days > 90:
                freshness_score -= 20.0
                deductions.append({"reason": "STALE_INTELLIGENCE", "points": 20.0, "details": f"Intelligence is {int(age_days)} days old (>90 days SLA)."})
            elif age_days > 30:
                freshness_score -= 10.0
                deductions.append({"reason": "AGING_INTELLIGENCE", "points": 10.0, "details": f"Intelligence is {int(age_days)} days old."})

        # 3. Completeness Score
        completeness_score = 100.0
        if not artifact.normalized_content or len(artifact.normalized_content) == 0:
            completeness_score -= 15.0
            deductions.append({"reason": "INCOMPLETE_CONTEXT", "points": 15.0, "details": "Artifact lacks structured normalized context."})

        if not artifact.raw_content_reference:
            completeness_score -= 15.0
            deductions.append({"reason": "UNKNOWN_ORIGIN", "points": 15.0, "details": "Artifact raw content origin reference is missing."})

        # 4. Cross-Validation Score
        cross_validation_score = 100.0
        if missing_cross_validation:
            cross_validation_score -= 10.0
            deductions.append({"reason": "NO_CROSS_VALIDATION", "points": 10.0, "details": "Intelligence observable confirmed by only single isolated feed."})

        if conflicting_intelligence:
            cross_validation_score -= 15.0
            deductions.append({"reason": "CONFLICTING_INTELLIGENCE", "points": 15.0, "details": "Conflicting reporting observed across external feeds."})

        # 5. Integrity Score & Hard Failure Override
        integrity_score = 100.0
        if force_crypto_failure or artifact.integrity_status != "VALID":
            integrity_score = 0.0
            deductions.append({"reason": "CRYPTOGRAPHIC_INTEGRITY_FAILURE", "points": 100.0, "details": "Cryptographic content hash divergence or signature verification failure."})

        # Calculate final score
        total_deduction = sum(d["points"] for d in deductions)
        final_score = max(0.0, min(100.0, base_score - total_deduction))

        # CRYPTOGRAPHIC DOMINANCE OVERRIDE
        if integrity_score == 0.0 or force_crypto_failure:
            final_score = 0.0
            trust_status = "UNTRUSTED"
            artifact.integrity_status = "TAMPERED"
        else:
            if final_score >= 90.0:
                trust_status = "HIGH_TRUST"
            elif final_score >= 75.0:
                trust_status = "TRUSTED"
            elif final_score >= 50.0:
                trust_status = "CONDITIONAL"
            elif final_score >= 25.0:
                trust_status = "LOW_TRUST"
            else:
                trust_status = "UNTRUSTED"

        artifact.trust_status = trust_status
        artifact.confidence_score = final_score

        # Prepare evaluation record
        evaluation = ThreatIntelligenceTrustEvaluation(
            artifact_id=artifact.id,
            source_score=max(0.0, min(100.0, source_score)),
            freshness_score=max(0.0, min(100.0, freshness_score)),
            completeness_score=max(0.0, min(100.0, completeness_score)),
            cross_validation_score=max(0.0, min(100.0, cross_validation_score)),
            integrity_score=integrity_score,
            final_trust_score=final_score,
            trust_status=trust_status,
            deductions_json=deductions,
            evaluation_hash="",
        )
        evaluation.evaluation_hash = evaluation.compute_evaluation_hash()

        db.add(evaluation)
        db.flush()

        # Log to Governance Ledger
        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="THREAT_INTELLIGENCE_TRUST_EVALUATED",
                actor_user_id=actor_user_id,
                details={
                    "artifact_id": artifact.id,
                    "artifact_reference": artifact.artifact_reference,
                    "final_trust_score": final_score,
                    "trust_status": trust_status,
                    "evaluation_hash": evaluation.evaluation_hash,
                    "crypto_override": force_crypto_failure or integrity_score == 0.0,
                },
            )
        except Exception:
            pass

        return evaluation
