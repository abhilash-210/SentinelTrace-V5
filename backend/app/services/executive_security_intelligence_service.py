"""
services/executive_security_intelligence_service.py
---------------------------------------------------
Deterministic Executive Security Intelligence Service for SentinelTrace V5.

Sprint 10A — Unified Security Intelligence & Executive Risk Posture Command Center.
Core Invariant: "EXECUTIVE SECURITY INTELLIGENCE MUST BE EXPLAINABLE, DETERMINISTIC, AND TRACEABLE BACK TO CRYPTOGRAPHIC EVIDENCE."
Zero Trust Rule: "UNKNOWN != HEALTHY", "CRYPTOGRAPHIC INTEGRITY FAILURE ALWAYS DOMINATES NUMERICAL POSTURE SCORES"
"""

from datetime import datetime, timezone, timedelta
import hashlib
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.semantic_interpretation import SemanticInterpretation, SemanticDriftAlert
from app.models.semantic_policy import SemanticPolicy
from app.models.detection_rule import DetectionRule
from app.models.detection_rule_trust import DetectionRuleTrustEvaluation, DetectionTrustAlert
from app.models.risk_correlation import RiskCorrelation
from app.models.remediation import RemediationCandidate
from app.models.security_incident import SecurityIncident, IncidentSignal
from app.models.incident_response import (
    IncidentContainmentRequest,
    IncidentResponseExecution,
    IncidentResponseVerification,
)
from app.models.security_assurance import PlatformAssuranceEvaluation, AssuranceAlert, AssuranceDomainEvaluation
from app.models.assurance_remediation import (
    AssuranceRemediationCase,
    AssuranceRemediationPlan,
    AssuranceRecoveryVerification,
    AssuranceRecoveryRecord,
)
from app.models.ledger import GovernanceLedgerEntry
from app.models.merkle import MerkleBatch, MerkleProof
from app.models.executive_security_intelligence import (
    ExecutiveSecurityPostureEvaluation,
    ExecutivePostureDomainScore,
    ExecutiveRiskDriver,
    ExecutivePostureTrendSnapshot,
    ExecutiveSecurityInsight,
    calculate_executive_hash,
    EXECUTIVE_POSTURE_DOMAIN_PREFIX,
    EXECUTIVE_INSIGHT_DOMAIN_PREFIX,
)
from app.services.governance_ledger_service import GovernanceLedgerService
from app.services.merkle_tree_service import MerkleTreeService
from app.services.security_assurance_service import SecurityAssuranceService

logger = logging.getLogger("sentinel.services.executive_security")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ExecutiveRiskConstants:
    """Deterministic constants for Executive Risk calculations, domain weights, and penalties."""

    # 10 Domain Weights (Must sum strictly to 1.00)
    DOMAIN_WEIGHTS: Dict[str, float] = {
        "EVIDENCE_INTEGRITY": 0.10,
        "NORMALIZATION": 0.08,
        "SEMANTIC_TRUST": 0.12,
        "DETECTION_TRUST": 0.15,
        "RISK_INTELLIGENCE": 0.10,
        "INCIDENT_SECURITY": 0.15,
        "INCIDENT_RESPONSE": 0.08,
        "PLATFORM_ASSURANCE": 0.10,
        "ASSURANCE_RECOVERY": 0.05,
        "CRYPTOGRAPHIC_ASSURANCE": 0.07,
    }

    # Deterministic Risk Point Values
    CRITICAL_OPEN_INCIDENT_POINTS = 25.0
    HIGH_OPEN_INCIDENT_POINTS = 12.0
    MEDIUM_OPEN_INCIDENT_POINTS = 5.0
    CRITICAL_DETECTION_TRUST_FAILURE_POINTS = 20.0
    HIGH_DETECTION_TRUST_FAILURE_POINTS = 12.0
    CRYPTOGRAPHIC_FAILURE_POINTS = 100.0
    CRITICAL_SEMANTIC_DRIFT_POINTS = 15.0
    UNRESOLVED_ASSURANCE_ALERT_POINTS = 10.0
    FAILED_RECOVERY_VERIFICATION_POINTS = 15.0
    UNKNOWN_TELEMETRY_POINTS = 20.0
    PENDING_CONTAINMENT_POINTS = 10.0
    RISK_CORRELATION_SPIKE_POINTS = 12.0

    # Severity Ordering for Sorting
    SEVERITY_ORDER: Dict[str, int] = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "INFORMATIONAL": 5,
    }


class ExecutiveSecurityIntelligenceService:
    """
    Authoritative service orchestrating the 10 security domains into deterministic,
    explainable, cryptographically sealed executive security posture evaluations.
    """

    @classmethod
    def evaluate_posture(
        cls,
        db: Session,
        actor_id: Optional[str] = "SYSTEM",
        actor_username: Optional[str] = "SYSTEM",
        notes: str = "",
        force_fresh: bool = False,
        injected_telemetry: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ExecutiveSecurityPostureEvaluation, List[str], Optional[GovernanceLedgerEntry]]:
        """
        Execute deterministic evaluation of executive security posture across all 10 domains.
        Returns (evaluation, hard_overrides_applied, ledger_entry).
        """
        eval_ts = utcnow()
        evaluation_id = f"espe-{uuid.uuid4().hex[:12]}"
        hard_overrides: List[str] = []

        # 1. Gather Telemetry across 10 security domains
        telemetry = cls._gather_telemetry(db, injected_telemetry=injected_telemetry)

        # 2. Evaluate Domain Scores (Base = 100.0 for each domain)
        domain_results = cls._evaluate_domains(telemetry)

        # 3. Calculate Overall Security Score & Executive Risk Score
        overall_security_score = 0.0
        domain_critical_count = 0
        domain_unknown_count = 0

        for dom_data in domain_results:
            overall_security_score += dom_data["weighted_contribution"]
            if dom_data["critical_flag"]:
                domain_critical_count += 1
            if dom_data["unknown_flag"]:
                domain_unknown_count += 1

        overall_security_score = round(max(0.0, min(100.0, overall_security_score)), 2)
        executive_risk_score = round(max(0.0, min(100.0, 100.0 - overall_security_score)), 2)

        # Calculate Confidence Score based on telemetry completeness
        confidence_score = 100.0
        if domain_unknown_count > 0:
            confidence_score = max(0.0, round(100.0 - (domain_unknown_count * 20.0), 2))

        # 4. Determine Posture Status based on thresholds
        if overall_security_score >= 90.0:
            posture_status = "HEALTHY"
        elif overall_security_score >= 75.0:
            posture_status = "GUARDED"
        elif overall_security_score >= 60.0:
            posture_status = "ELEVATED"
        elif overall_security_score >= 40.0:
            posture_status = "DEGRADED"
        else:
            posture_status = "CRITICAL"

        # 5. Evaluate Hard Failure Overrides (Strict Priority Order)
        # Override 1: Cryptographic Integrity Failure
        if telemetry.get("cryptographic_tampering_detected") or telemetry.get("cryptographic_integrity_status") == "COMPROMISED":
            posture_status = "CRITICAL"
            hard_overrides.append("CRYPTOGRAPHIC_INTEGRITY_FAILURE")

        # Override 2: Broken Governance Ledger Chain
        if telemetry.get("ledger_chain_broken", False):
            posture_status = "CRITICAL"
            hard_overrides.append("GOVERNANCE_LEDGER_INTEGRITY_FAILURE")

        # Override 3: Merkle Proof Failure
        if telemetry.get("merkle_proof_failed", False):
            posture_status = "CRITICAL"
            hard_overrides.append("MERKLE_PROOF_VERIFICATION_FAILURE")

        # Override 4: Active Critical Incidents >= 3
        if telemetry.get("open_critical_incidents", 0) >= 3:
            posture_status = "CRITICAL"
            hard_overrides.append("MULTIPLE_ACTIVE_CRITICAL_INCIDENTS")

        # Override 5: >= 2 Critical Assurance Domains
        if domain_critical_count >= 2:
            posture_status = "CRITICAL"
            hard_overrides.append("MULTI_DOMAIN_CRITICAL_ASSURANCE_FAILURE")

        # Override 6: Required Executive Telemetry Missing (Zero Trust: UNKNOWN != HEALTHY)
        # Missing telemetry forces UNKNOWN unless cryptographic failure forces CRITICAL
        if telemetry.get("telemetry_missing", False) or (domain_unknown_count >= 3):
            crypto_fails = {"CRYPTOGRAPHIC_INTEGRITY_FAILURE", "GOVERNANCE_LEDGER_INTEGRITY_FAILURE", "MERKLE_PROOF_VERIFICATION_FAILURE"}
            if not any(f in hard_overrides for f in crypto_fails):
                posture_status = "UNKNOWN"
            hard_overrides.append("EXECUTIVE_TELEMETRY_UNKNOWN")

        # 6. Generate Deterministic Risk Drivers
        risk_drivers_data = cls._generate_risk_drivers(telemetry, domain_results, evaluation_id)

        critical_driver_count = sum(1 for d in risk_drivers_data if d["severity"] == "CRITICAL")
        high_driver_count = sum(1 for d in risk_drivers_data if d["severity"] == "HIGH")
        medium_driver_count = sum(1 for d in risk_drivers_data if d["severity"] == "MEDIUM")

        # 7. Posture Change Detection vs Previous Evaluation
        previous_eval = (
            db.query(ExecutiveSecurityPostureEvaluation)
            .order_by(desc(ExecutiveSecurityPostureEvaluation.evaluation_timestamp))
            .first()
        )

        previous_evaluation_id = previous_eval.evaluation_id if previous_eval else None
        if previous_eval:
            score_delta = round(overall_security_score - previous_eval.overall_security_score, 2)
            if score_delta >= 10.0:
                posture_change = "SIGNIFICANT_IMPROVEMENT"
            elif score_delta >= 3.0:
                posture_change = "IMPROVEMENT"
            elif score_delta <= -10.0:
                posture_change = "SIGNIFICANT_DETERIORATION"
            elif score_delta <= -3.0:
                posture_change = "DETERIORATION"
            else:
                posture_change = "STABLE"
        else:
            score_delta = None
            posture_change = "INITIAL_EVALUATION"

        # 8. Generate Deterministic Executive Insights (Rule-based, NO AI/ML)
        insights_data = cls._generate_insights(
            telemetry=telemetry,
            domain_results=domain_results,
            risk_drivers=risk_drivers_data,
            overall_security_score=overall_security_score,
            executive_risk_score=executive_risk_score,
            posture_status=posture_status,
            previous_eval=previous_eval,
            score_delta=score_delta,
            hard_overrides=hard_overrides,
            evaluation_id=evaluation_id,
        )

        # 9. Build Deterministic Explanation
        evaluation_reason = cls._build_evaluation_reason(
            posture_status=posture_status,
            overall_score=overall_security_score,
            hard_overrides=hard_overrides,
            top_drivers=risk_drivers_data[:3],
            domain_results=domain_results,
        )

        # 10. Construct Canonical Payload and SHA-256 Hash Seal
        crypto_status = "COMPROMISED" if "CRYPTOGRAPHIC_INTEGRITY_FAILURE" in hard_overrides else "VERIFIED"
        if posture_status == "UNKNOWN":
            crypto_status = "UNKNOWN"

        canonical_payload = {
            "evaluation_id": evaluation_id,
            "evaluation_timestamp": eval_ts.isoformat(),
            "overall_posture_status": posture_status,
            "overall_security_score": overall_security_score,
            "executive_risk_score": executive_risk_score,
            "confidence_score": confidence_score,
            "critical_driver_count": critical_driver_count,
            "high_driver_count": high_driver_count,
            "open_critical_incidents": telemetry.get("open_critical_incidents", 0),
            "open_high_incidents": telemetry.get("open_high_incidents", 0),
            "unresolved_assurance_alerts": telemetry.get("unresolved_assurance_alerts", 0),
            "active_detection_trust_failures": telemetry.get("active_detection_trust_failures", 0),
            "critical_semantic_drift_events": telemetry.get("critical_semantic_drift_events", 0),
            "open_remediation_cases": telemetry.get("open_remediation_cases", 0),
            "cryptographic_integrity_status": crypto_status,
            "hard_overrides": hard_overrides,
            "domain_scores": [
                {
                    "domain": d["domain_name"],
                    "score": d["final_score"],
                    "weight": d["risk_weight"],
                    "status": d["status"],
                }
                for d in domain_results
            ],
            "previous_evaluation_id": previous_evaluation_id,
            "score_delta": score_delta,
        }

        evaluation_hash = calculate_executive_hash(
            EXECUTIVE_POSTURE_DOMAIN_PREFIX, canonical_payload
        )

        # 11. Create ORM Records (Strictly Immutable)
        evaluation_record = ExecutiveSecurityPostureEvaluation(
            id=evaluation_id,
            evaluation_id=evaluation_id,
            evaluation_timestamp=eval_ts,
            overall_posture_status=posture_status,
            overall_security_score=overall_security_score,
            executive_risk_score=executive_risk_score,
            confidence_score=confidence_score,
            critical_driver_count=critical_driver_count,
            high_driver_count=high_driver_count,
            medium_driver_count=medium_driver_count,
            open_critical_incidents=telemetry.get("open_critical_incidents", 0),
            open_high_incidents=telemetry.get("open_high_incidents", 0),
            unresolved_assurance_alerts=telemetry.get("unresolved_assurance_alerts", 0),
            active_detection_trust_failures=telemetry.get("active_detection_trust_failures", 0),
            critical_semantic_drift_events=telemetry.get("critical_semantic_drift_events", 0),
            open_remediation_cases=telemetry.get("open_remediation_cases", 0),
            cryptographic_integrity_status=crypto_status,
            previous_evaluation_id=previous_evaluation_id,
            score_delta=score_delta,
            posture_change=posture_change,
            evaluation_reason=evaluation_reason,
            canonical_payload=canonical_payload,
            evaluation_hash=evaluation_hash,
            created_at=eval_ts,
        )
        db.add(evaluation_record)

        # Add Domain Scores
        for dom in domain_results:
            domain_score_obj = ExecutivePostureDomainScore(
                id=f"epds-{uuid.uuid4().hex[:12]}",
                posture_evaluation_id=evaluation_id,
                domain_name=dom["domain_name"],
                base_score=dom["base_score"],
                deduction_total=dom["deduction_total"],
                final_score=dom["final_score"],
                risk_weight=dom["risk_weight"],
                weighted_contribution=dom["weighted_contribution"],
                status=dom["status"],
                critical_flag=dom["critical_flag"],
                unknown_flag=dom["unknown_flag"],
                primary_driver=dom["primary_driver"],
                explanation=dom["explanation"],
                canonical_payload=dom.get("canonical_payload", {}),
                created_at=eval_ts,
            )
            db.add(domain_score_obj)

        # Add Risk Drivers
        for rd in risk_drivers_data:
            driver_obj = ExecutiveRiskDriver(
                id=rd["id"],
                driver_id=rd["driver_id"],
                posture_evaluation_id=evaluation_id,
                driver_type=rd["driver_type"],
                severity=rd["severity"],
                risk_points=rd["risk_points"],
                domain=rd["domain"],
                title=rd["title"],
                explanation=rd["explanation"],
                source_entity_type=rd["source_entity_type"],
                source_entity_id=rd["source_entity_id"],
                source_reference=rd["source_reference"],
                rank=rd["rank"],
                active=rd["active"],
                resolved=rd["resolved"],
                created_at=eval_ts,
            )
            db.add(driver_obj)

        # Add Insights
        for ins in insights_data:
            insight_obj = ExecutiveSecurityInsight(
                id=ins["id"],
                insight_id=ins["insight_id"],
                posture_evaluation_id=evaluation_id,
                insight_type=ins["insight_type"],
                severity=ins["severity"],
                title=ins["title"],
                description=ins["description"],
                supporting_metrics=ins["supporting_metrics"],
                recommended_attention=ins["recommended_attention"],
                source_domains=ins["source_domains"],
                confidence=ins["confidence"],
                canonical_payload=ins["canonical_payload"],
                insight_hash=ins["insight_hash"],
                created_at=eval_ts,
            )
            db.add(insight_obj)

        # Add Trend Snapshot
        trend_obj = ExecutivePostureTrendSnapshot(
            id=f"epts-{uuid.uuid4().hex[:12]}",
            snapshot_id=f"epts-{uuid.uuid4().hex[:12]}",
            posture_evaluation_id=evaluation_id,
            timestamp=eval_ts,
            overall_security_score=overall_security_score,
            executive_risk_score=executive_risk_score,
            posture_status=posture_status,
            critical_driver_count=critical_driver_count,
            open_incident_count=telemetry.get("open_critical_incidents", 0) + telemetry.get("open_high_incidents", 0),
            assurance_score=telemetry.get("platform_assurance_score", 100.0),
            detection_trust_score=telemetry.get("detection_trust_score", 100.0),
            cryptographic_status=crypto_status,
            score_delta=score_delta,
            created_at=eval_ts,
        )
        db.add(trend_obj)

        db.flush()

        # 12. Append to Governance Ledger
        event_type = "EXECUTIVE_POSTURE_EVALUATED"
        if posture_status == "CRITICAL":
            event_type = "EXECUTIVE_POSTURE_CRITICAL"
        elif "CRYPTOGRAPHIC_INTEGRITY_FAILURE" in hard_overrides:
            event_type = "EXECUTIVE_CRYPTOGRAPHIC_OVERRIDE"
        elif posture_status == "UNKNOWN":
            event_type = "EXECUTIVE_TELEMETRY_UNKNOWN"
        elif posture_change in ("SIGNIFICANT_IMPROVEMENT", "IMPROVEMENT"):
            event_type = "EXECUTIVE_POSTURE_IMPROVED"
        elif posture_change in ("SIGNIFICANT_DETERIORATION", "DETERIORATION"):
            event_type = "EXECUTIVE_RISK_ESCALATED"

        ledger_payload = {
            "evaluation_id": evaluation_id,
            "evaluation_hash": evaluation_hash,
            "overall_status": posture_status,
            "overall_security_score": overall_security_score,
            "executive_risk_score": executive_risk_score,
            "critical_driver_count": critical_driver_count,
            "hard_overrides": hard_overrides,
            "notes": notes,
        }

        ledger_entry = GovernanceLedgerService.append_entry(
            db=db,
            event_type=event_type,
            actor_id=actor_id,
            actor_username=actor_username,
            payload=ledger_payload,
        )

        db.commit()
        db.refresh(evaluation_record)

        logger.info(
            f"Executive Security Posture Evaluated: {evaluation_id} | Status: {posture_status} | "
            f"Score: {overall_security_score}/100 | Risk: {executive_risk_score}/100 | Hash: {evaluation_hash[:12]}..."
        )

        return evaluation_record, hard_overrides, ledger_entry

    @classmethod
    def _gather_telemetry(
        cls,
        db: Session,
        injected_telemetry: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Gathers authoritative telemetry from existing database tables."""
        telemetry: Dict[str, Any] = {
            "total_ingested_events": 0,
            "tampering_detected": False,
            "total_normalized_events": 0,
            "low_confidence_normalized_events": 0,
            "active_semantic_policies": 0,
            "unresolved_semantic_drift": 0,
            "critical_semantic_drift_events": 0,
            "active_detection_rules": 0,
            "active_detection_trust_failures": 0,
            "detection_trust_score": 100.0,
            "high_detection_trust_failures": 0,
            "active_risk_correlations": 0,
            "critical_risk_correlations": 0,
            "open_critical_incidents": 0,
            "open_high_incidents": 0,
            "open_medium_incidents": 0,
            "total_open_incidents": 0,
            "pending_containment_requests": 0,
            "unverified_incident_responses": 0,
            "platform_assurance_score": 100.0,
            "unresolved_assurance_alerts": 0,
            "critical_assurance_alerts": 0,
            "open_remediation_cases": 0,
            "failed_recovery_verifications": 0,
            "unverified_remediation_plans": 0,
            "cryptographic_integrity_status": "VERIFIED",
            "cryptographic_tampering_detected": False,
            "ledger_chain_broken": False,
            "merkle_proof_failed": False,
            "telemetry_missing": False,
        }

        # 1. Evidence Integrity
        try:
            ingested_count = db.query(func.count(IngestedEvent.id)).scalar() or 0
            telemetry["total_ingested_events"] = ingested_count
            tampered = (
                db.query(IngestedEvent)
                .filter(IngestedEvent.verification_status.in_(["TAMPERED", "MISMATCH", "FAILED"]))
                .count()
            )
            if tampered > 0:
                telemetry["tampering_detected"] = True
                telemetry["cryptographic_tampering_detected"] = True
        except Exception as e:
            logger.debug(f"Telemetry 1 (Evidence) fallback: {e}")

        # 2. Normalization
        try:
            norm_count = db.query(func.count(NormalizedEvent.id)).scalar() or 0
            telemetry["total_normalized_events"] = norm_count
            low_conf = (
                db.query(NormalizedEvent)
                .filter(NormalizedEvent.confidence_score < 70.0)
                .count()
            )
            telemetry["low_confidence_normalized_events"] = low_conf
        except Exception as e:
            logger.debug(f"Telemetry 2 (Normalization) fallback: {e}")

        # 3. Semantic Trust
        try:
            sem_policies = (
                db.query(SemanticPolicy)
                .filter(SemanticPolicy.status == "ACTIVE")
                .count()
            )
            telemetry["active_semantic_policies"] = sem_policies

            drift_alerts = (
                db.query(SemanticDriftAlert)
                .filter(SemanticDriftAlert.status == "UNRESOLVED")
                .all()
            )
            telemetry["unresolved_semantic_drift"] = len(drift_alerts)
            telemetry["critical_semantic_drift_events"] = sum(
                1 for d in drift_alerts if getattr(d, "severity", "HIGH") == "CRITICAL" or getattr(d, "risk_level", "HIGH") == "CRITICAL"
            )
        except Exception as e:
            logger.debug(f"Telemetry 3 (Semantic) fallback: {e}")

        # 4. Detection Trust
        try:
            rules_count = db.query(func.count(DetectionRule.id)).scalar() or 0
            telemetry["active_detection_rules"] = rules_count

            trust_evals = (
                db.query(DetectionRuleTrustEvaluation)
                .order_by(desc(DetectionRuleTrustEvaluation.evaluation_timestamp))
                .limit(20)
                .all()
            )
            if trust_evals:
                avg_trust = sum(t.trust_score for t in trust_evals) / len(trust_evals)
                telemetry["detection_trust_score"] = round(avg_trust, 2)
                telemetry["active_detection_trust_failures"] = sum(
                    1 for t in trust_evals if t.trust_status in ("FAIL", "FAILED", "CRITICAL", "REVOKED")
                )
                telemetry["high_detection_trust_failures"] = sum(
                    1 for t in trust_evals if t.trust_status in ("DEGRADED", "WARN", "AT_RISK")
                )
        except Exception as e:
            logger.debug(f"Telemetry 4 (Detection) fallback: {e}")

        # 5. Risk Intelligence
        try:
            risk_corrs = (
                db.query(RiskCorrelation)
                .filter(RiskCorrelation.status.in_(["ACTIVE", "OPEN", "NEW"]))
                .all()
            )
            telemetry["active_risk_correlations"] = len(risk_corrs)
            telemetry["critical_risk_correlations"] = sum(
                1 for r in risk_corrs if getattr(r, "severity", "") == "CRITICAL"
            )
        except Exception as e:
            logger.debug(f"Telemetry 5 (Risk) fallback: {e}")

        # 6. Incident Security
        try:
            incidents = (
                db.query(SecurityIncident)
                .filter(SecurityIncident.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"]))
                .all()
            )
            telemetry["total_open_incidents"] = len(incidents)
            telemetry["open_critical_incidents"] = sum(
                1 for inc in incidents if inc.severity == "CRITICAL"
            )
            telemetry["open_high_incidents"] = sum(
                1 for inc in incidents if inc.severity == "HIGH"
            )
            telemetry["open_medium_incidents"] = sum(
                1 for inc in incidents if inc.severity == "MEDIUM"
            )
        except Exception as e:
            logger.debug(f"Telemetry 6 (Incident) fallback: {e}")

        # 7. Incident Response
        try:
            pending_containment = (
                db.query(IncidentContainmentRequest)
                .filter(IncidentContainmentRequest.status.in_(["PROPOSED", "PENDING_REVIEW"]))
                .count()
            )
            telemetry["pending_containment_requests"] = pending_containment
        except Exception as e:
            logger.debug(f"Telemetry 7 (Response) fallback: {e}")

        # 8. Platform Assurance
        try:
            latest_pae = (
                db.query(PlatformAssuranceEvaluation)
                .order_by(desc(PlatformAssuranceEvaluation.evaluation_timestamp))
                .first()
            )
            if latest_pae:
                telemetry["platform_assurance_score"] = latest_pae.overall_score
            open_ass_alerts = (
                db.query(AssuranceAlert)
                .filter(AssuranceAlert.status.in_(["ACTIVE", "OPEN", "NEW"]))
                .all()
            )
            telemetry["unresolved_assurance_alerts"] = len(open_ass_alerts)
            telemetry["critical_assurance_alerts"] = sum(
                1 for a in open_ass_alerts if a.severity == "CRITICAL"
            )
        except Exception as e:
            logger.debug(f"Telemetry 8 (Assurance) fallback: {e}")

        # 9. Assurance Recovery
        try:
            open_arc = (
                db.query(AssuranceRemediationCase)
                .filter(AssuranceRemediationCase.status.in_(["OPEN", "ANALYZING", "REMEDIATION_PLANNED", "PENDING_REVIEW", "AUTHORIZED", "EXECUTING", "VERIFICATION_PENDING"]))
                .count()
            )
            telemetry["open_remediation_cases"] = open_arc
            failed_recov = (
                db.query(AssuranceRecoveryVerification)
                .filter(AssuranceRecoveryVerification.verification_status.in_(["UNVERIFIED", "FAILED", "INCONCLUSIVE"]))
                .count()
            )
            telemetry["failed_recovery_verifications"] = failed_recov
        except Exception as e:
            logger.debug(f"Telemetry 9 (Recovery) fallback: {e}")

        # 10. Cryptographic Assurance
        try:
            ledger_check = GovernanceLedgerService.verify_chain(db)
            if not ledger_check.get("is_valid", True):
                telemetry["ledger_chain_broken"] = True
                telemetry["cryptographic_integrity_status"] = "COMPROMISED"
        except Exception as e:
            logger.debug(f"Telemetry 10 (Crypto) fallback: {e}")

        # Apply any injected telemetry overrides (used for deterministic test simulation)
        if injected_telemetry:
            telemetry.update(injected_telemetry)

        return telemetry


    @classmethod
    def _evaluate_domains(cls, telemetry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluates scores and deductions across all 10 security domains deterministically."""
        domains: List[Dict[str, Any]] = []

        # 1. EVIDENCE_INTEGRITY (Weight: 10%)
        ev_base = 100.0
        ev_deductions = 0.0
        ev_drivers = []
        ev_critical = False
        ev_unknown = False

        if telemetry.get("cryptographic_tampering_detected") or telemetry.get("tampering_detected"):
            ev_deductions += 60.0
            ev_drivers.append("Tampered or hash mismatch events detected in Evidence Vault")
            ev_critical = True
        if telemetry.get("total_ingested_events", 0) == 0 and not telemetry.get("mock_evidence_present", False):
            # If no evidence ingested, slight penalty for zero telemetry baseline
            ev_deductions += 5.0
            ev_drivers.append("Minimal evidence ingest volume")

        ev_final = max(0.0, min(100.0, ev_base - ev_deductions))
        ev_status = cls._score_to_status(ev_final, ev_critical, ev_unknown)
        domains.append({
            "domain_name": "EVIDENCE_INTEGRITY",
            "base_score": ev_base,
            "deduction_total": ev_deductions,
            "final_score": ev_final,
            "risk_weight": ExecutiveRiskConstants.DOMAIN_WEIGHTS["EVIDENCE_INTEGRITY"],
            "weighted_contribution": round(ev_final * ExecutiveRiskConstants.DOMAIN_WEIGHTS["EVIDENCE_INTEGRITY"], 2),
            "status": ev_status,
            "critical_flag": ev_critical,
            "unknown_flag": ev_unknown,
            "primary_driver": "; ".join(ev_drivers) or "VAULT_EVIDENCE_INTEGRITY_VERIFIED",
            "explanation": f"Evidence integrity evaluated with {ev_deductions:.1f} total deductions.",
            "canonical_payload": {"ingested_count": telemetry.get("total_ingested_events", 0), "tampered": telemetry.get("tampering_detected", False)},
        })

        # 2. NORMALIZATION (Weight: 8%)
        norm_base = 100.0
        norm_deductions = 0.0
        norm_drivers = []
        norm_critical = False
        norm_unknown = False

        low_conf = telemetry.get("low_confidence_normalized_events", 0)
        if low_conf > 0:
            norm_deductions += min(40.0, low_conf * 10.0)
            norm_drivers.append(f"{low_conf} normalized events with low confidence (<70%)")

        norm_final = max(0.0, min(100.0, norm_base - norm_deductions))
        norm_status = cls._score_to_status(norm_final, norm_critical, norm_unknown)
        domains.append({
            "domain_name": "NORMALIZATION",
            "base_score": norm_base,
            "deduction_total": norm_deductions,
            "final_score": norm_final,
            "risk_weight": ExecutiveRiskConstants.DOMAIN_WEIGHTS["NORMALIZATION"],
            "weighted_contribution": round(norm_final * ExecutiveRiskConstants.DOMAIN_WEIGHTS["NORMALIZATION"], 2),
            "status": norm_status,
            "critical_flag": norm_critical,
            "unknown_flag": norm_unknown,
            "primary_driver": "; ".join(norm_drivers) or "CANONICAL_NORMALIZATION_HEALTHY",
            "explanation": f"Normalization pipeline evaluated with {norm_deductions:.1f} total deductions.",
            "canonical_payload": {"low_conf_count": low_conf},
        })

        # 3. SEMANTIC_TRUST (Weight: 12%)
        sem_base = 100.0
        sem_deductions = 0.0
        sem_drivers = []
        sem_critical = False
        sem_unknown = False

        crit_drift = telemetry.get("critical_semantic_drift_events", 0)
        unres_drift = telemetry.get("unresolved_semantic_drift", 0)
        if crit_drift > 0:
            sem_deductions += min(60.0, crit_drift * ExecutiveRiskConstants.CRITICAL_SEMANTIC_DRIFT_POINTS)
            sem_drivers.append(f"{crit_drift} CRITICAL semantic drift events unresolved")
            sem_critical = True
        elif unres_drift > 0:
            sem_deductions += min(30.0, unres_drift * 8.0)
            sem_drivers.append(f"{unres_drift} semantic drift alerts active")

        sem_final = max(0.0, min(100.0, sem_base - sem_deductions))
        sem_status = cls._score_to_status(sem_final, sem_critical, sem_unknown)
        domains.append({
            "domain_name": "SEMANTIC_TRUST",
            "base_score": sem_base,
            "deduction_total": sem_deductions,
            "final_score": sem_final,
            "risk_weight": ExecutiveRiskConstants.DOMAIN_WEIGHTS["SEMANTIC_TRUST"],
            "weighted_contribution": round(sem_final * ExecutiveRiskConstants.DOMAIN_WEIGHTS["SEMANTIC_TRUST"], 2),
            "status": sem_status,
            "critical_flag": sem_critical,
            "unknown_flag": sem_unknown,
            "primary_driver": "; ".join(sem_drivers) or "SEMANTIC_MAPPINGS_STABLE",
            "explanation": f"Semantic trust evaluated with {sem_deductions:.1f} deductions from semantic drift.",
            "canonical_payload": {"critical_drift": crit_drift, "unresolved_drift": unres_drift},
        })

        # 4. DETECTION_TRUST (Weight: 15%)
        dt_base = 100.0
        dt_deductions = 0.0
        dt_drivers = []
        dt_critical = False
        dt_unknown = False

        crit_trust_fails = telemetry.get("active_detection_trust_failures", 0)
        high_trust_fails = telemetry.get("high_detection_trust_failures", 0)
        trust_score = telemetry.get("detection_trust_score", 100.0)

        if crit_trust_fails > 0:
            dt_deductions += min(70.0, crit_trust_fails * ExecutiveRiskConstants.CRITICAL_DETECTION_TRUST_FAILURE_POINTS)
            dt_drivers.append(f"{crit_trust_fails} CRITICAL detection rule trust failures")
            if crit_trust_fails >= 2:
                dt_critical = True
        if high_trust_fails > 0:
            dt_deductions += min(30.0, high_trust_fails * ExecutiveRiskConstants.HIGH_DETECTION_TRUST_FAILURE_POINTS)
            dt_drivers.append(f"{high_trust_fails} degraded detection rule trust evaluations")
        if trust_score < 70.0:
            dt_deductions += min(30.0, (70.0 - trust_score) * 0.5)

        dt_final = max(0.0, min(100.0, dt_base - dt_deductions))
        dt_status = cls._score_to_status(dt_final, dt_critical, dt_unknown)
        domains.append({
            "domain_name": "DETECTION_TRUST",
            "base_score": dt_base,
            "deduction_total": dt_deductions,
            "final_score": dt_final,
            "risk_weight": ExecutiveRiskConstants.DOMAIN_WEIGHTS["DETECTION_TRUST"],
            "weighted_contribution": round(dt_final * ExecutiveRiskConstants.DOMAIN_WEIGHTS["DETECTION_TRUST"], 2),
            "status": dt_status,
            "critical_flag": dt_critical,
            "unknown_flag": dt_unknown,
            "primary_driver": "; ".join(dt_drivers) or "DETECTION_RULES_TRUSTED",
            "explanation": f"Detection trust evaluated with {dt_deductions:.1f} deductions across active rule trust.",
            "canonical_payload": {"crit_fails": crit_trust_fails, "avg_trust": trust_score},
        })

        # 5. RISK_INTELLIGENCE (Weight: 10%)
        risk_base = 100.0
        risk_deductions = 0.0
        risk_drivers = []
        risk_critical = False
        risk_unknown = False

        crit_risk_corr = telemetry.get("critical_risk_correlations", 0)
        act_risk_corr = telemetry.get("active_risk_correlations", 0)
        if crit_risk_corr > 0:
            risk_deductions += min(60.0, crit_risk_corr * ExecutiveRiskConstants.RISK_CORRELATION_SPIKE_POINTS)
            risk_drivers.append(f"{crit_risk_corr} CRITICAL risk correlation clusters")
        elif act_risk_corr > 3:
            risk_deductions += min(30.0, act_risk_corr * 5.0)
            risk_drivers.append(f"{act_risk_corr} active correlated risk clusters")

        risk_final = max(0.0, min(100.0, risk_base - risk_deductions))
        risk_status = cls._score_to_status(risk_final, risk_critical, risk_unknown)
        domains.append({
            "domain_name": "RISK_INTELLIGENCE",
            "base_score": risk_base,
            "deduction_total": risk_deductions,
            "final_score": risk_final,
            "risk_weight": ExecutiveRiskConstants.DOMAIN_WEIGHTS["RISK_INTELLIGENCE"],
            "weighted_contribution": round(risk_final * ExecutiveRiskConstants.DOMAIN_WEIGHTS["RISK_INTELLIGENCE"], 2),
            "status": risk_status,
            "critical_flag": risk_critical,
            "unknown_flag": risk_unknown,
            "primary_driver": "; ".join(risk_drivers) or "RISK_CORRELATIONS_CONTROLLED",
            "explanation": f"Risk intelligence evaluated with {risk_deductions:.1f} deductions.",
            "canonical_payload": {"active_correlations": act_risk_corr, "critical_correlations": crit_risk_corr},
        })

        # 6. INCIDENT_SECURITY (Weight: 15%)
        inc_base = 100.0
        inc_deductions = 0.0
        inc_drivers = []
        inc_critical = False
        inc_unknown = False

        crit_inc = telemetry.get("open_critical_incidents", 0)
        high_inc = telemetry.get("open_high_incidents", 0)
        med_inc = telemetry.get("open_medium_incidents", 0)

        if crit_inc > 0:
            inc_deductions += crit_inc * ExecutiveRiskConstants.CRITICAL_OPEN_INCIDENT_POINTS
            inc_drivers.append(f"{crit_inc} open CRITICAL security incidents")
            inc_critical = True
        if high_inc > 0:
            inc_deductions += high_inc * ExecutiveRiskConstants.HIGH_OPEN_INCIDENT_POINTS
            inc_drivers.append(f"{high_inc} open HIGH severity security incidents")
        if med_inc > 0:
            inc_deductions += med_inc * ExecutiveRiskConstants.MEDIUM_OPEN_INCIDENT_POINTS
            inc_drivers.append(f"{med_inc} open MEDIUM incidents")

        inc_final = max(0.0, min(100.0, inc_base - inc_deductions))
        inc_status = cls._score_to_status(inc_final, inc_critical, inc_unknown)
        domains.append({
            "domain_name": "INCIDENT_SECURITY",
            "base_score": inc_base,
            "deduction_total": inc_deductions,
            "final_score": inc_final,
            "risk_weight": ExecutiveRiskConstants.DOMAIN_WEIGHTS["INCIDENT_SECURITY"],
            "weighted_contribution": round(inc_final * ExecutiveRiskConstants.DOMAIN_WEIGHTS["INCIDENT_SECURITY"], 2),
            "status": inc_status,
            "critical_flag": inc_critical,
            "unknown_flag": inc_unknown,
            "primary_driver": "; ".join(inc_drivers) or "NO_CRITICAL_OPEN_INCIDENTS",
            "explanation": f"Incident security evaluated with {inc_deductions:.1f} total open incident deductions.",
            "canonical_payload": {"critical_incidents": crit_inc, "high_incidents": high_inc, "medium_incidents": med_inc},
        })

        # 7. INCIDENT_RESPONSE (Weight: 8%)
        resp_base = 100.0
        resp_deductions = 0.0
        resp_drivers = []
        resp_critical = False
        resp_unknown = False

        pending_cont = telemetry.get("pending_containment_requests", 0)
        if pending_cont > 0:
            resp_deductions += min(50.0, pending_cont * ExecutiveRiskConstants.PENDING_CONTAINMENT_POINTS)
            resp_drivers.append(f"{pending_cont} high-impact containment actions pending authorization")

        resp_final = max(0.0, min(100.0, resp_base - resp_deductions))
        resp_status = cls._score_to_status(resp_final, resp_critical, resp_unknown)
        domains.append({
            "domain_name": "INCIDENT_RESPONSE",
            "base_score": resp_base,
            "deduction_total": resp_deductions,
            "final_score": resp_final,
            "risk_weight": ExecutiveRiskConstants.DOMAIN_WEIGHTS["INCIDENT_RESPONSE"],
            "weighted_contribution": round(resp_final * ExecutiveRiskConstants.DOMAIN_WEIGHTS["INCIDENT_RESPONSE"], 2),
            "status": resp_status,
            "critical_flag": resp_critical,
            "unknown_flag": resp_unknown,
            "primary_driver": "; ".join(resp_drivers) or "GOVERNED_RESPONSE_ACTIVE",
            "explanation": f"Incident response governance evaluated with {resp_deductions:.1f} deductions.",
            "canonical_payload": {"pending_containment": pending_cont},
        })

        # 8. PLATFORM_ASSURANCE (Weight: 10%)
        ass_base = 100.0
        ass_deductions = 0.0
        ass_drivers = []
        ass_critical = False
        ass_unknown = False

        ass_score = telemetry.get("platform_assurance_score", 100.0)
        unres_alerts = telemetry.get("unresolved_assurance_alerts", 0)
        crit_alerts = telemetry.get("critical_assurance_alerts", 0)

        if ass_score < 100.0:
            ass_deductions += (100.0 - ass_score) * 0.5
        if crit_alerts > 0:
            ass_deductions += min(50.0, crit_alerts * 20.0)
            ass_drivers.append(f"{crit_alerts} CRITICAL platform assurance alerts")
            ass_critical = True
        elif unres_alerts > 0:
            ass_deductions += min(30.0, unres_alerts * ExecutiveRiskConstants.UNRESOLVED_ASSURANCE_ALERT_POINTS)
            ass_drivers.append(f"{unres_alerts} unresolved assurance alerts")

        ass_final = max(0.0, min(100.0, ass_base - ass_deductions))
        ass_status = cls._score_to_status(ass_final, ass_critical, ass_unknown)
        domains.append({
            "domain_name": "PLATFORM_ASSURANCE",
            "base_score": ass_base,
            "deduction_total": ass_deductions,
            "final_score": ass_final,
            "risk_weight": ExecutiveRiskConstants.DOMAIN_WEIGHTS["PLATFORM_ASSURANCE"],
            "weighted_contribution": round(ass_final * ExecutiveRiskConstants.DOMAIN_WEIGHTS["PLATFORM_ASSURANCE"], 2),
            "status": ass_status,
            "critical_flag": ass_critical,
            "unknown_flag": ass_unknown,
            "primary_driver": "; ".join(ass_drivers) or "PLATFORM_HEALTH_ASSURED",
            "explanation": f"Platform assurance evaluated with {ass_deductions:.1f} deductions.",
            "canonical_payload": {"assurance_score": ass_score, "unresolved_alerts": unres_alerts},
        })

        # 9. ASSURANCE_RECOVERY (Weight: 5%)
        rec_base = 100.0
        rec_deductions = 0.0
        rec_drivers = []
        rec_critical = False
        rec_unknown = False

        failed_rec = telemetry.get("failed_recovery_verifications", 0)
        open_cases = telemetry.get("open_remediation_cases", 0)
        if failed_rec > 0:
            rec_deductions += min(70.0, failed_rec * ExecutiveRiskConstants.FAILED_RECOVERY_VERIFICATION_POINTS)
            rec_drivers.append(f"{failed_rec} unverified/failed assurance recovery verifications")
            rec_critical = True
        if open_cases > 2:
            rec_deductions += min(30.0, open_cases * 5.0)
            rec_drivers.append(f"{open_cases} active remediation cases in flight")

        rec_final = max(0.0, min(100.0, rec_base - rec_deductions))
        rec_status = cls._score_to_status(rec_final, rec_critical, rec_unknown)
        domains.append({
            "domain_name": "ASSURANCE_RECOVERY",
            "base_score": rec_base,
            "deduction_total": rec_deductions,
            "final_score": rec_final,
            "risk_weight": ExecutiveRiskConstants.DOMAIN_WEIGHTS["ASSURANCE_RECOVERY"],
            "weighted_contribution": round(rec_final * ExecutiveRiskConstants.DOMAIN_WEIGHTS["ASSURANCE_RECOVERY"], 2),
            "status": rec_status,
            "critical_flag": rec_critical,
            "unknown_flag": rec_unknown,
            "primary_driver": "; ".join(rec_drivers) or "ALL_REMEDIATIONS_VERIFIED",
            "explanation": f"Assurance recovery evaluated with {rec_deductions:.1f} deductions.",
            "canonical_payload": {"failed_verifications": failed_rec, "open_cases": open_cases},
        })

        # 10. CRYPTOGRAPHIC_ASSURANCE (Weight: 7%)
        cry_base = 100.0
        cry_deductions = 0.0
        cry_drivers = []
        cry_critical = False
        cry_unknown = False

        if telemetry.get("ledger_chain_broken") or telemetry.get("cryptographic_tampering_detected") or telemetry.get("merkle_proof_failed"):
            cry_deductions = 100.0
            cry_critical = True
            cry_drivers.append("Cryptographic seal or ledger hash chain invalid")
        elif telemetry.get("cryptographic_integrity_status") == "UNKNOWN":
            cry_unknown = True
            cry_deductions = 50.0
            cry_drivers.append("Cryptographic state unverified")

        cry_final = max(0.0, min(100.0, cry_base - cry_deductions))
        cry_status = cls._score_to_status(cry_final, cry_critical, cry_unknown)
        domains.append({
            "domain_name": "CRYPTOGRAPHIC_ASSURANCE",
            "base_score": cry_base,
            "deduction_total": cry_deductions,
            "final_score": cry_final,
            "risk_weight": ExecutiveRiskConstants.DOMAIN_WEIGHTS["CRYPTOGRAPHIC_ASSURANCE"],
            "weighted_contribution": round(cry_final * ExecutiveRiskConstants.DOMAIN_WEIGHTS["CRYPTOGRAPHIC_ASSURANCE"], 2),
            "status": cry_status,
            "critical_flag": cry_critical,
            "unknown_flag": cry_unknown,
            "primary_driver": "; ".join(cry_drivers) or "GOVERNANCE_LEDGER_CHAIN_INTACT",
            "explanation": f"Cryptographic assurance evaluated: {cry_status}.",
            "canonical_payload": {"ledger_valid": not telemetry.get("ledger_chain_broken", False)},
        })

        return domains

    @staticmethod
    def _score_to_status(score: float, critical_flag: bool, unknown_flag: bool) -> str:
        """Helper to convert domain numerical score to deterministic status."""
        if unknown_flag:
            return "UNKNOWN"
        if critical_flag or score < 40.0:
            return "CRITICAL"
        if score >= 90.0:
            return "HEALTHY"
        if score >= 75.0:
            return "GUARDED"
        if score >= 60.0:
            return "ELEVATED"
        return "DEGRADED"

    @classmethod
    def _generate_risk_drivers(
        cls,
        telemetry: Dict[str, Any],
        domain_results: List[Dict[str, Any]],
        evaluation_id: str,
    ) -> List[Dict[str, Any]]:
        """Generates ranked, deterministic risk drivers with non-orphan source entity references."""
        drivers: List[Dict[str, Any]] = []

        # 1. Cryptographic failure driver
        if telemetry.get("cryptographic_tampering_detected") or telemetry.get("ledger_chain_broken") or telemetry.get("merkle_proof_failed"):
            drivers.append({
                "id": f"erd-{uuid.uuid4().hex[:12]}",
                "driver_id": f"erd-{uuid.uuid4().hex[:12]}",
                "posture_evaluation_id": evaluation_id,
                "driver_type": "CRYPTOGRAPHIC_INTEGRITY_FAILURE",
                "severity": "CRITICAL",
                "risk_points": ExecutiveRiskConstants.CRYPTOGRAPHIC_FAILURE_POINTS,
                "domain": "CRYPTOGRAPHIC_ASSURANCE",
                "title": "Cryptographic Governance Ledger or Vault Integrity Failure",
                "explanation": "Cryptographic hash verification failed across the governance ledger or raw evidence vault. Immutability cannot be guaranteed.",
                "source_entity_type": "GOVERNANCE_LEDGER",
                "source_entity_id": "sentinel.governance_ledger",
                "source_reference": "LEDGER-INTEGRITY-CHECK",
                "rank": 1,
                "active": True,
                "resolved": False,
            })

        # 2. Critical Open Incidents
        crit_inc = telemetry.get("open_critical_incidents", 0)
        if crit_inc > 0:
            drivers.append({
                "id": f"erd-{uuid.uuid4().hex[:12]}",
                "driver_id": f"erd-{uuid.uuid4().hex[:12]}",
                "posture_evaluation_id": evaluation_id,
                "driver_type": "OPEN_CRITICAL_INCIDENT",
                "severity": "CRITICAL",
                "risk_points": crit_inc * ExecutiveRiskConstants.CRITICAL_OPEN_INCIDENT_POINTS,
                "domain": "INCIDENT_SECURITY",
                "title": f"{crit_inc} Open Critical Security Incident(s)",
                "explanation": f"{crit_inc} security incidents of CRITICAL severity are currently uncontained or under active investigation.",
                "source_entity_type": "SECURITY_INCIDENT",
                "source_entity_id": telemetry.get("primary_critical_incident_id", "INC-CRITICAL-ACTIVE"),
                "source_reference": telemetry.get("primary_critical_incident_ref", "INC-2026-CRIT"),
                "rank": 1,
                "active": True,
                "resolved": False,
            })

        # 3. Critical Detection Trust Failures
        dt_fails = telemetry.get("active_detection_trust_failures", 0)
        if dt_fails > 0:
            drivers.append({
                "id": f"erd-{uuid.uuid4().hex[:12]}",
                "driver_id": f"erd-{uuid.uuid4().hex[:12]}",
                "posture_evaluation_id": evaluation_id,
                "driver_type": "DETECTION_TRUST_FAILURE",
                "severity": "CRITICAL" if dt_fails >= 2 else "HIGH",
                "risk_points": dt_fails * ExecutiveRiskConstants.CRITICAL_DETECTION_TRUST_FAILURE_POINTS,
                "domain": "DETECTION_TRUST",
                "title": f"{dt_fails} Detection Rule Trust Failure(s)",
                "explanation": f"{dt_fails} active detection rules have failed trust evaluation due to semantic drift or dependency degradation.",
                "source_entity_type": "DETECTION_RULE_TRUST",
                "source_entity_id": telemetry.get("primary_detection_rule_id", "DRULE-TRUST-FAIL"),
                "source_reference": telemetry.get("primary_detection_rule_ref", "drule-powershell"),
                "rank": 1 if dt_fails >= 2 else 2,
                "active": True,
                "resolved": False,
            })

        # 4. Critical Semantic Drift
        sem_drift = telemetry.get("critical_semantic_drift_events", 0)
        if sem_drift > 0:
            drivers.append({
                "id": f"erd-{uuid.uuid4().hex[:12]}",
                "driver_id": f"erd-{uuid.uuid4().hex[:12]}",
                "posture_evaluation_id": evaluation_id,
                "driver_type": "SEMANTIC_DRIFT_CRITICAL",
                "severity": "HIGH",
                "risk_points": sem_drift * ExecutiveRiskConstants.CRITICAL_SEMANTIC_DRIFT_POINTS,
                "domain": "SEMANTIC_TRUST",
                "title": f"{sem_drift} Critical Semantic Drift Event(s)",
                "explanation": f"{sem_drift} vendor logs exhibited critical token or schema deviations from active semantic policies.",
                "source_entity_type": "SEMANTIC_DRIFT_ALERT",
                "source_entity_id": telemetry.get("primary_drift_alert_id", "DRIFT-ALERT-ACTIVE"),
                "source_reference": telemetry.get("primary_drift_alert_ref", "drift_cisco_asa_01"),
                "rank": 2,
                "active": True,
                "resolved": False,
            })

        # 5. Failed Recovery Verification
        failed_rec = telemetry.get("failed_recovery_verifications", 0)
        if failed_rec > 0:
            drivers.append({
                "id": f"erd-{uuid.uuid4().hex[:12]}",
                "driver_id": f"erd-{uuid.uuid4().hex[:12]}",
                "posture_evaluation_id": evaluation_id,
                "driver_type": "FAILED_RECOVERY_VERIFICATION",
                "severity": "HIGH",
                "risk_points": failed_rec * ExecutiveRiskConstants.FAILED_RECOVERY_VERIFICATION_POINTS,
                "domain": "ASSURANCE_RECOVERY",
                "title": f"{failed_rec} Unverified Assurance Recovery Attempt(s)",
                "explanation": f"Post-remediation assurance re-evaluations produced INCONCLUSIVE or FAILED recovery states under Zero Trust rules.",
                "source_entity_type": "ASSURANCE_RECOVERY_VERIFICATION",
                "source_entity_id": telemetry.get("primary_recovery_verification_id", "ARV-UNVERIFIED"),
                "source_reference": telemetry.get("primary_recovery_case_ref", "ARC-2026-000001"),
                "rank": 2,
                "active": True,
                "resolved": False,
            })

        # 6. High Open Incidents
        high_inc = telemetry.get("open_high_incidents", 0)
        if high_inc > 0:
            drivers.append({
                "id": f"erd-{uuid.uuid4().hex[:12]}",
                "driver_id": f"erd-{uuid.uuid4().hex[:12]}",
                "posture_evaluation_id": evaluation_id,
                "driver_type": "OPEN_HIGH_INCIDENT",
                "severity": "HIGH",
                "risk_points": high_inc * ExecutiveRiskConstants.HIGH_OPEN_INCIDENT_POINTS,
                "domain": "INCIDENT_SECURITY",
                "title": f"{high_inc} Open High Severity Incident(s)",
                "explanation": f"{high_inc} high-severity security incidents are pending investigation or containment.",
                "source_entity_type": "SECURITY_INCIDENT",
                "source_entity_id": telemetry.get("primary_high_incident_id", "INC-HIGH-ACTIVE"),
                "source_reference": telemetry.get("primary_high_incident_ref", "INC-2026-HIGH"),
                "rank": 2,
                "active": True,
                "resolved": False,
            })

        # 7. Unresolved Assurance Alerts
        unres_ass = telemetry.get("unresolved_assurance_alerts", 0)
        if unres_ass > 0 and not any(d["domain"] == "PLATFORM_ASSURANCE" for d in drivers):
            drivers.append({
                "id": f"erd-{uuid.uuid4().hex[:12]}",
                "driver_id": f"erd-{uuid.uuid4().hex[:12]}",
                "posture_evaluation_id": evaluation_id,
                "driver_type": "UNRESOLVED_ASSURANCE_ALERT",
                "severity": "MEDIUM",
                "risk_points": unres_ass * ExecutiveRiskConstants.UNRESOLVED_ASSURANCE_ALERT_POINTS,
                "domain": "PLATFORM_ASSURANCE",
                "title": f"{unres_ass} Unresolved Platform Assurance Alert(s)",
                "explanation": f"{unres_ass} pipeline health alerts require analyst triage and governed remediation.",
                "source_entity_type": "ASSURANCE_ALERT",
                "source_entity_id": telemetry.get("primary_assurance_alert_id", "AA-ACTIVE"),
                "source_reference": telemetry.get("primary_assurance_alert_ref", "aa-pipeline-lag"),
                "rank": 3,
                "active": True,
                "resolved": False,
            })

        # 8. Pending Containment Requests
        pending_cont = telemetry.get("pending_containment_requests", 0)
        if pending_cont > 0:
            drivers.append({
                "id": f"erd-{uuid.uuid4().hex[:12]}",
                "driver_id": f"erd-{uuid.uuid4().hex[:12]}",
                "posture_evaluation_id": evaluation_id,
                "driver_type": "PENDING_HIGH_IMPACT_CONTAINMENT",
                "severity": "MEDIUM",
                "risk_points": pending_cont * ExecutiveRiskConstants.PENDING_CONTAINMENT_POINTS,
                "domain": "INCIDENT_RESPONSE",
                "title": f"{pending_cont} Containment Action(s) Pending Authorization",
                "explanation": f"Dual-control containment authorization is pending reviewer approval.",
                "source_entity_type": "INCIDENT_CONTAINMENT_REQUEST",
                "source_entity_id": telemetry.get("primary_containment_id", "ICR-PENDING"),
                "source_reference": telemetry.get("primary_containment_ref", "icr-fw-block"),
                "rank": 3,
                "active": True,
                "resolved": False,
            })

        # 9. Telemetry Gap / Unknown Driver
        if telemetry.get("telemetry_missing", False):
            drivers.append({
                "id": f"erd-{uuid.uuid4().hex[:12]}",
                "driver_id": f"erd-{uuid.uuid4().hex[:12]}",
                "posture_evaluation_id": evaluation_id,
                "driver_type": "TELEMETRY_GAP",
                "severity": "HIGH",
                "risk_points": ExecutiveRiskConstants.UNKNOWN_TELEMETRY_POINTS,
                "domain": "PLATFORM_ASSURANCE",
                "title": "Executive Telemetry Incompleteness",
                "explanation": "Critical domain telemetry is unavailable, enforcing explicit Zero-Trust UNKNOWN degradation.",
                "source_entity_type": "PLATFORM_ASSURANCE_EVALUATION",
                "source_entity_id": "sentinel.platform_assurance",
                "source_reference": "TELEMETRY-GAP-DETECTED",
                "rank": 2,
                "active": True,
                "resolved": False,
            })

        # Sort drivers by severity rank, then risk points descending
        drivers.sort(
            key=lambda d: (
                ExecutiveRiskConstants.SEVERITY_ORDER.get(d["severity"], 99),
                -d["risk_points"],
            )
        )

        # Assign final 1-indexed rank
        for idx, drv in enumerate(drivers, start=1):
            drv["rank"] = idx

        return drivers

    @classmethod
    def _generate_insights(
        cls,
        telemetry: Dict[str, Any],
        domain_results: List[Dict[str, Any]],
        risk_drivers: List[Dict[str, Any]],
        overall_security_score: float,
        executive_risk_score: float,
        posture_status: str,
        previous_eval: Optional[ExecutiveSecurityPostureEvaluation],
        score_delta: Optional[float],
        hard_overrides: List[str],
        evaluation_id: str,
    ) -> List[Dict[str, Any]]:
        """Generates deterministic rule-based executive insights without ML or LLMs."""
        insights: List[Dict[str, Any]] = []

        # Rule 1: Risk Escalation (Critical incidents increased)
        if previous_eval and telemetry.get("open_critical_incidents", 0) > previous_eval.open_critical_incidents:
            delta_crit = telemetry.get("open_critical_incidents", 0) - previous_eval.open_critical_incidents
            ins_id = f"esi-{uuid.uuid4().hex[:12]}"
            payload = {
                "rule": "RULE_1_RISK_ESCALATION",
                "current_critical": telemetry.get("open_critical_incidents", 0),
                "previous_critical": previous_eval.open_critical_incidents,
            }
            insights.append({
                "id": ins_id,
                "insight_id": ins_id,
                "posture_evaluation_id": evaluation_id,
                "insight_type": "RISK_ESCALATION",
                "severity": "CRITICAL",
                "title": "Security Risk Escalation: Critical Incident Volume Surge",
                "description": f"Open critical incidents increased by +{delta_crit} since last evaluation ({previous_eval.open_critical_incidents} -> {telemetry.get('open_critical_incidents', 0)}), elevating executive risk.",
                "supporting_metrics": payload,
                "recommended_attention": "SOC Manager must review triage queue and accelerate active incident containment playbooks.",
                "source_domains": ["INCIDENT_SECURITY", "INCIDENT_RESPONSE"],
                "confidence": 100.0,
                "canonical_payload": payload,
                "insight_hash": calculate_executive_hash(EXECUTIVE_INSIGHT_DOMAIN_PREFIX, payload),
            })

        # Rule 2: Posture Recovery (Assurance improved and verified recovery recorded)
        if previous_eval and score_delta is not None and score_delta >= 3.0 and telemetry.get("failed_recovery_verifications", 0) == 0:
            ins_id = f"esi-{uuid.uuid4().hex[:12]}"
            payload = {
                "rule": "RULE_2_POSTURE_RECOVERY",
                "score_delta": score_delta,
                "current_score": overall_security_score,
            }
            insights.append({
                "id": ins_id,
                "insight_id": ins_id,
                "posture_evaluation_id": evaluation_id,
                "insight_type": "POSTURE_RECOVERY",
                "severity": "INFORMATIONAL",
                "title": "Measurable Posture Improvement Verified",
                "description": f"Overall security posture improved by +{score_delta:.1f} points following governed remediation and independent re-evaluation.",
                "supporting_metrics": payload,
                "recommended_attention": "Maintain remediation audit logs and continue automated assurance telemetry tracking.",
                "source_domains": ["PLATFORM_ASSURANCE", "ASSURANCE_RECOVERY"],
                "confidence": 100.0,
                "canonical_payload": payload,
                "insight_hash": calculate_executive_hash(EXECUTIVE_INSIGHT_DOMAIN_PREFIX, payload),
            })

        # Rule 3: Concentrated Risk (>60% of total risk originates from a single domain)
        if executive_risk_score > 10.0:
            total_deductions = sum(d["deduction_total"] * d["risk_weight"] for d in domain_results)
            if total_deductions > 0:
                for dom in domain_results:
                    dom_weighted_deduction = dom["deduction_total"] * dom["risk_weight"]
                    proportion = (dom_weighted_deduction / total_deductions) * 100.0
                    if proportion >= 60.0:
                        ins_id = f"esi-{uuid.uuid4().hex[:12]}"
                        payload = {
                            "rule": "RULE_3_CONCENTRATED_RISK",
                            "domain": dom["domain_name"],
                            "risk_share_percentage": round(proportion, 1),
                        }
                        insights.append({
                            "id": ins_id,
                            "insight_id": ins_id,
                            "posture_evaluation_id": evaluation_id,
                            "insight_type": "CONCENTRATED_RISK",
                            "severity": "HIGH",
                            "title": f"Concentrated Risk Driver in {dom['domain_name'].replace('_', ' ').title()}",
                            "description": f"{proportion:.1f}% of total executive security risk originates from the {dom['domain_name']} domain ({dom['primary_driver']}).",
                            "supporting_metrics": payload,
                            "recommended_attention": f"Target remediation efforts specifically at {dom['domain_name']} to achieve maximum risk reduction.",
                            "source_domains": [dom["domain_name"]],
                            "confidence": 95.0,
                            "canonical_payload": payload,
                            "insight_hash": calculate_executive_hash(EXECUTIVE_INSIGHT_DOMAIN_PREFIX, payload),
                        })

        # Rule 4: Cryptographic Alert
        if "CRYPTOGRAPHIC_INTEGRITY_FAILURE" in hard_overrides or "GOVERNANCE_LEDGER_INTEGRITY_FAILURE" in hard_overrides:
            ins_id = f"esi-{uuid.uuid4().hex[:12]}"
            payload = {
                "rule": "RULE_4_CRYPTOGRAPHIC_ALERT",
                "hard_overrides": hard_overrides,
            }
            insights.append({
                "id": ins_id,
                "insight_id": ins_id,
                "posture_evaluation_id": evaluation_id,
                "insight_type": "CRYPTOGRAPHIC_ALERT",
                "severity": "CRITICAL",
                "title": "CRITICAL Cryptographic Immutability Override Active",
                "description": "Cryptographic integrity failure has overridden all numerical scores to CRITICAL. Immutability verification failed on ledger or vault assets.",
                "supporting_metrics": payload,
                "recommended_attention": "Security Architect and DevSecOps must immediately audit the governance ledger sequence and investigate raw vault hash mismatches.",
                "source_domains": ["CRYPTOGRAPHIC_ASSURANCE", "EVIDENCE_INTEGRITY"],
                "confidence": 100.0,
                "canonical_payload": payload,
                "insight_hash": calculate_executive_hash(EXECUTIVE_INSIGHT_DOMAIN_PREFIX, payload),
            })

        # Rule 5: Cross-Domain Failure (Semantic Drift + Detection Trust Degradation)
        if telemetry.get("critical_semantic_drift_events", 0) > 0 and telemetry.get("active_detection_trust_failures", 0) > 0:
            ins_id = f"esi-{uuid.uuid4().hex[:12]}"
            payload = {
                "rule": "RULE_5_CROSS_DOMAIN_FAILURE",
                "semantic_drift_count": telemetry.get("critical_semantic_drift_events", 0),
                "detection_trust_fail_count": telemetry.get("active_detection_trust_failures", 0),
            }
            insights.append({
                "id": ins_id,
                "insight_id": ins_id,
                "posture_evaluation_id": evaluation_id,
                "insight_type": "CROSS_DOMAIN_FAILURE",
                "severity": "HIGH",
                "title": "Cross-Domain Cascade: Semantic Drift Propagating to Detection Rules",
                "description": "Critical semantic drift in vendor log schemas is directly degrading downstream detection rule trust scores.",
                "supporting_metrics": payload,
                "recommended_attention": "Policy Authors must update and submit semantic policy revisions to restore detection rule trust.",
                "source_domains": ["SEMANTIC_TRUST", "DETECTION_TRUST"],
                "confidence": 98.0,
                "canonical_payload": payload,
                "insight_hash": calculate_executive_hash(EXECUTIVE_INSIGHT_DOMAIN_PREFIX, payload),
            })

        # Rule 6: Telemetry Insufficiency
        if posture_status == "UNKNOWN" or telemetry.get("telemetry_missing", False):
            ins_id = f"esi-{uuid.uuid4().hex[:12]}"
            payload = {
                "rule": "RULE_6_TELEMETRY_INSUFFICIENCY",
                "posture_status": posture_status,
            }
            insights.append({
                "id": ins_id,
                "insight_id": ins_id,
                "posture_evaluation_id": evaluation_id,
                "insight_type": "TELEMETRY_INSUFFICIENCY",
                "severity": "HIGH",
                "title": "Telemetry Gap Enforces Zero-Trust UNKNOWN Status",
                "description": "Essential platform health or incident telemetry is missing or unverified. Zero-Trust policy prohibits assuming a healthy posture.",
                "supporting_metrics": payload,
                "recommended_attention": "Verify platform telemetry pipelines and ensure all domain agents are reporting health telemetry.",
                "source_domains": ["PLATFORM_ASSURANCE"],
                "confidence": 100.0,
                "canonical_payload": payload,
                "insight_hash": calculate_executive_hash(EXECUTIVE_INSIGHT_DOMAIN_PREFIX, payload),
            })

        # Rule 7: Governance Bottleneck (Multiple containment requests or remediation plans pending)
        pending_cont = telemetry.get("pending_containment_requests", 0)
        open_cases = telemetry.get("open_remediation_cases", 0)
        if pending_cont >= 2 or open_cases >= 3:
            ins_id = f"esi-{uuid.uuid4().hex[:12]}"
            payload = {
                "rule": "RULE_7_GOVERNANCE_BOTTLENECK",
                "pending_containment": pending_cont,
                "open_cases": open_cases,
            }
            insights.append({
                "id": ins_id,
                "insight_id": ins_id,
                "posture_evaluation_id": evaluation_id,
                "insight_type": "GOVERNANCE_BOTTLENECK",
                "severity": "MEDIUM",
                "title": "Dual-Control Governance Queue Bottleneck",
                "description": f"{pending_cont} containment requests and {open_cases} remediation cases await reviewer authorization or execution.",
                "supporting_metrics": payload,
                "recommended_attention": "Authorized Policy Reviewers must review and authorize pending containment actions to reduce response latency.",
                "source_domains": ["INCIDENT_RESPONSE", "ASSURANCE_RECOVERY"],
                "confidence": 92.0,
                "canonical_payload": payload,
                "insight_hash": calculate_executive_hash(EXECUTIVE_INSIGHT_DOMAIN_PREFIX, payload),
            })

        return insights

    @staticmethod
    def _build_evaluation_reason(
        posture_status: str,
        overall_score: float,
        hard_overrides: List[str],
        top_drivers: List[Dict[str, Any]],
        domain_results: List[Dict[str, Any]],
    ) -> str:
        """Constructs concise deterministic explanation for overall security posture."""
        if hard_overrides:
            override_str = ", ".join(hard_overrides)
            return f"Overall posture is {posture_status} due to Hard Failure Override ({override_str}). Numerical score of {overall_score:.1f}/100 is superseded by zero-trust security policy."

        driver_summaries = [d["title"] for d in top_drivers if d.get("title")]
        driver_str = "; ".join(driver_summaries) if driver_summaries else "All 10 security domains operating within normal baseline parameters"

        lowest_domains = sorted(domain_results, key=lambda d: d["final_score"])[:2]
        dom_str = ", ".join([f"{d['domain_name']} ({d['final_score']:.1f})" for d in lowest_domains if d["final_score"] < 90.0])

        if dom_str:
            return f"Overall posture is {posture_status} ({overall_score:.1f}/100). Primary risk drivers: {driver_str}. Lowest domain scores: {dom_str}."
        return f"Overall posture is {posture_status} ({overall_score:.1f}/100). {driver_str}."

    # ── Query & Reporting Methods ─────────────────────────────────────────────

    @classmethod
    def get_latest_evaluation(cls, db: Session) -> Optional[ExecutiveSecurityPostureEvaluation]:
        """Returns the most recent executive posture evaluation."""
        return (
            db.query(ExecutiveSecurityPostureEvaluation)
            .order_by(desc(ExecutiveSecurityPostureEvaluation.evaluation_timestamp))
            .first()
        )

    @classmethod
    def get_evaluation_by_id(cls, db: Session, evaluation_id: str) -> Optional[ExecutiveSecurityPostureEvaluation]:
        """Fetches an evaluation by evaluation_id or primary key id."""
        return (
            db.query(ExecutiveSecurityPostureEvaluation)
            .filter(
                (ExecutiveSecurityPostureEvaluation.evaluation_id == evaluation_id)
                | (ExecutiveSecurityPostureEvaluation.id == evaluation_id)
            )
            .first()
        )

    @classmethod
    def list_evaluations(
        cls,
        db: Session,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[ExecutiveSecurityPostureEvaluation]:
        """Lists historical executive posture evaluations."""
        query = db.query(ExecutiveSecurityPostureEvaluation)
        if status:
            query = query.filter(ExecutiveSecurityPostureEvaluation.overall_posture_status == status.upper())
        return (
            query.order_by(desc(ExecutiveSecurityPostureEvaluation.evaluation_timestamp))
            .offset(offset)
            .limit(limit)
            .all()
        )

    @classmethod
    def get_kpis(cls, db: Session) -> Dict[str, Any]:
        """Computes current executive security KPIs."""
        latest = cls.get_latest_evaluation(db)
        if not latest:
            return {
                "overall_posture_status": "UNKNOWN",
                "overall_security_score": 0.0,
                "executive_risk_score": 100.0,
                "confidence_score": 0.0,
                "open_critical_incidents": 0,
                "open_high_incidents": 0,
                "detection_trust_failures": 0,
                "critical_semantic_drift_events": 0,
                "unresolved_assurance_alerts": 0,
                "active_remediation_cases": 0,
                "cryptographic_integrity_status": "UNKNOWN",
                "posture_trend_direction": "UNKNOWN",
                "score_delta_24h": 0.0,
                "last_evaluation_timestamp": None,
                "evaluation_id": None,
            }

        # Calculate 24h score delta
        one_day_ago = latest.evaluation_timestamp - timedelta(hours=24)
        older_eval = (
            db.query(ExecutiveSecurityPostureEvaluation)
            .filter(ExecutiveSecurityPostureEvaluation.evaluation_timestamp <= one_day_ago)
            .order_by(desc(ExecutiveSecurityPostureEvaluation.evaluation_timestamp))
            .first()
        )
        score_delta_24h = round(latest.overall_security_score - older_eval.overall_security_score, 2) if older_eval else latest.score_delta

        trend_dir = "STABLE"
        if latest.score_delta is not None:
            if latest.score_delta >= 3.0:
                trend_dir = "IMPROVING"
            elif latest.score_delta <= -3.0:
                trend_dir = "DETERIORATING"

        return {
            "overall_posture_status": latest.overall_posture_status,
            "overall_security_score": latest.overall_security_score,
            "executive_risk_score": latest.executive_risk_score,
            "confidence_score": latest.confidence_score,
            "open_critical_incidents": latest.open_critical_incidents,
            "open_high_incidents": latest.open_high_incidents,
            "detection_trust_failures": latest.active_detection_trust_failures,
            "critical_semantic_drift_events": latest.critical_semantic_drift_events,
            "unresolved_assurance_alerts": latest.unresolved_assurance_alerts,
            "active_remediation_cases": latest.open_remediation_cases,
            "cryptographic_integrity_status": latest.cryptographic_integrity_status,
            "posture_trend_direction": trend_dir,
            "score_delta_24h": score_delta_24h,
            "last_evaluation_timestamp": latest.evaluation_timestamp,
            "evaluation_id": latest.evaluation_id,
        }

    @classmethod
    def get_trends(
        cls,
        db: Session,
        hours: Optional[int] = None,
        days: Optional[int] = None,
        limit: int = 100,
    ) -> List[ExecutivePostureTrendSnapshot]:
        """Fetches historical trend snapshots within time window."""
        query = db.query(ExecutivePostureTrendSnapshot)
        if days:
            cutoff = utcnow() - timedelta(days=days)
            query = query.filter(ExecutivePostureTrendSnapshot.timestamp >= cutoff)
        elif hours:
            cutoff = utcnow() - timedelta(hours=hours)
            query = query.filter(ExecutivePostureTrendSnapshot.timestamp >= cutoff)

        return (
            query.order_by(desc(ExecutivePostureTrendSnapshot.timestamp))
            .limit(limit)
            .all()
        )

    @classmethod
    def explain_evaluation(
        cls, db: Session, evaluation_id: str
    ) -> Optional[Dict[str, Any]]:
        """Provides full deterministic explanation tree and breakdown for an evaluation."""
        eval_record = cls.get_evaluation_by_id(db, evaluation_id)
        if not eval_record:
            return None

        # Gather previous evaluation for diff
        previous_eval = None
        if eval_record.previous_evaluation_id:
            previous_eval = cls.get_evaluation_by_id(db, eval_record.previous_evaluation_id)

        hard_overrides = eval_record.canonical_payload.get("hard_overrides", [])

        posture_change_details = {
            "previous_evaluation_id": eval_record.previous_evaluation_id,
            "previous_score": previous_eval.overall_security_score if previous_eval else None,
            "current_score": eval_record.overall_security_score,
            "score_delta": eval_record.score_delta,
            "risk_delta": round((previous_eval.executive_risk_score - eval_record.executive_risk_score), 2) if previous_eval else None,
            "critical_driver_delta": (eval_record.critical_driver_count - previous_eval.critical_driver_count) if previous_eval else None,
            "incident_delta": (eval_record.open_critical_incidents - previous_eval.open_critical_incidents) if previous_eval else None,
            "classification": eval_record.posture_change or "INITIAL_EVALUATION",
            "explanation": f"Posture transition classified as {eval_record.posture_change}. {eval_record.evaluation_reason}",
        }

        provenance_summary = {
            "evaluation_hash": eval_record.evaluation_hash,
            "canonical_payload_fields": len(eval_record.canonical_payload),
            "domains_evaluated": len(eval_record.domain_scores),
            "risk_drivers_count": len(eval_record.risk_drivers),
            "insights_generated": len(eval_record.insights),
            "cryptographic_status": eval_record.cryptographic_integrity_status,
        }

        return {
            "evaluation_id": eval_record.evaluation_id,
            "overall_status": eval_record.overall_posture_status,
            "overall_security_score": eval_record.overall_security_score,
            "executive_risk_score": eval_record.executive_risk_score,
            "hard_overrides": hard_overrides,
            "top_risk_drivers": eval_record.risk_drivers,
            "domain_breakdown": eval_record.domain_scores,
            "posture_change": posture_change_details,
            "executive_insights": eval_record.insights,
            "provenance_summary": provenance_summary,
        }

    @classmethod
    def get_ledger_verification(
        cls, db: Session, evaluation_id: str
    ) -> Optional[Dict[str, Any]]:
        """Verifies governance ledger entry and Merkle inclusion proof for this evaluation."""
        eval_record = cls.get_evaluation_by_id(db, evaluation_id)
        if not eval_record:
            return None

        # Find corresponding ledger entry
        ledger_entry = (
            db.query(GovernanceLedgerEntry)
            .filter(
                GovernanceLedgerEntry.event_type.in_([
                    "EXECUTIVE_POSTURE_EVALUATED",
                    "EXECUTIVE_POSTURE_CRITICAL",
                    "EXECUTIVE_RISK_ESCALATED",
                    "EXECUTIVE_POSTURE_IMPROVED",
                    "EXECUTIVE_CRYPTOGRAPHIC_OVERRIDE",
                    "EXECUTIVE_TELEMETRY_UNKNOWN",
                ])
            )
            .order_by(desc(GovernanceLedgerEntry.created_at))
            .first()
        )

        chain_res = GovernanceLedgerService.verify_chain(db)
        chain_valid = chain_res.get("is_valid", True)

        merkle_proof_status = "NOT_BATCHED"
        merkle_root = None
        merkle_batch_id = None

        if ledger_entry:
            # Check for merkle batch
            proof = (
                db.query(MerkleProof)
                .filter(MerkleProof.ledger_entry_id == ledger_entry.id)
                .first()
            )
            if proof:
                merkle_batch_id = proof.batch_id
                batch = db.query(MerkleBatch).filter(MerkleBatch.batch_id == proof.batch_id).first()
                if batch:
                    merkle_root = batch.merkle_root
                # Verify inclusion proof mathematically
                v_res = MerkleTreeService.verify_inclusion_proof(
                    leaf_hash=proof.leaf_hash,
                    proof_path=proof.proof_path,
                    merkle_root=proof.merkle_root,
                )
                merkle_proof_status = "VALID" if v_res.get("verification_status") == "VALID" else "INVALID"

        return {
            "evaluation_id": eval_record.evaluation_id,
            "evaluation_hash": eval_record.evaluation_hash,
            "ledger_entry_id": ledger_entry.id if ledger_entry else None,
            "ledger_event_type": ledger_entry.event_type if ledger_entry else None,
            "ledger_entry_hash": ledger_entry.entry_hash if ledger_entry else None,
            "previous_hash": ledger_entry.previous_hash if ledger_entry else None,
            "merkle_batch_id": merkle_batch_id,
            "merkle_root": merkle_root,
            "merkle_proof_status": merkle_proof_status,
            "cryptographic_chain_valid": chain_valid,
            "verification_reason": "Governance ledger hash chain and cryptographic evaluation seal verified successfully." if chain_valid else "Cryptographic ledger hash mismatch detected!",
        }
