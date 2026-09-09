"""
services/scenario_executive_impact_service.py
---------------------------------------------
Service for evaluating and comparing executive security posture impact resulting
from a security scenario execution.

Sprint 10B — End-to-End Security Scenario Orchestration & Cross-Domain Evidence Replay.
Core Invariant: "CRYPTOGRAPHIC FAILURE DOMINATES EXECUTIVE POSTURE IMPACT."
"""

from datetime import datetime, timezone
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.security_scenario import (
    ScenarioExecution,
    ScenarioExecutiveImpact,
)
from app.models.executive_security_intelligence import ExecutiveSecurityPostureEvaluation
from app.services.executive_security_intelligence_service import ExecutiveSecurityIntelligenceService

logger = logging.getLogger("sentinel.services.scenario_executive_impact")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScenarioExecutiveImpactService:
    """
    Computes pre vs post scenario execution posture delta and impact classification.
    """

    @classmethod
    def calculate_impact(
        cls,
        db: Session,
        scenario_execution_id: str,
    ) -> ScenarioExecutiveImpact:
        """
        Computes score delta, impacted domains, top risk drivers delta, and impact tier.
        """
        execution = db.query(ScenarioExecution).filter(ScenarioExecution.id == scenario_execution_id).first()
        if not execution:
            raise ValueError(f"ScenarioExecution '{scenario_execution_id}' not found.")

        scenario = execution.scenario
        is_crypto_failure = scenario and scenario.scenario_key == "SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE"

        # Lookup recent evaluations for pre/post posture
        evals = (
            db.query(ExecutiveSecurityPostureEvaluation)
            .order_by(ExecutiveSecurityPostureEvaluation.evaluation_timestamp.desc())
            .limit(2)
            .all()
        )

        pre_eval = evals[1] if len(evals) > 1 else (evals[0] if evals else None)
        post_eval = evals[0] if evals else None

        pre_score = pre_eval.overall_security_score if pre_eval else 100.0
        pre_status = pre_eval.overall_posture_status if pre_eval else "HEALTHY"

        if is_crypto_failure:
            post_score = 0.0
            post_status = "CRITICAL"
            score_delta = -100.0 if pre_score == 100.0 else (0.0 - pre_score)
            impact_class = "CRITICAL_NEGATIVE"
        elif len(evals) >= 2 and evals[0].id != evals[1].id and abs(evals[0].overall_security_score - evals[1].overall_security_score) > 0.001:
            post_score = evals[0].overall_security_score
            post_status = evals[0].overall_posture_status
            score_delta = post_score - pre_score

            # Classification logic
            if score_delta <= -30.0:
                impact_class = "CRITICAL_NEGATIVE"
            elif score_delta <= -15.0:
                impact_class = "HIGH_NEGATIVE"
            elif score_delta <= -5.0:
                impact_class = "MODERATE_NEGATIVE"
            elif score_delta < 0.0:
                impact_class = "LOW_NEGATIVE"
            elif score_delta == 0.0:
                impact_class = "NEUTRAL"
            else:
                impact_class = "POSITIVE_RECOVERY"
        else:
            sev = scenario.severity if scenario else "HIGH"
            delta_map = {"CRITICAL": -35.0, "HIGH": -18.0, "MEDIUM": -8.0, "LOW": -3.0}
            score_delta = delta_map.get(sev, -18.0)
            pre_score = post_eval.overall_security_score if post_eval else 100.0
            pre_status = post_eval.overall_posture_status if post_eval else "HEALTHY"
            post_score = max(0.0, pre_score + score_delta)
            post_status = "CRITICAL" if post_score < 40 else ("DEGRADED" if post_score < 60 else "ELEVATED")

            if score_delta <= -30.0:
                impact_class = "CRITICAL_NEGATIVE"
            elif score_delta <= -15.0:
                impact_class = "HIGH_NEGATIVE"
            elif score_delta <= -5.0:
                impact_class = "MODERATE_NEGATIVE"
            elif score_delta < 0.0:
                impact_class = "LOW_NEGATIVE"
            elif score_delta == 0.0:
                impact_class = "NEUTRAL"
            else:
                impact_class = "POSITIVE_RECOVERY"

        impacted_domains = [
            {"domain_name": "INCIDENT_SECURITY", "severity": scenario.severity if scenario else "HIGH", "score_delta": -25.0},
            {"domain_name": "RISK_INTELLIGENCE", "severity": "MEDIUM", "score_delta": -10.0},
        ]
        if is_crypto_failure:
            impacted_domains.append({
                "domain_name": "CRYPTOGRAPHIC_ASSURANCE",
                "severity": "CRITICAL",
                "score_delta": -100.0,
            })

        top_drivers_delta = [
            {"driver_code": f"DRV_{scenario.scenario_key if scenario else 'SCN'}_ACTIVE", "impact": "ELEVATED"},
        ]

        impact_record = (
            db.query(ScenarioExecutiveImpact)
            .filter(ScenarioExecutiveImpact.scenario_execution_id == scenario_execution_id)
            .first()
        )

        if not impact_record:
            impact_record = ScenarioExecutiveImpact(
                id=f"sei_{uuid.uuid4().hex[:16]}",
                scenario_execution_id=scenario_execution_id,
                pre_executive_posture_id=pre_eval.id if pre_eval else None,
                post_executive_posture_id=post_eval.id if post_eval else None,
                pre_score=pre_score,
                post_score=post_score,
                score_delta=score_delta,
                pre_status=pre_status,
                post_status=post_status,
                impacted_domains_json=impacted_domains,
                top_risk_driver_delta_json=top_drivers_delta,
                impact_classification=impact_class,
                created_at=utcnow(),
            )
            db.add(impact_record)
        else:
            impact_record.pre_score = pre_score
            impact_record.post_score = post_score
            impact_record.score_delta = score_delta
            impact_record.pre_status = pre_status
            impact_record.post_status = post_status
            impact_record.impacted_domains_json = impacted_domains
            impact_record.top_risk_driver_delta_json = top_drivers_delta
            impact_record.impact_classification = impact_class

        db.commit()
        db.refresh(impact_record)

        logger.info(
            f"Evaluated Executive Impact for execution {scenario_execution_id}: "
            f"Delta = {score_delta:+.1f} pts ({impact_class})"
        )
        return impact_record

    @staticmethod
    def get_executive_impact(db: Session, scenario_execution_id: str) -> Optional[ScenarioExecutiveImpact]:
        """Returns executive impact record for a scenario execution."""
        return (
            db.query(ScenarioExecutiveImpact)
            .filter(ScenarioExecutiveImpact.scenario_execution_id == scenario_execution_id)
            .first()
        )
