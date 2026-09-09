"""
services/security_analytics_insight_service.py
----------------------------------------------
Deterministic Rule-Based Platform Analytics Insight Engine.

Sprint 12B — Security Analytics, Reporting & Evidence Intelligence.
Core Invariant: "ZERO ML / ZERO LLM: ALL INSIGHTS ARE GROUNDED IN DETERMINISTIC RULES & BACKED BY TRACEABLE EVIDENCE."
"""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.security_analytics import (
    SecurityAnalyticsSnapshot,
    SecurityMetricEvaluation,
    SecurityMetricDefinition,
    SecurityAnalyticsInsight,
    ANALYTICS_INSIGHT_DOMAIN_PREFIX,
    compute_canonical_hash,
)


class SecurityAnalyticsInsightService:
    """
    Evaluates rule-based deterministic conditions against platform analytics snapshots.
    """

    @staticmethod
    def generate_insights_for_snapshot(
        db: Session,
        snapshot_id: str,
    ) -> List[SecurityAnalyticsInsight]:
        """
        Applies deterministic rules to generate audit-grounded insights.
        """
        snapshot = db.query(SecurityAnalyticsSnapshot).filter_by(id=snapshot_id).first()
        if not snapshot:
            return []

        evals = db.query(
            SecurityMetricEvaluation, SecurityMetricDefinition
        ).join(
            SecurityMetricDefinition,
            SecurityMetricEvaluation.metric_definition_id == SecurityMetricDefinition.id,
        ).filter(
            SecurityMetricEvaluation.snapshot_id == snapshot_id
        ).all()

        metrics_map: Dict[str, SecurityMetricEvaluation] = {
            m_def.metric_code: m_eval for m_eval, m_def in evals
        }

        generated_insights: List[SecurityAnalyticsInsight] = []
        now = datetime.now(timezone.utc)

        # Helper to build insight
        def add_insight(
            code: str,
            i_type: str,
            severity: str,
            title: str,
            description: str,
            rule_name: str,
            supp_metrics: List[Dict[str, Any]],
            source_refs: List[str],
            conf: float,
            limitations: List[str],
        ):
            payload = {
                "snapshot_id": snapshot.id,
                "insight_code": code,
                "insight_type": i_type,
                "severity": severity,
                "title": title,
                "rule_triggered": rule_name,
            }
            i_hash = compute_canonical_hash(ANALYTICS_INSIGHT_DOMAIN_PREFIX, payload)

            insight = SecurityAnalyticsInsight(
                id=f"sai-{uuid.uuid4().hex[:12]}",
                snapshot_id=snapshot.id,
                insight_code=code,
                insight_type=i_type,
                severity=severity,
                title=title,
                description=description,
                rule_triggered=rule_name,
                supporting_metrics_json=supp_metrics,
                source_references_json=source_refs,
                confidence_score=conf,
                limitations_json=limitations,
                insight_hash=i_hash,
                created_at=now,
            )
            db.add(insight)
            generated_insights.append(insight)

        # RULE 7: Cryptographic Integrity Failure (Dominance Rule)
        if snapshot.overall_confidence == 0.0:
            add_insight(
                code="SAI-CRYPTO-TAMPER-001",
                i_type="CRYPTOGRAPHIC_INTEGRITY_FAILURE",
                severity="CRITICAL",
                title="Cryptographic Integrity Violation Detected",
                description="Evidence tampering or checksum mismatch detected. All numerical metrics are overridden to UNTRUSTED.",
                rule_name="RULE_CRYPTOGRAPHIC_FAILURE_DOMINANCE",
                supp_metrics=[{"metric": "OVERALL_CONFIDENCE", "value": 0.0}],
                source_refs=[snapshot.snapshot_hash],
                conf=100.0,
                limitations=["Cryptographic failure strictly invalidates all higher-order conclusions."],
            )

        # RULE 1: Cross-Domain Failure (Incidents Surge + Detection Trust Degradation)
        inc_eval = metrics_map.get("METRIC_OPEN_INCIDENTS")
        det_trust_eval = metrics_map.get("METRIC_DETECTION_TRUST_AVERAGE")
        if inc_eval and det_trust_eval and inc_eval.metric_value > 2 and det_trust_eval.metric_value < 85.0:
            add_insight(
                code="SAI-CROSS-DOMAIN-001",
                i_type="CROSS_DOMAIN_FAILURE",
                severity="HIGH",
                title="Cross-Domain Incident & Detection Correlation Risk",
                description="Active security incident volume is elevated while detection rule trust average has declined.",
                rule_name="RULE_INCIDENT_INCREASE_AND_DETECTION_TRUST_DECLINE",
                supp_metrics=[
                    {"metric": "METRIC_OPEN_INCIDENTS", "value": inc_eval.metric_value},
                    {"metric": "METRIC_DETECTION_TRUST_AVERAGE", "value": det_trust_eval.metric_value},
                ],
                source_refs=inc_eval.source_references_json or [],
                conf=90.0,
                limitations=["Assumes detection trust scores reflect current rule fleet reliability."],
            )

        # RULE 2: Threat Intelligence Escalation
        threat_eval = metrics_map.get("METRIC_THREAT_INTELLIGENCE_TRUST")
        risk_eval = metrics_map.get("METRIC_CRITICAL_RISK_EVENTS")
        if (risk_eval and risk_eval.metric_value > 0) or (threat_eval and threat_eval.metric_value < 75.0):
            add_insight(
                code="SAI-THREAT-ESCALATION-001",
                i_type="THREAT_ESCALATION",
                severity="HIGH",
                title="Active Threat Correlation & Risk Concentration",
                description="High-severity correlated threat observables or reduced threat feed trust detected across platform events.",
                rule_name="RULE_THREAT_CORRELATION_OR_TRUST_DROP",
                supp_metrics=[
                    {"metric": "METRIC_CRITICAL_RISK_EVENTS", "value": risk_eval.metric_value if risk_eval else 0.0},
                    {"metric": "METRIC_THREAT_INTELLIGENCE_TRUST", "value": threat_eval.metric_value if threat_eval else 100.0},
                ],
                source_refs=risk_eval.source_references_json if risk_eval else [],
                conf=88.0,
                limitations=["Threat correlation relies on active feed freshness."],
            )

        # RULE 3: Compliance Degradation
        comp_eval = metrics_map.get("METRIC_COMPLIANCE_SCORE")
        if comp_eval and comp_eval.metric_value < 80.0:
            add_insight(
                code="SAI-COMPLIANCE-DEG-001",
                i_type="COMPLIANCE_DEGRADATION",
                severity="MEDIUM",
                title="Compliance Control Effectiveness Deficit",
                description=f"Global compliance posture score ({comp_eval.metric_value}) is below target assurance threshold of 80.0.",
                rule_name="RULE_COMPLIANCE_SCORE_BELOW_THRESHOLD",
                supp_metrics=[{"metric": "METRIC_COMPLIANCE_SCORE", "value": comp_eval.metric_value}],
                source_refs=comp_eval.source_references_json or [],
                conf=95.0,
                limitations=["Grounded in latest security control effectiveness audit records."],
            )

        # RULE 4: Assurance Recovery Positive Milestone
        rec_eval = metrics_map.get("METRIC_RECOVERY_VERIFICATION_RATE")
        if rec_eval and rec_eval.metric_value >= 80.0:
            add_insight(
                code="SAI-ASSURANCE-REC-001",
                i_type="ASSURANCE_RECOVERY",
                severity="INFO",
                title="Assurance Remediation Recovery High Efficacy",
                description=f"Verified recovery rate is {rec_eval.metric_value}%, confirming successful post-incident remediations.",
                rule_name="RULE_RECOVERY_VERIFICATION_HIGH",
                supp_metrics=[{"metric": "METRIC_RECOVERY_VERIFICATION_RATE", "value": rec_eval.metric_value}],
                source_refs=[],
                conf=92.0,
                limitations=["Applies only to closed assurance remediation plans."],
            )

        # RULE 5: Investigation Backlog
        inv_eval = metrics_map.get("METRIC_OPEN_INVESTIGATIONS")
        if inv_eval and inv_eval.metric_value > 2:
            add_insight(
                code="SAI-INV-BACKLOG-001",
                i_type="INVESTIGATION_BACKLOG",
                severity="MEDIUM",
                title="SOC Investigation Queue Growth",
                description=f"{int(inv_eval.metric_value)} open investigation cases currently require analyst triage and dual-control review.",
                rule_name="RULE_OPEN_INVESTIGATIONS_ACCUMULATION",
                supp_metrics=[{"metric": "METRIC_OPEN_INVESTIGATIONS", "value": inv_eval.metric_value}],
                source_refs=inv_eval.source_references_json or [],
                conf=95.0,
                limitations=["Dual-control separation of duties required for all case resolutions."],
            )

        # RULE 6: Telemetry Gap
        if snapshot.telemetry_completeness < 85.0:
            add_insight(
                code="SAI-TELEMETRY-GAP-001",
                i_type="TELEMETRY_GAP",
                severity="MEDIUM",
                title="Telemetry Coverage Deficit Identified",
                description=f"Platform telemetry completeness is at {snapshot.telemetry_completeness}%. Certain domains lack full active telemetry.",
                rule_name="RULE_TELEMETRY_COMPLETENESS_BELOW_THRESHOLD",
                supp_metrics=[{"metric": "TELEMETRY_COMPLETENESS", "value": snapshot.telemetry_completeness}],
                source_refs=[],
                conf=100.0,
                limitations=["Unknown domains reduce analytic confidence score deterministically."],
            )

        db.commit()
        return generated_insights

    @staticmethod
    def get_insights_for_snapshot(db: Session, snapshot_id: str) -> List[SecurityAnalyticsInsight]:
        return db.query(SecurityAnalyticsInsight).filter_by(
            snapshot_id=snapshot_id
        ).order_by(SecurityAnalyticsInsight.created_at.asc()).all()
