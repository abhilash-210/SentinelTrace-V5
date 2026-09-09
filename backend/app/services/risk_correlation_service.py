"""
services/risk_correlation_service.py
------------------------------------
Service for Deterministic Security Posture Risk Correlation, Concentration Analysis & Graph Construction.

Sprint 7B — Security Posture Risk Correlation, Prioritized Remediation & Executive Risk Intelligence.
Deterministically connects semantic drift alerts, detection trust alerts, rule trust evaluations,
and protected semantic fields into auditable risk chains and concentration clusters.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.risk_correlation import RiskCorrelation, RiskCorrelationMember
from app.models.semantic_interpretation import SemanticDriftAlert, SemanticInterpretation
from app.models.detection_rule_trust import DetectionRuleTrustEvaluation, DetectionTrustAlert
from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.models.semantic_policy import ProtectedSemanticField
from app.models.normalized_event import NormalizedEvent
from app.models.event import IngestedEvent

logger = logging.getLogger("sentinel.services.risk_correlation")


class RiskCorrelationService:
    """
    Deterministic Risk Correlation and Concentration Analysis Engine.
    """

    @staticmethod
    def correlate_security_risks(
        db: Session,
        force_reanalyze: bool = False,
    ) -> List[RiskCorrelation]:
        """
        Scans all platform security telemetry, drift alerts, trust evaluations,
        and dependency mappings to generate deterministic risk correlations.
        """
        if force_reanalyze:
            logger.info("Force re-analyze requested. Clearing active automated risk correlations...")
            # Remove existing correlations
            db.query(RiskCorrelationMember).delete(synchronize_session=False)
            db.query(RiskCorrelation).delete(synchronize_session=False)
            db.commit()

        existing_corrs = db.query(RiskCorrelation).all()
        if existing_corrs and not force_reanalyze:
            logger.info(f"Returning {len(existing_corrs)} existing risk correlations.")
            return existing_corrs

        # 1. Fetch relevant signals from database
        drift_alerts = db.query(SemanticDriftAlert).filter(SemanticDriftAlert.status == "OPEN").all()
        trust_alerts = db.query(DetectionTrustAlert).filter(DetectionTrustAlert.status == "OPEN").all()
        trust_evals = db.query(DetectionRuleTrustEvaluation).order_by(desc(DetectionRuleTrustEvaluation.created_at)).all()
        protected_fields = {pf.field_name for pf in db.query(ProtectedSemanticField).all()}
        # Add default protected fields if table empty
        if not protected_fields:
            protected_fields = {"action.result", "severity", "authentication.outcome"}

        dependencies = db.query(DetectionRuleDependency).all()
        rules = {r.rule_id: r for r in db.query(DetectionRule).all()}

        # Map dependencies by canonical field
        field_to_rules: Dict[str, Set[str]] = {}
        for dep in dependencies:
            field_to_rules.setdefault(dep.canonical_field, set()).add(dep.rule_id)

        # Helper to extract canonical field safely from drift alert
        def _get_drift_canonical_field(da: SemanticDriftAlert) -> str:
            if da.interpretation and da.interpretation.canonical_field:
                return da.interpretation.canonical_field
            if hasattr(da, "canonical_field") and da.canonical_field:
                return da.canonical_field
            return "action.result"

        # Map drift alerts by canonical field
        field_to_drift_alerts: Dict[str, List[SemanticDriftAlert]] = {}
        for da in drift_alerts:
            c_field = _get_drift_canonical_field(da)
            field_to_drift_alerts.setdefault(c_field, []).append(da)

        # Map trust evaluations by rule_id (keep latest)
        latest_eval_by_rule: Dict[str, DetectionRuleTrustEvaluation] = {}
        for ev in trust_evals:
            if ev.rule_id not in latest_eval_by_rule:
                latest_eval_by_rule[ev.rule_id] = ev

        created_correlations: List[RiskCorrelation] = []

        # 2. Correlate by Canonical Field & Dependency Chains
        # We look at fields that have drift alerts OR trust degradation on dependent rules
        all_candidate_fields = set(field_to_drift_alerts.keys()) | set(field_to_rules.keys())

        for canonical_field in sorted(all_candidate_fields):
            da_list = field_to_drift_alerts.get(canonical_field, [])
            dep_rule_ids = field_to_rules.get(canonical_field, set())
            is_protected = canonical_field in protected_fields

            # Identify affected rules and their trust states
            affected_rules_data = []
            has_invalid_rule = False
            has_at_risk_rule = False
            has_degraded_rule = False

            for rid in sorted(dep_rule_ids):
                rule_obj = rules.get(rid)
                ev = latest_eval_by_rule.get(rid)
                trust_status = ev.trust_status if ev else "UNKNOWN"
                if trust_status == "INVALID":
                    has_invalid_rule = True
                elif trust_status == "AT_RISK":
                    has_at_risk_rule = True
                elif trust_status == "DEGRADED":
                    has_degraded_rule = True

                affected_rules_data.append({
                    "rule_id": rid,
                    "rule_name": rule_obj.rule_name if rule_obj else rid,
                    "trust_status": trust_status,
                    "trust_score": ev.trust_score if ev else 1.0,
                })

            # Check if this field has enough signals to warrant a correlation
            if not da_list and not (has_invalid_rule or has_at_risk_rule or has_degraded_rule):
                continue

            # Determine correlation type and severity
            if is_protected and (has_invalid_rule or len(affected_rules_data) > 1 or len(da_list) > 0):
                corr_type = "CRITICAL_RISK_CLUSTER" if len(affected_rules_data) > 1 else "PROTECTED_FIELD_CHAIN"
                severity = "CRITICAL"
                base_risk = 92.0 if has_invalid_rule else 85.0
            elif has_invalid_rule or has_at_risk_rule:
                corr_type = "TRUST_DEGRADATION_CHAIN"
                severity = "HIGH"
                base_risk = 75.0
            elif len(dep_rule_ids) > 1:
                corr_type = "DEPENDENCY_CHAIN"
                severity = "MEDIUM"
                base_risk = 55.0
            else:
                corr_type = "SINGLE_SIGNAL"
                severity = "LOW" if not is_protected else "MEDIUM"
                base_risk = 35.0

            # Calculate deterministic risk score
            risk_score = min(100.0, base_risk + (len(da_list) * 4.0) + (len(affected_rules_data) * 3.0))

            # Compile root cause candidates
            root_causes = []
            for da in da_list:
                c_f = _get_drift_canonical_field(da)
                root_causes.append({
                    "candidate_type": "SEMANTIC_DRIFT_ALERT",
                    "alert_id": da.alert_id,
                    "canonical_field": c_f,
                    "description": f"Vendor semantic drift: '{da.observed_value}' mapped to '{da.expected_value}'",
                })
            if not root_causes and (has_invalid_rule or has_at_risk_rule):
                root_causes.append({
                    "candidate_type": "DETECTION_TRUST_DEGRADATION",
                    "canonical_field": canonical_field,
                    "description": f"Trust degradation on dependent rules for field '{canonical_field}'",
                })

            # Build explainable text
            explanation = (
                f"Concentrated risk chain detected around canonical field '{canonical_field}'. "
                f"Protected Field: {'YES' if is_protected else 'NO'}. "
                f"Active Drift Alerts: {len(da_list)}. "
                f"Dependent Rules: {len(affected_rules_data)} "
                f"({sum(1 for r in affected_rules_data if r['trust_status'] in ('INVALID', 'AT_RISK'))} at-risk/invalid). "
                f"Correlation classification: {corr_type} ({severity})."
            )

            corr_id = f"rcorr_{uuid.uuid4().hex[:12]}"
            cluster_key = f"cluster_{canonical_field}"

            correlation = RiskCorrelation(
                correlation_id=corr_id,
                correlation_type=corr_type,
                severity=severity,
                status="ACTIVE",
                risk_cluster_key=cluster_key,
                affected_signal_count=len(da_list) + len(affected_rules_data),
                affected_rule_count=len(affected_rules_data),
                affected_field_count=1,
                risk_score=risk_score,
                root_cause_candidates=root_causes,
                explanation=explanation,
                created_at=datetime.now(timezone.utc),
            )
            db.add(correlation)
            db.flush()

            # Add member associations
            # 1. Field Member
            db.add(RiskCorrelationMember(
                correlation_id=corr_id,
                member_type="PROTECTED_FIELD" if is_protected else "CANONICAL_FIELD",
                member_id=canonical_field,
                relationship_type="DIRECT_DEPENDENCY",
            ))

            # 2. Drift Alert Members
            for da in da_list:
                db.add(RiskCorrelationMember(
                    correlation_id=corr_id,
                    member_type="SEMANTIC_DRIFT_ALERT",
                    member_id=da.alert_id,
                    relationship_type="ROOT_CAUSE_CANDIDATE",
                ))

            # 3. Detection Rule Members
            for rdata in affected_rules_data:
                db.add(RiskCorrelationMember(
                    correlation_id=corr_id,
                    member_type="DETECTION_RULE",
                    member_id=rdata["rule_id"],
                    relationship_type="DOWNSTREAM_IMPACT",
                ))

            created_correlations.append(correlation)

        # 3. If no correlations created (clean state), create fallback baseline correlations for isolated drift/trust alerts
        if not created_correlations:
            for da in drift_alerts:
                c_field = _get_drift_canonical_field(da)
                corr_id = f"rcorr_{uuid.uuid4().hex[:12]}"
                corr = RiskCorrelation(
                    correlation_id=corr_id,
                    correlation_type="SINGLE_SIGNAL",
                    severity="LOW",
                    status="ACTIVE",
                    risk_cluster_key=f"cluster_{c_field}",
                    affected_signal_count=1,
                    affected_rule_count=0,
                    affected_field_count=1,
                    risk_score=25.0,
                    root_cause_candidates=[{
                        "candidate_type": "SEMANTIC_DRIFT_ALERT",
                        "alert_id": da.alert_id,
                        "canonical_field": c_field,
                        "description": f"Isolated drift alert on {c_field}",
                    }],
                    explanation=f"Isolated semantic drift alert on canonical field '{c_field}'.",
                    created_at=datetime.now(timezone.utc),
                )
                db.add(corr)
                db.flush()
                db.add(RiskCorrelationMember(
                    correlation_id=corr_id,
                    member_type="SEMANTIC_DRIFT_ALERT",
                    member_id=da.alert_id,
                    relationship_type="ROOT_CAUSE_CANDIDATE",
                ))
                created_correlations.append(corr)

        db.commit()
        logger.info(f"Generated {len(created_correlations)} risk correlations.")
        return created_correlations

    @staticmethod
    def detect_risk_clusters(db: Session) -> List[Dict[str, Any]]:
        """
        Aggregates risk correlations into concentration clusters centered around shared canonical fields or vendors.
        """
        correlations = db.query(RiskCorrelation).filter(RiskCorrelation.status == "ACTIVE").all()
        clusters_map: Dict[str, Dict[str, Any]] = {}

        for corr in correlations:
            key = corr.risk_cluster_key or f"cluster_{corr.correlation_id}"
            center = key.replace("cluster_", "")
            is_protected = center in ("action.result", "severity", "authentication.outcome")

            if key not in clusters_map:
                clusters_map[key] = {
                    "cluster_key": key,
                    "cluster_center": center,
                    "severity": corr.severity,
                    "concentration_score": corr.risk_score,
                    "is_protected_field": is_protected,
                    "affected_rule_count": corr.affected_rule_count,
                    "affected_signal_count": corr.affected_signal_count,
                    "affected_correlations": [corr.correlation_id],
                    "connected_signals": [],
                    "explanation": (
                        f"Risk concentration cluster centered on '{center}'. "
                        f"Aggregates {corr.affected_rule_count} dependent rules and "
                        f"{corr.affected_signal_count} security signals."
                    ),
                }
            else:
                c = clusters_map[key]
                c["concentration_score"] = max(c["concentration_score"], corr.risk_score)
                c["affected_rule_count"] += corr.affected_rule_count
                c["affected_signal_count"] += corr.affected_signal_count
                c["affected_correlations"].append(corr.correlation_id)
                if corr.severity == "CRITICAL":
                    c["severity"] = "CRITICAL"

            # Populate connected signals from members
            for m in corr.members:
                clusters_map[key]["connected_signals"].append({
                    "member_type": m.member_type,
                    "member_id": m.member_id,
                    "relationship_type": m.relationship_type,
                })

        return sorted(list(clusters_map.values()), key=lambda x: x["concentration_score"], reverse=True)

    @staticmethod
    def build_correlation_graph(db: Session, correlation_id: str) -> Dict[str, Any]:
        """
        Builds a directed acyclic graph (DAG) representing the complete root-cause and downstream
        impact chain for a risk correlation.
        """
        corr = db.query(RiskCorrelation).filter(RiskCorrelation.correlation_id == correlation_id).first()
        if not corr:
            return {"correlation_id": correlation_id, "correlation_type": "UNKNOWN", "severity": "NONE", "nodes": [], "edges": [], "root_cause_candidates": []}

        nodes = []
        edges = []
        node_ids_seen = set()

        # 1. Main Correlation Node
        corr_node_id = f"node_{corr.correlation_id}"
        nodes.append({
            "id": corr_node_id,
            "label": f"Risk Correlation: {corr.correlation_type}",
            "node_type": "RISK_CORRELATION",
            "severity": corr.severity,
            "status": corr.status,
            "data": {
                "risk_score": corr.risk_score,
                "cluster_key": corr.risk_cluster_key,
                "affected_rules": corr.affected_rule_count,
            },
        })
        node_ids_seen.add(corr_node_id)

        # 2. Add members and build causal links
        drift_node_ids = []
        field_node_ids = []
        rule_node_ids = []

        for member in corr.members:
            m_node_id = f"node_{member.member_type}_{member.member_id}"
            if m_node_id not in node_ids_seen:
                nodes.append({
                    "id": m_node_id,
                    "label": f"{member.member_type.replace('_', ' ').title()}: {member.member_id}",
                    "node_type": member.member_type,
                    "severity": corr.severity if member.member_type in ("PROTECTED_FIELD", "SEMANTIC_DRIFT_ALERT") else "MEDIUM",
                    "status": "ACTIVE",
                    "data": {
                        "relationship_type": member.relationship_type,
                        "member_id": member.member_id,
                    },
                })
                node_ids_seen.add(m_node_id)

            if member.member_type == "SEMANTIC_DRIFT_ALERT":
                drift_node_ids.append(m_node_id)
            elif member.member_type in ("CANONICAL_FIELD", "PROTECTED_FIELD"):
                field_node_ids.append(m_node_id)
            elif member.member_type == "DETECTION_RULE":
                rule_node_ids.append(m_node_id)

        # 3. Create Edges
        # Drift Alert -> Protected/Canonical Field (DEGRADES / AFFECTS)
        for d_id in drift_node_ids:
            for f_id in field_node_ids:
                edges.append({
                    "source": d_id,
                    "target": f_id,
                    "relationship": "DEGRADES",
                    "label": "Semantic Drift",
                })

        # Field -> Detection Rule (DEPENDS_ON / DOWNSTREAM_IMPACT)
        for f_id in field_node_ids:
            for r_id in rule_node_ids:
                edges.append({
                    "source": f_id,
                    "target": r_id,
                    "relationship": "DOWNSTREAM_IMPACT",
                    "label": "Rule Dependency",
                })

        # Detection Rule / Field -> Risk Correlation (CONTRIBUTES_TO / TRIGGERS)
        for r_id in rule_node_ids:
            edges.append({
                "source": r_id,
                "target": corr_node_id,
                "relationship": "CONTRIBUTES_TO",
                "label": "Risk Factor",
            })
        for f_id in field_node_ids:
            if not rule_node_ids:
                edges.append({
                    "source": f_id,
                    "target": corr_node_id,
                    "relationship": "TRIGGERS",
                    "label": "Field Risk",
                })

        root_causes = [rc.get("alert_id") or rc.get("canonical_field") for rc in (corr.root_cause_candidates or []) if isinstance(rc, dict)]

        return {
            "correlation_id": corr.correlation_id,
            "correlation_type": corr.correlation_type,
            "severity": corr.severity,
            "nodes": nodes,
            "edges": edges,
            "root_cause_candidates": [rc for rc in root_causes if rc],
        }

    @staticmethod
    def get_correlation_by_id(db: Session, correlation_id: str) -> Optional[RiskCorrelation]:
        return db.query(RiskCorrelation).filter(RiskCorrelation.correlation_id == correlation_id).first()

    @staticmethod
    def list_correlations(
        db: Session,
        severity: Optional[str] = None,
        correlation_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[RiskCorrelation]:
        query = db.query(RiskCorrelation)
        if severity:
            query = query.filter(RiskCorrelation.severity == severity.upper())
        if correlation_type:
            query = query.filter(RiskCorrelation.correlation_type == correlation_type.upper())
        if status:
            query = query.filter(RiskCorrelation.status == status.upper())
        return query.order_by(desc(RiskCorrelation.risk_score)).all()
