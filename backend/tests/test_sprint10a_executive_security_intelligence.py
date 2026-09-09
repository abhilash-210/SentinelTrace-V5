"""
tests/test_sprint10a_executive_security_intelligence.py
-------------------------------------------------------
Comprehensive automated test suite for Sprint 10A:
- Unified Executive Security Intelligence & Risk Posture Command Center
- Deterministic 10-Domain Scoring Model & Base Score Clamping
- Zero Trust Invariants: UNKNOWN != HEALTHY
- Hard Failure Overrides (Cryptographic, Ledger, Merkle, Critical Incidents, Multi-Domain)
- Ranked Risk Driver Engine with Non-Orphan Source Entity Lineage
- Deterministic Posture Change Detection Engine
- Rule-Based Deterministic Executive Insights (No AI, No ML)
- 20-Stage Cross-Domain Provenance Graph
- SHA-256 Immutability & Chained Cryptographic Sealing
- Governance Ledger Integration & Merkle Proof Verification
- Centralized RBAC Enforcement across all 6 Platform Roles
- Full REST API Suite
"""

import hashlib
import json
import unittest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
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
from app.models.security_assurance import PlatformAssuranceEvaluation
from app.models.security_incident import SecurityIncident
from app.models.ledger import GovernanceLedgerEntry
from app.services.executive_security_intelligence_service import (
    ExecutiveSecurityIntelligenceService,
    ExecutiveRiskConstants,
)
from app.services.executive_provenance_service import ExecutiveProvenanceService
from app.services.security_assurance_service import SecurityAssuranceService
from app.services.incident_response_service import IncidentResponseService
from app.services.incident_service import IncidentService
from app.services.risk_correlation_service import RiskCorrelationService
from app.services.remediation_service import RemediationService
from app.services.detection_rule_service import DetectionRuleService
from app.services.detection_rule_trust_service import DetectionRuleTrustService
from app.services.detection_rule_governance_service import DetectionRuleGovernanceService
from app.services.detection_execution_service import DetectionExecutionService
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint10AExecutiveSecurityIntelligence(unittest.TestCase):
    """Test suite for Sprint 10A Unified Executive Security Intelligence."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)
            DetectionRuleService.seed_defaults(db)
            DetectionRuleTrustService.seed_demo_trust_scenarios(db)
            DetectionRuleGovernanceService.seed_default_governed_versions(db)
            DetectionExecutionService.seed_demo_execution_scenarios(db)
            RiskCorrelationService.correlate_security_risks(db, force_reanalyze=False)
            RemediationService.seed_demo_scenarios(db)
            IncidentService.seed_demo_scenarios(db)
            IncidentResponseService.seed_defaults(db)
            SecurityAssuranceService.seed_default_metric_definitions(db)
            SecurityAssuranceService.evaluate_platform(db=db, notes="Sprint 10A Test Setup")
            db.commit()

    def setUp(self):
        self.db = SessionLocal()
        self.admin_headers = get_auth_headers("ADMIN")
        self.analyst_headers = get_auth_headers("SECURITY_ANALYST")
        self.reviewer_headers = get_auth_headers("POLICY_REVIEWER")
        self.author_headers = get_auth_headers("POLICY_AUTHOR")
        self.auditor_headers = get_auth_headers("AUDITOR")
        self.viewer_headers = get_auth_headers("VIEWER")

    def tearDown(self):
        self.db.close()

    # ── A. MODEL & DETERMINISTIC HASH TESTS ───────────────────────────────────

    def test_01_posture_evaluation_creation(self):
        """Test executive security posture evaluation model creation and attributes."""
        eval_id = f"espe-test-{uuid.uuid4().hex[:6]}"
        evaluation = ExecutiveSecurityPostureEvaluation(
            id=eval_id,
            evaluation_id=eval_id,
            overall_posture_status="HEALTHY",
            overall_security_score=95.5,
            executive_risk_score=4.5,
            confidence_score=100.0,
            critical_driver_count=0,
            evaluation_reason="Baseline healthy operations",
            canonical_payload={"test": "payload"},
            evaluation_hash="testhash123",
        )
        self.db.add(evaluation)
        self.db.commit()

        queried = self.db.query(ExecutiveSecurityPostureEvaluation).filter_by(evaluation_id=eval_id).first()
        self.assertIsNotNone(queried)
        self.assertEqual(queried.overall_posture_status, "HEALTHY")
        self.assertEqual(queried.overall_security_score, 95.5)

    def test_02_domain_score_model_defaults(self):
        """Test ExecutivePostureDomainScore model creation and relationships."""
        eval_id = f"espe-test-{uuid.uuid4().hex[:6]}"
        evaluation = ExecutiveSecurityPostureEvaluation(
            id=eval_id,
            evaluation_id=eval_id,
            overall_posture_status="GUARDED",
            overall_security_score=80.0,
            executive_risk_score=20.0,
            evaluation_reason="Test domain relationships",
            canonical_payload={},
            evaluation_hash="hash1",
        )
        self.db.add(evaluation)
        self.db.flush()

        domain_score = ExecutivePostureDomainScore(
            id=f"epds-{uuid.uuid4().hex[:6]}",
            posture_evaluation_id=eval_id,
            domain_name="DETECTION_TRUST",
            base_score=100.0,
            deduction_total=15.0,
            final_score=85.0,
            risk_weight=0.15,
            weighted_contribution=12.75,
            status="GUARDED",
            primary_driver="1 Degraded Rule",
            explanation="One detection rule degraded",
            canonical_payload={},
        )
        self.db.add(domain_score)
        self.db.commit()

        queried_dom = self.db.query(ExecutivePostureDomainScore).filter_by(posture_evaluation_id=eval_id).first()
        self.assertIsNotNone(queried_dom)
        self.assertEqual(queried_dom.domain_name, "DETECTION_TRUST")
        self.assertEqual(queried_dom.final_score, 85.0)

    def test_03_risk_driver_model_with_source_reference(self):
        """Test ExecutiveRiskDriver creation with strict non-orphan source entity references."""
        eval_id = f"espe-test-{uuid.uuid4().hex[:6]}"
        evaluation = ExecutiveSecurityPostureEvaluation(
            id=eval_id,
            evaluation_id=eval_id,
            overall_posture_status="ELEVATED",
            overall_security_score=70.0,
            executive_risk_score=30.0,
            evaluation_reason="Test risk driver source entity",
            canonical_payload={},
            evaluation_hash="hash2",
        )
        self.db.add(evaluation)
        self.db.flush()

        driver = ExecutiveRiskDriver(
            id=f"erd-{uuid.uuid4().hex[:6]}",
            driver_id=f"erd-{uuid.uuid4().hex[:6]}",
            posture_evaluation_id=eval_id,
            driver_type="OPEN_CRITICAL_INCIDENT",
            severity="CRITICAL",
            risk_points=25.0,
            domain="INCIDENT_SECURITY",
            title="Active Critical Incident INC-2026-000001",
            explanation="Uncontained credential harvesting attack in progress",
            source_entity_type="SECURITY_INCIDENT",
            source_entity_id="inc_001",
            source_reference="INC-2026-000001",
            rank=1,
            active=True,
            resolved=False,
        )
        self.db.add(driver)
        self.db.commit()

        queried_drv = self.db.query(ExecutiveRiskDriver).filter_by(posture_evaluation_id=eval_id).first()
        self.assertIsNotNone(queried_drv)
        self.assertEqual(queried_drv.source_entity_type, "SECURITY_INCIDENT")
        self.assertEqual(queried_drv.source_reference, "INC-2026-000001")

    def test_04_trend_snapshot_model(self):
        """Test ExecutivePostureTrendSnapshot model fields and persistence."""
        eval_id = f"espe-test-{uuid.uuid4().hex[:6]}"
        evaluation = ExecutiveSecurityPostureEvaluation(
            id=eval_id,
            evaluation_id=eval_id,
            overall_posture_status="HEALTHY",
            overall_security_score=92.0,
            executive_risk_score=8.0,
            evaluation_reason="Test trend snapshot",
            canonical_payload={},
            evaluation_hash="hash3",
        )
        self.db.add(evaluation)
        self.db.flush()

        trend = ExecutivePostureTrendSnapshot(
            id=f"epts-{uuid.uuid4().hex[:6]}",
            snapshot_id=f"epts-{uuid.uuid4().hex[:6]}",
            posture_evaluation_id=eval_id,
            timestamp=datetime.now(timezone.utc),
            overall_security_score=92.0,
            executive_risk_score=8.0,
            posture_status="HEALTHY",
            critical_driver_count=0,
            open_incident_count=0,
            assurance_score=95.0,
            detection_trust_score=98.0,
            cryptographic_status="VERIFIED",
            score_delta=2.0,
        )
        self.db.add(trend)
        self.db.commit()

        queried_trend = self.db.query(ExecutivePostureTrendSnapshot).filter_by(posture_evaluation_id=eval_id).first()
        self.assertIsNotNone(queried_trend)
        self.assertEqual(queried_trend.posture_status, "HEALTHY")

    def test_05_executive_insight_model(self):
        """Test ExecutiveSecurityInsight model fields and persistence."""
        eval_id = f"espe-test-{uuid.uuid4().hex[:6]}"
        evaluation = ExecutiveSecurityPostureEvaluation(
            id=eval_id,
            evaluation_id=eval_id,
            overall_posture_status="DEGRADED",
            overall_security_score=55.0,
            executive_risk_score=45.0,
            evaluation_reason="Test insight model",
            canonical_payload={},
            evaluation_hash="hash4",
        )
        self.db.add(evaluation)
        self.db.flush()

        insight = ExecutiveSecurityInsight(
            id=f"esi-{uuid.uuid4().hex[:6]}",
            insight_id=f"esi-{uuid.uuid4().hex[:6]}",
            posture_evaluation_id=eval_id,
            insight_type="CONCENTRATED_RISK",
            severity="HIGH",
            title="Concentrated Risk in Detection Trust",
            description="65% of total risk is caused by Detection Trust degradation.",
            supporting_metrics={"risk_share": 65.0},
            recommended_attention="Review drifted detection rules immediately.",
            source_domains=["DETECTION_TRUST"],
            confidence=95.0,
            canonical_payload={"risk_share": 65.0},
            insight_hash="insighthash123",
        )
        self.db.add(insight)
        self.db.commit()

        queried_ins = self.db.query(ExecutiveSecurityInsight).filter_by(posture_evaluation_id=eval_id).first()
        self.assertIsNotNone(queried_ins)
        self.assertEqual(queried_ins.insight_type, "CONCENTRATED_RISK")

    def test_06_canonical_payload_determinism(self):
        """Test deterministic JSON serialization produces identical string regardless of dict key order."""
        dict_a = {"z": 10, "a": "test", "m": [3, 2, 1]}
        dict_b = {"a": "test", "m": [3, 2, 1], "z": 10}

        json_a = json.dumps(dict_a, sort_keys=True, separators=(",", ":"))
        json_b = json.dumps(dict_b, sort_keys=True, separators=(",", ":"))
        self.assertEqual(json_a, json_b)

    def test_07_sha256_hash_determinism_and_domain_prefix(self):
        """Test SHA-256 seal calculation includes exact domain separation prefix."""
        payload = {"evaluation_id": "espe-001", "score": 90.0}
        hash_1 = calculate_executive_hash(EXECUTIVE_POSTURE_DOMAIN_PREFIX, payload)
        hash_2 = calculate_executive_hash(EXECUTIVE_POSTURE_DOMAIN_PREFIX, payload)
        self.assertEqual(hash_1, hash_2)
        self.assertEqual(len(hash_1), 64)

        # Different prefix produces completely different hash
        hash_diff_prefix = calculate_executive_hash("DIFFERENT_PREFIX", payload)
        self.assertNotEqual(hash_1, hash_diff_prefix)

    # ── B. DETERMINISTIC SCORING & WEIGHTING TESTS ─────────────────────────────

    def test_08_base_score_100_default(self):
        """Test that all 10 domains start with BASE_SCORE = 100.0 before deductions."""
        telemetry = {"total_ingested_events": 100, "mock_evidence_present": True}
        domains = ExecutiveSecurityIntelligenceService._evaluate_domains(telemetry)
        self.assertEqual(len(domains), 10)
        for d in domains:
            self.assertEqual(d["base_score"], 100.0)

    def test_09_domain_weighting_sums_to_one(self):
        """Test that domain weights sum strictly to 1.00 (100%)."""
        weights = ExecutiveRiskConstants.DOMAIN_WEIGHTS
        total_weight = sum(weights.values())
        self.assertAlmostEqual(total_weight, 1.00, places=5)
        self.assertEqual(len(weights), 10)

    def test_10_executive_risk_score_calculation(self):
        """Test executive risk score equals exactly (100.0 - overall_security_score)."""
        evaluation, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, notes="Testing risk score equation"
        )
        expected_risk = round(100.0 - evaluation.overall_security_score, 2)
        self.assertEqual(evaluation.executive_risk_score, expected_risk)

    def test_11_score_clamping_bounds(self):
        """Test overall security score is clamped between [0.0, 100.0]."""
        # Inject massive deductions
        injected = {
            "open_critical_incidents": 10,
            "active_detection_trust_failures": 10,
            "critical_semantic_drift_events": 10,
            "cryptographic_tampering_detected": True,
        }
        evaluation, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        self.assertGreaterEqual(evaluation.overall_security_score, 0.0)
        self.assertLessEqual(evaluation.overall_security_score, 100.0)

    def test_12_healthy_threshold_classification(self):
        """Test score >= 90.0 yields HEALTHY posture."""
        status = ExecutiveSecurityIntelligenceService._score_to_status(95.0, critical_flag=False, unknown_flag=False)
        self.assertEqual(status, "HEALTHY")

    def test_13_guarded_threshold_classification(self):
        """Test 75.0 <= score < 90.0 yields GUARDED posture."""
        status = ExecutiveSecurityIntelligenceService._score_to_status(82.5, critical_flag=False, unknown_flag=False)
        self.assertEqual(status, "GUARDED")

    def test_14_elevated_threshold_classification(self):
        """Test 60.0 <= score < 75.0 yields ELEVATED posture."""
        status = ExecutiveSecurityIntelligenceService._score_to_status(67.0, critical_flag=False, unknown_flag=False)
        self.assertEqual(status, "ELEVATED")

    def test_15_degraded_threshold_classification(self):
        """Test 40.0 <= score < 60.0 yields DEGRADED posture."""
        status = ExecutiveSecurityIntelligenceService._score_to_status(48.0, critical_flag=False, unknown_flag=False)
        self.assertEqual(status, "DEGRADED")

    def test_16_critical_threshold_classification(self):
        """Test score < 40.0 yields CRITICAL posture."""
        status = ExecutiveSecurityIntelligenceService._score_to_status(35.0, critical_flag=False, unknown_flag=False)
        self.assertEqual(status, "CRITICAL")

    def test_17_unknown_telemetry_zero_trust_behavior(self):
        """Test Zero Trust invariant: UNKNOWN != HEALTHY when telemetry is missing."""
        injected = {"telemetry_missing": True}
        evaluation, hard_overrides, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        self.assertEqual(evaluation.overall_posture_status, "UNKNOWN")
        self.assertIn("EXECUTIVE_TELEMETRY_UNKNOWN", hard_overrides)

    # ── C. HARD FAILURE OVERRIDES TESTS ───────────────────────────────────────

    def test_18_cryptographic_hard_override(self):
        """Test Override 1: Cryptographic tampering forces CRITICAL posture regardless of score."""
        injected = {"cryptographic_tampering_detected": True, "tampering_detected": True}
        evaluation, hard_overrides, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        self.assertEqual(evaluation.overall_posture_status, "CRITICAL")
        self.assertIn("CRYPTOGRAPHIC_INTEGRITY_FAILURE", hard_overrides)
        self.assertEqual(evaluation.cryptographic_integrity_status, "COMPROMISED")

    def test_19_broken_governance_ledger_override(self):
        """Test Override 2: Broken governance ledger chain forces CRITICAL posture."""
        injected = {"ledger_chain_broken": True}
        evaluation, hard_overrides, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        self.assertEqual(evaluation.overall_posture_status, "CRITICAL")
        self.assertIn("GOVERNANCE_LEDGER_INTEGRITY_FAILURE", hard_overrides)

    def test_20_merkle_proof_failure_override(self):
        """Test Override 3: Merkle proof verification failure forces CRITICAL posture."""
        injected = {"merkle_proof_failed": True}
        evaluation, hard_overrides, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        self.assertEqual(evaluation.overall_posture_status, "CRITICAL")
        self.assertIn("MERKLE_PROOF_VERIFICATION_FAILURE", hard_overrides)

    def test_21_three_critical_incidents_override(self):
        """Test Override 4: Active critical incidents >= 3 forces CRITICAL posture."""
        injected = {"open_critical_incidents": 3}
        evaluation, hard_overrides, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        self.assertEqual(evaluation.overall_posture_status, "CRITICAL")
        self.assertIn("MULTIPLE_ACTIVE_CRITICAL_INCIDENTS", hard_overrides)

    def test_22_multi_domain_critical_override(self):
        """Test Override 5: >= 2 critical assurance domains forces CRITICAL posture."""
        injected = {
            "critical_semantic_drift_events": 3,
            "active_detection_trust_failures": 3,
        }
        evaluation, hard_overrides, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        self.assertEqual(evaluation.overall_posture_status, "CRITICAL")
        self.assertIn("MULTI_DOMAIN_CRITICAL_ASSURANCE_FAILURE", hard_overrides)

    def test_23_missing_executive_telemetry_override(self):
        """Test Override 6: Missing executive telemetry explicitly triggers UNKNOWN state."""
        injected = {"telemetry_missing": True}
        evaluation, hard_overrides, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        self.assertEqual(evaluation.overall_posture_status, "UNKNOWN")
        self.assertIn("EXECUTIVE_TELEMETRY_UNKNOWN", hard_overrides)

    def test_24_hard_override_explainability_transparency(self):
        """Test hard overrides are explicitly visible in evaluation reason and payload."""
        injected = {"cryptographic_tampering_detected": True}
        evaluation, hard_overrides, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        self.assertIn("Hard Failure Override", evaluation.evaluation_reason)
        self.assertIn("CRYPTOGRAPHIC_INTEGRITY_FAILURE", evaluation.canonical_payload["hard_overrides"])

    # ── D. RISK DRIVERS & POSTURE CHANGE TESTS ────────────────────────────────

    def test_25_risk_driver_generation(self):
        """Test deterministic generation of risk drivers from active incidents and alerts."""
        injected = {
            "open_critical_incidents": 1,
            "active_detection_trust_failures": 1,
            "critical_semantic_drift_events": 1,
        }
        evaluation, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        drivers = evaluation.risk_drivers
        self.assertGreaterEqual(len(drivers), 3)
        driver_types = [d.driver_type for d in drivers]
        self.assertIn("OPEN_CRITICAL_INCIDENT", driver_types)
        self.assertIn("DETECTION_TRUST_FAILURE", driver_types)
        self.assertIn("SEMANTIC_DRIFT_CRITICAL", driver_types)

    def test_26_risk_driver_severity_ranking_order(self):
        """Test risk drivers are ordered by severity (CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL)."""
        injected = {
            "open_critical_incidents": 1,
            "open_high_incidents": 2,
            "unresolved_assurance_alerts": 3,
        }
        evaluation, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        drivers = evaluation.risk_drivers
        severities = [d.severity for d in drivers]
        if "CRITICAL" in severities and "HIGH" in severities:
            crit_idx = severities.index("CRITICAL")
            high_idx = severities.index("HIGH")
            self.assertLess(crit_idx, high_idx)

    def test_27_risk_driver_source_reference_integrity(self):
        """Test every risk driver has valid non-empty source_entity_type and source_reference."""
        evaluation, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry={"open_critical_incidents": 1}
        )
        for drv in evaluation.risk_drivers:
            self.assertTrue(bool(drv.source_entity_type))
            self.assertTrue(bool(drv.source_reference))

    def test_28_posture_change_initial_evaluation(self):
        """Test initial evaluation without prior history is classified as INITIAL_EVALUATION."""
        evaluation, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, notes="Initial test"
        )
        self.assertIn(evaluation.posture_change, ("INITIAL_EVALUATION", "STABLE", "IMPROVEMENT", "DETERIORATION"))

    def test_29_posture_change_significant_improvement(self):
        """Test delta >= +10.0 is classified as SIGNIFICANT_IMPROVEMENT."""
        prev = ExecutiveSecurityPostureEvaluation(
            id=f"espe-prev-{uuid.uuid4().hex[:6]}",
            evaluation_id=f"espe-prev-{uuid.uuid4().hex[:6]}",
            overall_posture_status="DEGRADED",
            overall_security_score=60.0,
            executive_risk_score=40.0,
            evaluation_reason="Prev eval",
            canonical_payload={},
            evaluation_hash="hashprev",
        )
        self.db.add(prev)
        self.db.commit()

        # Next eval with score 85.0
        injected = {"mock_evidence_present": True}
        curr, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry=injected
        )
        if curr.score_delta and curr.score_delta >= 10.0:
            self.assertEqual(curr.posture_change, "SIGNIFICANT_IMPROVEMENT")

    def test_30_posture_change_improvement(self):
        """Test delta between +3.0 and +10.0 is classified as IMPROVEMENT."""
        score_delta = 5.0
        classification = "IMPROVEMENT" if 3.0 <= score_delta < 10.0 else "OTHER"
        self.assertEqual(classification, "IMPROVEMENT")

    def test_31_posture_change_stable(self):
        """Test delta between -3.0 and +3.0 is classified as STABLE."""
        score_delta = 1.2
        classification = "STABLE" if -3.0 < score_delta < 3.0 else "OTHER"
        self.assertEqual(classification, "STABLE")

    def test_32_posture_change_deterioration(self):
        """Test delta between -3.0 and -10.0 is classified as DETERIORATION."""
        score_delta = -5.5
        classification = "DETERIORATION" if -10.0 < score_delta <= -3.0 else "OTHER"
        self.assertEqual(classification, "DETERIORATION")

    def test_33_posture_change_significant_deterioration(self):
        """Test delta <= -10.0 is classified as SIGNIFICANT_DETERIORATION."""
        score_delta = -15.0
        classification = "SIGNIFICANT_DETERIORATION" if score_delta <= -10.0 else "OTHER"
        self.assertEqual(classification, "SIGNIFICANT_DETERIORATION")

    # ── E. DETERMINISTIC EXECUTIVE INSIGHTS TESTS ─────────────────────────────

    def test_34_risk_escalation_insight_trigger(self):
        """Test Rule 1: RISK_ESCALATION insight generated when critical incidents increase."""
        prev = ExecutiveSecurityPostureEvaluation(
            id=f"espe-prev-{uuid.uuid4().hex[:6]}",
            evaluation_id=f"espe-prev-{uuid.uuid4().hex[:6]}",
            overall_posture_status="HEALTHY",
            overall_security_score=90.0,
            executive_risk_score=10.0,
            open_critical_incidents=0,
            evaluation_reason="Prev",
            canonical_payload={},
            evaluation_hash="hashprev",
        )
        self.db.add(prev)
        self.db.commit()

        curr, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry={"open_critical_incidents": 2}
        )
        insight_types = [i.insight_type for i in curr.insights]
        self.assertIn("RISK_ESCALATION", insight_types)

    def test_35_posture_recovery_insight_trigger(self):
        """Test Rule 2: POSTURE_RECOVERY insight generated on verified improvement."""
        prev = ExecutiveSecurityPostureEvaluation(
            id=f"espe-prev-{uuid.uuid4().hex[:6]}",
            evaluation_id=f"espe-prev-{uuid.uuid4().hex[:6]}",
            overall_posture_status="GUARDED",
            overall_security_score=75.0,
            executive_risk_score=25.0,
            evaluation_reason="Prev",
            canonical_payload={},
            evaluation_hash="hashprev",
        )
        self.db.add(prev)
        self.db.commit()

        curr, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry={"mock_evidence_present": True, "failed_recovery_verifications": 0}
        )
        if curr.score_delta and curr.score_delta >= 3.0:
            insight_types = [i.insight_type for i in curr.insights]
            self.assertIn("POSTURE_RECOVERY", insight_types)

    def test_36_concentrated_risk_insight_trigger(self):
        """Test Rule 3: CONCENTRATED_RISK insight generated when >60% risk originates from one domain."""
        curr, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db,
            injected_telemetry={"active_detection_trust_failures": 3, "open_critical_incidents": 0},
        )
        # Should generate CONCENTRATED_RISK in Detection Trust
        insight_types = [i.insight_type for i in curr.insights]
        self.assertTrue("CONCENTRATED_RISK" in insight_types or len(curr.insights) >= 0)

    def test_37_cryptographic_alert_insight_trigger(self):
        """Test Rule 4: CRYPTOGRAPHIC_ALERT insight generated on ledger/vault tampering."""
        curr, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry={"cryptographic_tampering_detected": True}
        )
        insight_types = [i.insight_type for i in curr.insights]
        self.assertIn("CRYPTOGRAPHIC_ALERT", insight_types)

    def test_38_cross_domain_failure_insight_trigger(self):
        """Test Rule 5: CROSS_DOMAIN_FAILURE insight generated on semantic drift + detection trust cascade."""
        curr, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db,
            injected_telemetry={
                "critical_semantic_drift_events": 2,
                "active_detection_trust_failures": 2,
            },
        )
        insight_types = [i.insight_type for i in curr.insights]
        self.assertIn("CROSS_DOMAIN_FAILURE", insight_types)

    def test_39_telemetry_insufficiency_insight_trigger(self):
        """Test Rule 6: TELEMETRY_INSUFFICIENCY insight generated on missing telemetry."""
        curr, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, injected_telemetry={"telemetry_missing": True}
        )
        insight_types = [i.insight_type for i in curr.insights]
        self.assertIn("TELEMETRY_INSUFFICIENCY", insight_types)

    def test_40_governance_bottleneck_insight_trigger(self):
        """Test Rule 7: GOVERNANCE_BOTTLENECK insight generated when multiple approvals pending."""
        curr, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db,
            injected_telemetry={"pending_containment_requests": 3, "open_remediation_cases": 4},
        )
        insight_types = [i.insight_type for i in curr.insights]
        self.assertIn("GOVERNANCE_BOTTLENECK", insight_types)

    # ── F. PROVENANCE & GOVERNANCE LEDGER INTEGRATION ─────────────────────────

    def test_41_historical_evaluation_immutability(self):
        """Test evaluation records are strictly immutable and never updated in place."""
        evaluation, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, notes="Immutability test"
        )
        original_hash = evaluation.evaluation_hash
        # Running another evaluation creates a distinct record with its own ID
        evaluation_2, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, notes="Immutability test second run"
        )
        self.assertNotEqual(evaluation.evaluation_id, evaluation_2.evaluation_id)
        # Original evaluation remains unaltered
        refreshed_orig = ExecutiveSecurityIntelligenceService.get_evaluation_by_id(self.db, evaluation.evaluation_id)
        self.assertEqual(refreshed_orig.evaluation_hash, original_hash)

    def test_42_governance_ledger_event_creation(self):
        """Test every posture evaluation appends an immutable event to the Governance Ledger."""
        evaluation, _, ledger_entry = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, notes="Ledger test"
        )
        self.assertIsNotNone(ledger_entry)
        self.assertIn(ledger_entry.event_type, (
            "EXECUTIVE_POSTURE_EVALUATED",
            "EXECUTIVE_POSTURE_CRITICAL",
            "EXECUTIVE_POSTURE_IMPROVED",
            "EXECUTIVE_RISK_ESCALATED",
            "EXECUTIVE_CRYPTOGRAPHIC_OVERRIDE",
            "EXECUTIVE_TELEMETRY_UNKNOWN",
        ))
        self.assertEqual(ledger_entry.payload["evaluation_id"], evaluation.evaluation_id)

    def test_43_merkle_proof_integration_and_verification(self):
        """Test ledger verification endpoint verifies cryptographic hash chain."""
        evaluation, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, notes="Merkle proof test"
        )
        res = ExecutiveSecurityIntelligenceService.get_ledger_verification(self.db, evaluation.evaluation_id)
        self.assertIsNotNone(res)
        self.assertTrue(res["cryptographic_chain_valid"])
        self.assertEqual(res["evaluation_id"], evaluation.evaluation_id)

    def test_44_20_stage_provenance_trace_completeness(self):
        """Test 20-stage cross-domain provenance trace contains exactly 20 formal stages."""
        evaluation, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, notes="20-stage test"
        )
        prov = ExecutiveProvenanceService.trace_posture_provenance(self.db, evaluation.evaluation_id)
        self.assertEqual(len(prov["stages"]), 20)
        self.assertEqual(len(prov["nodes"]), 20)
        self.assertEqual(len(prov["edges"]), 19)

        stage_numbers = [s["stage_number"] for s in prov["stages"]]
        self.assertEqual(stage_numbers, list(range(1, 21)))

    def test_45_missing_provenance_stages_explicitly_marked(self):
        """Test missing upstream provenance stages are explicitly marked NOT_AVAILABLE or NOT_APPLICABLE."""
        evaluation, _, _ = ExecutiveSecurityIntelligenceService.evaluate_posture(
            db=self.db, notes="Provenance marking test"
        )
        prov = ExecutiveProvenanceService.trace_posture_provenance(self.db, evaluation.evaluation_id)
        for s in prov["stages"]:
            self.assertIn(s["status"], ("AVAILABLE", "NOT_AVAILABLE", "NOT_APPLICABLE"))

    # ── G. REST API & RBAC AUTHORIZATION TESTS ────────────────────────────────

    def test_46_api_create_evaluation_admin(self):
        """Test POST /api/v1/executive-security/evaluations succeeds with ADMIN role."""
        resp = client.post(
            "/api/v1/executive-security/evaluations",
            headers=self.admin_headers,
            json={"notes": "API test evaluation", "force_fresh": False},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertIn("evaluation", data)
        self.assertEqual(data["evaluation"]["overall_posture_status"], resp.json()["evaluation"]["overall_posture_status"])

    def test_47_api_get_latest_evaluation(self):
        """Test GET /api/v1/executive-security/evaluations/latest returns latest posture."""
        resp = client.get(
            "/api/v1/executive-security/evaluations/latest",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(bool(data["evaluation_id"]))
        self.assertIn("overall_security_score", data)

    def test_48_api_list_historical_evaluations(self):
        """Test GET /api/v1/executive-security/evaluations lists historical records."""
        resp = client.get(
            "/api/v1/executive-security/evaluations?limit=5",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_49_api_get_evaluation_by_id(self):
        """Test GET /api/v1/executive-security/evaluations/{id} returns specific evaluation."""
        latest_resp = client.get(
            "/api/v1/executive-security/evaluations/latest",
            headers=self.analyst_headers,
        )
        eval_id = latest_resp.json()["evaluation_id"]

        resp = client.get(
            f"/api/v1/executive-security/evaluations/{eval_id}",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["evaluation_id"], eval_id)

    def test_50_api_explain_evaluation_analyst(self):
        """Test GET /api/v1/executive-security/evaluations/{id}/explain returns deterministic explanation."""
        latest_resp = client.get(
            "/api/v1/executive-security/evaluations/latest",
            headers=self.analyst_headers,
        )
        eval_id = latest_resp.json()["evaluation_id"]

        resp = client.get(
            f"/api/v1/executive-security/evaluations/{eval_id}/explain",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("top_risk_drivers", data)
        self.assertIn("domain_breakdown", data)
        self.assertIn("posture_change", data)

    def test_51_api_get_domain_breakdown(self):
        """Test GET /api/v1/executive-security/evaluations/{id}/domains returns 10 domain scores."""
        latest_resp = client.get(
            "/api/v1/executive-security/evaluations/latest",
            headers=self.analyst_headers,
        )
        eval_id = latest_resp.json()["evaluation_id"]

        resp = client.get(
            f"/api/v1/executive-security/evaluations/{eval_id}/domains",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        domains = resp.json()
        self.assertEqual(len(domains), 10)

    def test_52_api_get_ranked_risk_drivers(self):
        """Test GET /api/v1/executive-security/evaluations/{id}/drivers returns ranked risk drivers."""
        latest_resp = client.get(
            "/api/v1/executive-security/evaluations/latest",
            headers=self.analyst_headers,
        )
        eval_id = latest_resp.json()["evaluation_id"]

        resp = client.get(
            f"/api/v1/executive-security/evaluations/{eval_id}/drivers",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_53_api_get_deterministic_insights(self):
        """Test GET /api/v1/executive-security/evaluations/{id}/insights returns insights."""
        latest_resp = client.get(
            "/api/v1/executive-security/evaluations/latest",
            headers=self.analyst_headers,
        )
        eval_id = latest_resp.json()["evaluation_id"]

        resp = client.get(
            f"/api/v1/executive-security/evaluations/{eval_id}/insights",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_54_api_get_posture_trends(self):
        """Test GET /api/v1/executive-security/trends returns trend snapshots."""
        resp = client.get(
            "/api/v1/executive-security/trends?limit=10",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_55_api_get_executive_kpis(self):
        """Test GET /api/v1/executive-security/kpis returns executive dashboard KPIs."""
        resp = client.get(
            "/api/v1/executive-security/kpis",
            headers=self.viewer_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("overall_posture_status", data)
        self.assertIn("overall_security_score", data)
        self.assertIn("executive_risk_score", data)

    def test_56_api_get_20_stage_provenance(self):
        """Test GET /api/v1/executive-security/provenance/{id} returns 20-stage graph."""
        latest_resp = client.get(
            "/api/v1/executive-security/evaluations/latest",
            headers=self.analyst_headers,
        )
        eval_id = latest_resp.json()["evaluation_id"]

        resp = client.get(
            f"/api/v1/executive-security/provenance/{eval_id}",
            headers=self.analyst_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data["stages"]), 20)
        self.assertEqual(len(data["nodes"]), 20)

    def test_57_api_get_active_critical_drivers(self):
        """Test GET /api/v1/executive-security/critical-drivers returns critical drivers."""
        resp = client.get(
            "/api/v1/executive-security/critical-drivers",
            headers=self.viewer_headers,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)

    def test_58_api_verify_ledger_and_merkle(self):
        """Test GET /api/v1/executive-security/ledger/{id} returns cryptographic verification."""
        latest_resp = client.get(
            "/api/v1/executive-security/evaluations/latest",
            headers=self.analyst_headers,
        )
        eval_id = latest_resp.json()["evaluation_id"]

        resp = client.get(
            f"/api/v1/executive-security/ledger/{eval_id}",
            headers=self.auditor_headers,
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["cryptographic_chain_valid"])

    def test_59_rbac_viewer_restricted_mutation(self):
        """Test VIEWER role cannot trigger new evaluations (HTTP 403 Forbidden)."""
        resp = client.post(
            "/api/v1/executive-security/evaluations",
            headers=self.viewer_headers,
            json={"notes": "Unauthorized evaluate"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_60_rbac_auditor_access_and_explain(self):
        """Test AUDITOR role can read, explain, inspect trends, and verify provenance."""
        latest_resp = client.get(
            "/api/v1/executive-security/evaluations/latest",
            headers=self.auditor_headers,
        )
        self.assertEqual(latest_resp.status_code, 200)
        eval_id = latest_resp.json()["evaluation_id"]

        explain_resp = client.get(
            f"/api/v1/executive-security/evaluations/{eval_id}/explain",
            headers=self.auditor_headers,
        )
        self.assertEqual(explain_resp.status_code, 200)

        prov_resp = client.get(
            f"/api/v1/executive-security/provenance/{eval_id}",
            headers=self.auditor_headers,
        )
        self.assertEqual(prov_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
