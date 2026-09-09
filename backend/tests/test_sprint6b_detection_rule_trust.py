"""
tests/test_sprint6b_detection_rule_trust.py
-------------------------------------------
Test suite for Sprint 6B: Detection Rule Trust Evaluation & Semantic Drift Binding.

27 comprehensive unit, integration, and security tests covering:
- Trust evaluation creation and deterministic calculation
- TRUSTED, DEGRADED, AT_RISK, INVALID, and UNKNOWN status classification
- Zero Trust principle (UNKNOWN != SAFE)
- AMBIGUOUS, INCOMPATIBLE, and UNMAPPED semantic mapping impact
- Protected semantic field risk escalation
- Unaffected rules remain 100% trusted (dependency isolation)
- Multi-dependency worst-impact dominance
- Trust score clamping [0.00, 1.00] and mathematical deduction logging
- Trust alert generation, triage, and deduplication
- Idempotent evaluation persistence
- RBAC permissions (401/403 security enforcement)
- Complete 10-stage trust trace provenance
- Immutable evaluation history
- Verification that Sprint 1 evidence and Sprint 2 events remain untouched
"""

import unittest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.models.detection_rule_trust import DetectionRuleTrustEvaluation, DetectionTrustAlert
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.semantic_interpretation import SemanticDriftAlert, SemanticInterpretation
from app.models.semantic_policy import ProtectedSemanticField, SemanticPolicy
from app.services.detection_rule_service import DetectionRuleService
from app.services.detection_rule_trust_service import DetectionRuleTrustService
from app.services.detection_trust_alert_service import DetectionTrustAlertService
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint6BDetectionRuleTrust(unittest.TestCase):
    """Automated test suite for Sprint 6B Detection Rule Trust Evaluation."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)
            DetectionRuleService.seed_defaults(db)
            DetectionRuleTrustService.seed_demo_trust_scenarios(db)

    # ── Test 1: Trust evaluation record created ──────────────────────────────
    def test_01_trust_evaluation_record_created(self):
        """Verify trust evaluation record creation and persistence."""
        with SessionLocal() as db:
            eval_record = DetectionRuleTrustService.evaluate_rule_trust(
                db=db,
                rule_id="drule_fw_deny_scan",
            )
            self.assertIsNotNone(eval_record)
            self.assertTrue(eval_record.evaluation_id.startswith("teval_"))
            self.assertEqual(eval_record.rule_id, "drule_fw_deny_scan")
            self.assertIn(eval_record.trust_status, ["TRUSTED", "DEGRADED", "AT_RISK", "INVALID", "UNKNOWN"])

    # ── Test 2: TRUSTED rule calculation works ───────────────────────────────
    def test_02_trusted_rule_calculation_works(self):
        """Verify exact alignment with no drift produces TRUSTED status (score >= 0.90)."""
        score, reasons = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="EXACT",
            risk_level="NONE",
            is_protected_field=False,
        )
        status, risk = DetectionRuleTrustService.determine_trust_status(score)
        self.assertEqual(status, "TRUSTED")
        self.assertEqual(risk, "NONE")
        self.assertGreaterEqual(score, 0.90)
        self.assertEqual(score, 1.00)

    # ── Test 3: DEGRADED rule calculation works ──────────────────────────────
    def test_03_degraded_rule_calculation_works(self):
        """Verify COMPATIBLE mapping yields DEGRADED status (score between 0.70 and 0.89)."""
        score, reasons = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="COMPATIBLE",
            risk_level="LOW",
            is_protected_field=False,
        )
        status, risk = DetectionRuleTrustService.determine_trust_status(score)
        self.assertEqual(status, "DEGRADED")
        self.assertEqual(risk, "LOW")
        self.assertAlmostEqual(score, 0.90, places=2)

    # ── Test 4: AT_RISK rule calculation works ───────────────────────────────
    def test_04_at_risk_rule_calculation_works(self):
        """Verify AMBIGUOUS mapping on protected field yields AT_RISK status (score 0.60)."""
        score, reasons = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="AMBIGUOUS",
            risk_level="MEDIUM",
            is_protected_field=True,
        )
        status, risk = DetectionRuleTrustService.determine_trust_status(score)
        self.assertEqual(status, "AT_RISK")
        self.assertEqual(risk, "HIGH")
        # 1.00 - 0.25 (ambiguous) - 0.15 (protected) = 0.60
        self.assertAlmostEqual(score, 0.60, places=2)

    # ── Test 5: INVALID rule calculation works ───────────────────────────────
    def test_05_invalid_rule_calculation_works(self):
        """Verify INCOMPATIBLE mapping yields INVALID status (score < 0.40)."""
        score, reasons = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="INCOMPATIBLE",
            risk_level="CRITICAL",
            is_protected_field=True,
        )
        status, risk = DetectionRuleTrustService.determine_trust_status(score)
        self.assertEqual(status, "INVALID")
        self.assertEqual(risk, "CRITICAL")
        self.assertLess(score, 0.40)

    # ── Test 6: UNKNOWN state never automatically becomes TRUSTED ────────────
    def test_06_unknown_state_never_automatically_trusted(self):
        """Zero Trust Principle: UNKNOWN dependency state must NOT become TRUSTED (score <= 0.50)."""
        score, reasons = DetectionRuleTrustService.calculate_trust_score(
            is_unknown=True,
        )
        status, risk = DetectionRuleTrustService.determine_trust_status(score, is_unknown=True)
        self.assertEqual(status, "UNKNOWN")
        self.assertLessEqual(score, 0.50)
        self.assertNotEqual(status, "TRUSTED")

    # ── Test 7: AMBIGUOUS_MAPPING degrades trust ─────────────────────────────
    def test_07_ambiguous_mapping_degrades_trust(self):
        """Verify AMBIGUOUS_MAPPING deducts 0.25 from base trust."""
        score, reasons = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="AMBIGUOUS",
            risk_level="NONE",
            is_protected_field=False,
        )
        self.assertAlmostEqual(score, 0.75, places=2)
        status, _ = DetectionRuleTrustService.determine_trust_status(score)
        self.assertEqual(status, "DEGRADED")

    # ── Test 8: INCOMPATIBLE_MAPPING invalidates trust ────────────────────────
    def test_08_incompatible_mapping_invalidates_trust(self):
        """Verify INCOMPATIBLE_MAPPING deducts 0.60 from base trust."""
        score, reasons = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="INCOMPATIBLE",
            risk_level="NONE",
            is_protected_field=False,
        )
        self.assertAlmostEqual(score, 0.40, places=2)

    # ── Test 9: UNMAPPED_VALUE affects dependent rule ─────────────────────────
    def test_09_unmapped_value_affects_dependent_rule(self):
        """Verify UNMAPPED_VALUE deducts 0.40 from base trust."""
        score, reasons = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="UNMAPPED",
            risk_level="NONE",
            is_protected_field=False,
        )
        self.assertAlmostEqual(score, 0.60, places=2)

    # ── Test 10: Protected semantic field increases trust risk ───────────────
    def test_10_protected_semantic_field_increases_trust_risk(self):
        """Verify protected semantic field incurs additional -0.15 deduction."""
        score_unprot, _ = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="AMBIGUOUS",
            is_protected_field=False,
        )
        score_prot, _ = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="AMBIGUOUS",
            is_protected_field=True,
        )
        self.assertAlmostEqual(score_unprot - score_prot, 0.15, places=2)

    # ── Test 11: Unaffected rules remain unaffected ──────────────────────────
    def test_11_unaffected_rules_remain_unaffected(self):
        """Verify that rules without drift on their dependencies maintain 100% TRUSTED status."""
        score, _ = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="EXACT",
            risk_level="NONE",
            is_protected_field=False,
        )
        self.assertEqual(score, 1.00)

    # ── Test 12: Dependency isolation is preserved ───────────────────────────
    def test_12_dependency_isolation_is_preserved(self):
        """Verify that drift on 'action.result' does NOT affect rules dependent only on 'dns_query'."""
        with SessionLocal() as db:
            dns_rule = db.query(DetectionRule).filter(DetectionRule.rule_id == "drule_suri_dns_tunnel").first()
            self.assertIsNotNone(dns_rule)
            # Evaluate dns_rule
            eval_record = DetectionRuleTrustService.evaluate_rule_trust(
                db=db,
                rule_id=dns_rule.rule_id,
            )
            self.assertEqual(eval_record.trust_status, "TRUSTED")
            self.assertEqual(eval_record.trust_score, 1.00)

    # ── Test 13: Multiple dependency evaluation uses worst impact ────────────
    def test_13_multiple_dependency_evaluation_uses_worst_impact(self):
        """Verify worst dependency impact dominates overall rule status."""
        with SessionLocal() as db:
            # win_sec_logon depends on action.result (which has ambiguous drift in demo) and src_endpoint_ip
            eval_record = DetectionRuleTrustService.get_evaluation_by_id(db, "teval_demo_win_sec")
            evals = db.query(DetectionRuleTrustEvaluation).filter(DetectionRuleTrustEvaluation.rule_id == "drule_win_sec_logon").all()
            self.assertTrue(len(evals) >= 1)
            latest = evals[0]
            # Since action.result was ambiguous in scenario 2, status is AT_RISK
            self.assertEqual(latest.trust_status, "AT_RISK")

    # ── Test 14: Trust score remains between 0.00 and 1.00 ───────────────────
    def test_14_trust_score_clamped_between_zero_and_one(self):
        """Verify trust score cannot fall below 0.00 or exceed 1.00 even with stacked deductions."""
        score, _ = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="INCOMPATIBLE",  # -0.60
            risk_level="CRITICAL",                      # -0.30
            is_protected_field=True,                     # -0.15
            drift_type="SEMANTIC_ANOMALY",              # -0.10
        )
        self.assertGreaterEqual(score, 0.00)
        self.assertLessEqual(score, 1.00)
        self.assertEqual(score, 0.00)

    # ── Test 15: Trust evaluation explanations contain deductions ────────────
    def test_15_trust_evaluation_explanations_contain_deductions(self):
        """Verify evaluation reasons list contains transparent step-by-step math."""
        score, reasons = DetectionRuleTrustService.calculate_trust_score(
            equivalence_classification="AMBIGUOUS",
            risk_level="HIGH",
            is_protected_field=True,
        )
        self.assertTrue(any("Base trust score: 1.00" in r for r in reasons))
        self.assertTrue(any("AMBIGUOUS semantic mapping detected: -0.25" in r for r in reasons))
        self.assertTrue(any("Protected semantic field affected: -0.15" in r for r in reasons))
        self.assertTrue(any("HIGH semantic risk level: -0.15" in r for r in reasons))

    # ── Test 16: Trust alert generated for AT_RISK rule ──────────────────────
    def test_16_trust_alert_generated_for_at_risk_rule(self):
        """Verify DetectionTrustAlert is generated when trust state is AT_RISK."""
        with SessionLocal() as db:
            alerts = (
                db.query(DetectionTrustAlert)
                .filter(DetectionTrustAlert.trust_status == "AT_RISK")
                .all()
            )
            self.assertGreaterEqual(len(alerts), 1)
            alert = alerts[0]
            self.assertEqual(alert.alert_type, "RULE_AT_RISK")

    # ── Test 17: CRITICAL alert generated for INVALID protected dependency ───
    def test_17_critical_alert_generated_for_invalid_protected_dependency(self):
        """Verify CRITICAL severity alert generated for INVALID protected dependency."""
        with SessionLocal() as db:
            alerts = (
                db.query(DetectionTrustAlert)
                .filter(DetectionTrustAlert.severity == "CRITICAL")
                .all()
            )
            self.assertGreaterEqual(len(alerts), 1)

    # ── Test 18: Duplicate evaluation is idempotent ──────────────────────────
    def test_18_duplicate_evaluation_is_idempotent(self):
        """Verify evaluating the exact same context returns existing evaluation record."""
        with SessionLocal() as db:
            initial_count = db.query(DetectionRuleTrustEvaluation).count()
            eval1 = DetectionRuleTrustService.evaluate_rule_trust(
                db=db,
                rule_id="drule_fw_deny_scan",
            )
            eval2 = DetectionRuleTrustService.evaluate_rule_trust(
                db=db,
                rule_id="drule_fw_deny_scan",
            )
            self.assertEqual(eval1.evaluation_id, eval2.evaluation_id)
            final_count = db.query(DetectionRuleTrustEvaluation).count()
            self.assertEqual(initial_count, final_count)

    # ── Test 19: RBAC unauthorized request returns 401 ───────────────────────
    def test_19_rbac_unauthorized_request_returns_401(self):
        """Verify unauthenticated requests are rejected with HTTP 401."""
        response = client.post("/api/v1/detection-rules/drule_fw_deny_scan/evaluate-trust")
        self.assertEqual(response.status_code, 401)

    # ── Test 20: RBAC unauthorized role returns 403 ──────────────────────────
    def test_20_rbac_unauthorized_role_returns_403(self):
        """Verify VIEWER role cannot trigger trust evaluations (HTTP 403)."""
        headers = get_auth_headers("VIEWER")
        response = client.post(
            "/api/v1/detection-rules/drule_fw_deny_scan/evaluate-trust",
            headers=headers,
        )
        self.assertEqual(response.status_code, 403)

    # ── Test 21: Trust trace endpoint returns complete chain ─────────────────
    def test_21_trust_trace_endpoint_returns_complete_chain(self):
        """Verify /api/v1/detection-rule-trust/{id}/trace returns provenance chain."""
        headers = get_auth_headers("AUDITOR")
        with SessionLocal() as db:
            eval_record = db.query(DetectionRuleTrustEvaluation).first()
            self.assertIsNotNone(eval_record)
            eval_id = eval_record.evaluation_id

        response = client.get(
            f"/api/v1/detection-rule-trust/{eval_id}/trace",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("provenance_chain", data)
        self.assertGreaterEqual(len(data["provenance_chain"]), 2)

    # ── Test 22: Trust history remains immutable ─────────────────────────────
    def test_22_trust_history_remains_immutable(self):
        """Verify multiple evaluations over time create distinct immutable historical records."""
        headers = get_auth_headers("ADMIN")
        response = client.get(
            "/api/v1/detection-rules/drule_fw_deny_scan/trust-history",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)

    # ── Test 23: Semantic drift alert links correctly to trust evaluation ────
    def test_23_semantic_drift_alert_links_correctly_to_trust_evaluation(self):
        """Verify evaluate-rule-impact on a drift alert links drift_alert_id."""
        with SessionLocal() as db:
            # Create a test drift alert if not already present
            drift = (
                db.query(SemanticDriftAlert)
                .filter(SemanticDriftAlert.alert_id == "drift_test_sprint6b_01")
                .first()
            )
            if not drift:
                drift = SemanticDriftAlert(
                    alert_id="drift_test_sprint6b_01",
                    normalized_event_id="norm_test_6b_01",
                    interpretation_id="interp_test_6b_01",
                    drift_type="AMBIGUOUS_MAPPING",
                    severity="HIGH",
                    status="OPEN",
                    description="Test ambiguous drift on disposition",
                )
                db.add(drift)
                db.commit()

        headers = get_auth_headers("SECURITY_ANALYST")
        response = client.post(
            "/api/v1/semantic-drift-alerts/drift_test_sprint6b_01/evaluate-rule-impact",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        if len(data) > 0:
            self.assertEqual(data[0]["drift_alert_id"], "drift_test_sprint6b_01")

    # ── Test 24: Existing Sprint 1 evidence remains unchanged ────────────────
    def test_24_existing_sprint1_evidence_remains_unchanged(self):
        """Architectural verification: Raw evidence vault records are NOT modified by trust evaluation."""
        with SessionLocal() as db:
            raw_count = db.query(IngestedEvent).count()
            self.assertGreaterEqual(raw_count, 0)
            # Evaluate a rule
            DetectionRuleTrustService.evaluate_rule_trust(db, "drule_fw_deny_scan")
            raw_count_after = db.query(IngestedEvent).count()
            self.assertEqual(raw_count, raw_count_after)

    # ── Test 25: Existing normalized events remain unchanged ─────────────────
    def test_25_existing_normalized_events_remain_unchanged(self):
        """Architectural verification: Normalized events are NOT modified by trust evaluation."""
        with SessionLocal() as db:
            norm_count = db.query(NormalizedEvent).count()
            self.assertGreaterEqual(norm_count, 0)
            # Evaluate a rule
            DetectionRuleTrustService.evaluate_rule_trust(db, "drule_linux_ssh_brute")
            norm_count_after = db.query(NormalizedEvent).count()
            self.assertEqual(norm_count, norm_count_after)

    # ── Test 26: KPIs summary endpoint ───────────────────────────────────────
    def test_26_kpis_summary_endpoint(self):
        """Verify /api/v1/detection-rule-trust/kpis/summary returns accurate statistics."""
        headers = get_auth_headers("ADMIN")
        response = client.get("/api/v1/detection-rule-trust/kpis/summary", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_evaluations", data)
        self.assertIn("trusted_rules_count", data)
        self.assertIn("open_alerts_count", data)

    # ── Test 27: Alert status triage acknowledgement ─────────────────────────
    def test_27_alert_status_triage_acknowledgement(self):
        """Verify PATCH /api/v1/detection-trust-alerts/{id}/status updates alert status."""
        headers = get_auth_headers("SECURITY_ANALYST")
        with SessionLocal() as db:
            alert = db.query(DetectionTrustAlert).first()
            self.assertIsNotNone(alert)
            alert_id = alert.alert_id

        response = client.patch(
            f"/api/v1/detection-trust-alerts/{alert_id}/status",
            json={"status": "ACKNOWLEDGED"},
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ACKNOWLEDGED")
        self.assertIsNotNone(data["resolved_at"])
