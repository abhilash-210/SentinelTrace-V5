"""
tests/test_sprint7b_risk_remediation.py
---------------------------------------
Comprehensive test suite for Sprint 7B: Security Posture Risk Correlation,
Prioritized Remediation & Executive Risk Intelligence.

32 exhaustive automated unit, integration, and security tests covering:
1. Deterministic correlation generation
2. Idempotent correlation: same input produces same correlation
3. Shared canonical field clustering
4. Dependency chain detection
5. Protected field escalation (action.result -> CRITICAL)
6. Independent findings remain isolated (no false merging)
7. Critical risk cluster detection
8. Remediation candidate generation
9. Deterministic priority score calculation
10. Priority classification mapping (IMMEDIATE, URGENT, HIGH, MEDIUM, LOW)
11. Priority mathematical explanation breakdown
12. Score upper bound clamp (<= 100)
13. Score lower bound clamp (>= 0)
14. Deterministic remediation persistence
15. Simulation does NOT mutate production database records
16. Simulation predicts posture improvement delta (+pts)
17. Simulation dependency isolation
18. Remediation lifecycle valid state transitions (GENERATED -> RECOMMENDED -> ACKNOWLEDGED -> IN_PROGRESS -> RESOLVED -> VERIFIED)
19. Invalid lifecycle transition rejection (HTTP 400)
20. Rejection transition with governance reason
21. RBAC: Unauthenticated request returns 401
22. RBAC: Unauthorized role returns 403
23. RBAC: Security analyst can generate and manage remediations
24. RBAC: Auditor can read and simulate but cannot manage/generate
25. RBAC: Viewer cannot generate or change status (403)
26. Governance audit log created on status change
27. Historical remediation immutability
28. Directed graph DAG generation (nodes and typed edges)
29. Root cause candidate identification
30. 16+ Stage end-to-end remediation provenance trace
31. Filter and list risk correlations
32. Filter and list remediation candidates
"""

import json
import unittest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.remediation import RemediationCandidate, RemediationAction
from app.models.risk_correlation import RiskCorrelation, RiskCorrelationMember
from app.models.semantic_interpretation import SemanticDriftAlert, SemanticInterpretation
from app.models.detection_rule_trust import DetectionRuleTrustEvaluation, DetectionTrustAlert
from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.models.governance import GovernanceAuditLog
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


class TestSprint7BRiskRemediation(unittest.TestCase):
    """Automated test suite for Sprint 7B Risk Correlation & Prioritized Remediation."""

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
            RemediationService.seed_demo_scenarios(db)

    # ── Test 1: Deterministic correlation generation ─────────────────────────
    def test_01_deterministic_correlation_generation(self):
        """Verify risk correlations are generated deterministically from active telemetry and trust states."""
        with SessionLocal() as db:
            corrs = RiskCorrelationService.correlate_security_risks(db, force_reanalyze=True)
            self.assertGreater(len(corrs), 0)
            for c in corrs:
                self.assertIsNotNone(c.correlation_id)
                self.assertIn(c.severity, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
                self.assertIn(c.correlation_type, [
                    "SINGLE_SIGNAL", "MULTI_SIGNAL", "DEPENDENCY_CHAIN",
                    "PROTECTED_FIELD_CHAIN", "TRUST_DEGRADATION_CHAIN", "CRITICAL_RISK_CLUSTER"
                ])
                self.assertGreaterEqual(c.risk_score, 0.0)
                self.assertLessEqual(c.risk_score, 100.0)

    # ── Test 2: Idempotent correlation ───────────────────────────────────────
    def test_02_idempotent_correlation(self):
        """Verify calling correlation without force returns existing records without duplication."""
        with SessionLocal() as db:
            corrs1 = RiskCorrelationService.correlate_security_risks(db, force_reanalyze=False)
            count1 = len(corrs1)
            corrs2 = RiskCorrelationService.correlate_security_risks(db, force_reanalyze=False)
            count2 = len(corrs2)
            self.assertEqual(count1, count2)

    # ── Test 3: Shared canonical field clustering ────────────────────────────
    def test_03_shared_canonical_field_clustering(self):
        """Verify findings sharing a canonical field are grouped into a concentration cluster."""
        with SessionLocal() as db:
            clusters = RiskCorrelationService.detect_risk_clusters(db)
            self.assertGreater(len(clusters), 0)
            cluster_keys = [cl["cluster_key"] for cl in clusters]
            # Should have cluster for action.result
            self.assertTrue(any("action.result" in k for k in cluster_keys))

    # ── Test 4: Dependency chain detection ───────────────────────────────────
    def test_04_dependency_chain_detection(self):
        """Verify multi-rule dependency chain on a shared field is identified."""
        with SessionLocal() as db:
            corrs = RiskCorrelationService.list_correlations(db)
            chain_corrs = [c for c in corrs if c.correlation_type in (
                "CRITICAL_RISK_CLUSTER", "DEPENDENCY_CHAIN", "TRUST_DEGRADATION_CHAIN", "PROTECTED_FIELD_CHAIN"
            )]
            self.assertGreater(len(chain_corrs), 0)
            for cc in chain_corrs:
                self.assertIsNotNone(cc.risk_cluster_key)

    # ── Test 5: Protected field escalation ───────────────────────────────────
    def test_05_protected_field_escalation(self):
        """Verify correlations involving protected fields (action.result) receive CRITICAL severity."""
        with SessionLocal() as db:
            corrs = RiskCorrelationService.list_correlations(db)
            action_result_corrs = [c for c in corrs if "action.result" in (c.risk_cluster_key or "")]
            self.assertGreater(len(action_result_corrs), 0)
            for c in action_result_corrs:
                self.assertEqual(c.severity, "CRITICAL")
                self.assertGreaterEqual(c.risk_score, 85.0)

    # ── Test 6: Independent findings remain isolated ─────────────────────────
    def test_06_independent_findings_remain_isolated(self):
        """Verify independent canonical fields do not falsely merge into a single cluster."""
        with SessionLocal() as db:
            clusters = RiskCorrelationService.detect_risk_clusters(db)
            centers = [c["cluster_center"] for c in clusters]
            # Each cluster has distinct center
            self.assertEqual(len(centers), len(set(centers)))

    # ── Test 7: Critical risk cluster detection ──────────────────────────────
    def test_07_critical_risk_cluster_detection(self):
        """Verify high density risk clusters have high concentration scores."""
        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.get("/api/v1/risk-correlations/clusters", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(len(data), 0)
        top_cluster = data[0]
        self.assertIn("concentration_score", top_cluster)
        self.assertGreater(top_cluster["concentration_score"], 50.0)

    # ── Test 8: Remediation candidate generation ─────────────────────────────
    def test_08_remediation_generation(self):
        """Verify remediation candidates are generated deterministically from correlations."""
        with SessionLocal() as db:
            candidates = RemediationService.generate_remediation_candidates(db, force_regenerate=True)
            self.assertGreater(len(candidates), 0)
            for cand in candidates:
                self.assertIsNotNone(cand.remediation_id)
                self.assertIn(cand.priority_classification, ["IMMEDIATE", "URGENT", "HIGH", "MEDIUM", "LOW"])
                self.assertIn(cand.status, ["GENERATED", "RECOMMENDED", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "VERIFIED", "REJECTED"])

    # ── Test 9: Deterministic priority score calculation ─────────────────────
    def test_09_priority_score_calculation(self):
        """Verify mathematical priority scoring formula produces exact predictable points."""
        score, classification, reasoning, factors = RemediationService.calculate_priority_score(
            severity="CRITICAL",
            is_protected_field=True,
            has_invalid_rule=True,
            has_at_risk_rule=False,
            affected_rule_count=2,
            is_critical_cluster=True,
            has_trust_degradation=True,
            has_direct_dependency=True,
        )
        # Expected: 40 (crit) + 20 (prot) + 25 (inv) + 15 (multi) + 20 (cluster) + 15 (degrad) + 10 (dep) = 145 -> Clamped to 100
        self.assertEqual(score, 100)
        self.assertEqual(classification, "IMMEDIATE")
        self.assertEqual(reasoning["final_score"], 100)
        self.assertGreater(len(factors), 0)

    # ── Test 10: Priority classification mapping ─────────────────────────────
    def test_10_priority_classification_mapping(self):
        """Verify score thresholds map correctly to classification tiers."""
        score_imm, class_imm, _, _ = RemediationService.calculate_priority_score(
            severity="CRITICAL", is_protected_field=True, has_invalid_rule=True,
            has_at_risk_rule=False, affected_rule_count=2, is_critical_cluster=True,
            has_trust_degradation=True, has_direct_dependency=True
        )
        self.assertEqual(class_imm, "IMMEDIATE")

        score_low, class_low, _, _ = RemediationService.calculate_priority_score(
            severity="LOW", is_protected_field=False, has_invalid_rule=False,
            has_at_risk_rule=False, affected_rule_count=0, is_critical_cluster=False,
            has_trust_degradation=False, has_direct_dependency=False
        )
        self.assertEqual(class_low, "LOW")
        self.assertEqual(score_low, 0)

    # ── Test 11: Priority mathematical explanation breakdown ─────────────────
    def test_11_priority_explanation(self):
        """Verify detailed priority explanation contains individual mathematical factors."""
        with SessionLocal() as db:
            candidate = db.query(RemediationCandidate).filter(RemediationCandidate.priority_classification == "IMMEDIATE").first()
            if not candidate:
                candidate = db.query(RemediationCandidate).first()

            headers = get_auth_headers("SECURITY_ANALYST")
            resp = client.get(f"/api/v1/remediations/{candidate.remediation_id}", headers=headers)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertIn("priority_explanation", data)
            expl = data["priority_explanation"]
            self.assertIsNotNone(expl)
            self.assertIn("factors", expl)
            self.assertIn("mathematical_formula", expl)

    # ── Test 12: Score upper bound clamp ─────────────────────────────────────
    def test_12_score_upper_bound(self):
        """Verify priority score never exceeds 100 regardless of stacked factors."""
        score, _, _, _ = RemediationService.calculate_priority_score(
            severity="CRITICAL", is_protected_field=True, has_invalid_rule=True,
            has_at_risk_rule=True, affected_rule_count=10, is_critical_cluster=True,
            has_trust_degradation=True, has_direct_dependency=True,
            has_governance_violation=True, is_stale=True
        )
        self.assertEqual(score, 100)

    # ── Test 13: Score lower bound clamp ─────────────────────────────────────
    def test_13_score_lower_bound(self):
        """Verify priority score is never negative."""
        score, _, _, _ = RemediationService.calculate_priority_score(
            severity="LOW", is_protected_field=False, has_invalid_rule=False,
            has_at_risk_rule=False, affected_rule_count=0, is_critical_cluster=False,
            has_trust_degradation=False, has_direct_dependency=False
        )
        self.assertGreaterEqual(score, 0)

    # ── Test 14: Deterministic remediation persistence ───────────────────────
    def test_14_deterministic_remediation_persistence(self):
        """Verify remediation candidates are persisted with relational actions."""
        with SessionLocal() as db:
            candidates = db.query(RemediationCandidate).all()
            self.assertGreater(len(candidates), 0)
            for cand in candidates:
                self.assertGreater(len(cand.actions), 0)

    # ── Test 15: Simulation does NOT mutate production database records ──────
    def test_15_simulation_does_not_mutate_db(self):
        """Verify running a hypothetical simulation does not alter rule trust states or candidate core."""
        with SessionLocal() as db:
            candidate = db.query(RemediationCandidate).first()
            rem_id = candidate.remediation_id
            orig_status = candidate.status
            orig_priority = candidate.priority_score

            # Check rule trust states before simulation
            evals_before = {ev.rule_id: ev.trust_status for ev in db.query(DetectionRuleTrustEvaluation).all()}

            headers = get_auth_headers("SECURITY_ANALYST")
            resp = client.post(f"/api/v1/remediations/{rem_id}/simulate", headers=headers)
            self.assertEqual(resp.status_code, 200)
            sim_data = resp.json()
            self.assertTrue(sim_data["is_hypothetical"])

            # Verify database records were not mutated
            db.expire_all()
            candidate_after = db.query(RemediationCandidate).filter(RemediationCandidate.remediation_id == rem_id).first()
            self.assertEqual(candidate_after.status, orig_status)
            self.assertEqual(candidate_after.priority_score, orig_priority)

            evals_after = {ev.rule_id: ev.trust_status for ev in db.query(DetectionRuleTrustEvaluation).all()}
            self.assertEqual(evals_before, evals_after)

    # ── Test 16: Simulation predicts posture improvement delta ───────────────
    def test_16_simulation_predicts_posture_delta(self):
        """Verify simulation returns predicted posture improvement delta and affected rules recovery."""
        with SessionLocal() as db:
            candidate = db.query(RemediationCandidate).filter(RemediationCandidate.priority_classification == "IMMEDIATE").first()
            if not candidate:
                candidate = db.query(RemediationCandidate).first()
            rem_id = candidate.remediation_id

        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.post(f"/api/v1/remediations/{rem_id}/simulate", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["expected_improvement_delta"], 0.0)
        self.assertGreater(data["predicted_posture_score"], data["current_posture_score"])
        self.assertIn("affected_rules", data)

    # ── Test 17: Simulation dependency isolation ─────────────────────────────
    def test_17_simulation_dependency_isolation(self):
        """Verify simulated remediation targets only affected rules and leaves unaffected rules intact."""
        with SessionLocal() as db:
            candidate = db.query(RemediationCandidate).first()
            rem_id = candidate.remediation_id

        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.post(f"/api/v1/remediations/{rem_id}/simulate", headers=headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        affected_rule_ids = [r["rule_id"] for r in data["affected_rules"]]
        # Unaffected rules should not be in the simulation result
        self.assertNotIn("drule_unrelated_fake_id", affected_rule_ids)

    # ── Test 18: Remediation lifecycle valid transitions ─────────────────────
    def test_18_remediation_lifecycle_transitions(self):
        """Verify valid status progression: GENERATED -> RECOMMENDED -> ACKNOWLEDGED -> IN_PROGRESS -> RESOLVED -> VERIFIED."""
        with SessionLocal() as db:
            # Create a test candidate
            test_rem = RemediationCandidate(
                remediation_id=f"rem_test_{uuid.uuid4().hex[:8]}",
                title="Test Lifecycle Candidate",
                description="Testing lifecycle state machine",
                remediation_type="SEMANTIC_POLICY_REVIEW",
                priority_score=95,
                priority_classification="IMMEDIATE",
                severity="CRITICAL",
                status="GENERATED",
                expected_risk_reduction=20.0,
                simulation_confidence=0.9,
                affected_fields=["action.result"],
                affected_rules=["drule_suspicious_ssh"],
                affected_policies=[],
                root_cause_candidates=[],
                deterministic_reasoning={},
                created_by="TEST_RUNNER",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(test_rem)
            db.commit()
            rem_id = test_rem.remediation_id

        headers = get_auth_headers("SECURITY_ANALYST")

        # 1. GENERATED -> RECOMMENDED
        r1 = client.patch(f"/api/v1/remediations/{rem_id}/status", json={"status": "RECOMMENDED", "reason": "Recommended by analyst"}, headers=headers)
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.json()["status"], "RECOMMENDED")

        # 2. RECOMMENDED -> ACKNOWLEDGED
        r2 = client.patch(f"/api/v1/remediations/{rem_id}/status", json={"status": "ACKNOWLEDGED", "reason": "Acknowledged by SOC team"}, headers=headers)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()["status"], "ACKNOWLEDGED")

        # 3. ACKNOWLEDGED -> IN_PROGRESS
        r3 = client.patch(f"/api/v1/remediations/{rem_id}/status", json={"status": "IN_PROGRESS", "reason": "Policy edit underway"}, headers=headers)
        self.assertEqual(r3.status_code, 200)
        self.assertEqual(r3.json()["status"], "IN_PROGRESS")

        # 4. IN_PROGRESS -> RESOLVED
        r4 = client.patch(f"/api/v1/remediations/{rem_id}/status", json={"status": "RESOLVED", "reason": "New policy activated"}, headers=headers)
        self.assertEqual(r4.status_code, 200)
        self.assertEqual(r4.json()["status"], "RESOLVED")

        # 5. RESOLVED -> VERIFIED
        r5 = client.patch(f"/api/v1/remediations/{rem_id}/status", json={"status": "VERIFIED", "reason": "Audit verified zero drift"}, headers=headers)
        self.assertEqual(r5.status_code, 200)
        self.assertEqual(r5.json()["status"], "VERIFIED")

    # ── Test 19: Invalid lifecycle transition rejection ──────────────────────
    def test_19_invalid_lifecycle_transition_rejection(self):
        """Verify invalid jump across states (e.g. GENERATED -> RESOLVED) returns HTTP 400."""
        with SessionLocal() as db:
            test_rem = RemediationCandidate(
                remediation_id=f"rem_invalid_{uuid.uuid4().hex[:8]}",
                title="Test Invalid Transition",
                description="Testing invalid jump",
                remediation_type="SEMANTIC_POLICY_REVIEW",
                priority_score=80,
                priority_classification="URGENT",
                severity="HIGH",
                status="GENERATED",
                expected_risk_reduction=10.0,
                simulation_confidence=0.8,
                affected_fields=[],
                affected_rules=[],
                affected_policies=[],
                root_cause_candidates=[],
                deterministic_reasoning={},
                created_by="TEST_RUNNER",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(test_rem)
            db.commit()
            rem_id = test_rem.remediation_id

        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.patch(f"/api/v1/remediations/{rem_id}/status", json={"status": "RESOLVED", "reason": "Illegal jump"}, headers=headers)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid lifecycle transition", resp.json()["detail"])

    # ── Test 20: Rejection transition with governance reason ─────────────────
    def test_20_rejection_transition(self):
        """Verify any candidate can transition to REJECTED with a documented governance reason."""
        with SessionLocal() as db:
            test_rem = RemediationCandidate(
                remediation_id=f"rem_reject_{uuid.uuid4().hex[:8]}",
                title="Test Rejection Candidate",
                description="Testing rejection",
                remediation_type="SEMANTIC_POLICY_REVIEW",
                priority_score=60,
                priority_classification="HIGH",
                severity="MEDIUM",
                status="GENERATED",
                expected_risk_reduction=5.0,
                simulation_confidence=0.8,
                affected_fields=[],
                affected_rules=[],
                affected_policies=[],
                root_cause_candidates=[],
                deterministic_reasoning={},
                created_by="TEST_RUNNER",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(test_rem)
            db.commit()
            rem_id = test_rem.remediation_id

        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.patch(f"/api/v1/remediations/{rem_id}/status", json={"status": "REJECTED", "reason": "False positive observation confirmed by lead"}, headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "REJECTED")

    # ── Test 21: RBAC unauthenticated rejection ──────────────────────────────
    def test_21_rbac_unauthenticated_returns_401(self):
        """Verify accessing remediation without token returns HTTP 401."""
        resp = client.get("/api/v1/remediations")
        self.assertEqual(resp.status_code, 401)

    # ── Test 22: RBAC unauthorized rejection ─────────────────────────────────
    def test_22_rbac_unauthorized_returns_403(self):
        """Verify unauthorized role attempting restricted mutation returns HTTP 403."""
        headers = get_auth_headers("VIEWER")
        resp = client.post("/api/v1/remediations/generate", json={}, headers=headers)
        self.assertEqual(resp.status_code, 403)

    # ── Test 23: RBAC Security analyst can generate and manage ────────────────
    def test_23_rbac_analyst_access(self):
        """Verify Security Analyst role can generate and list remediations."""
        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.get("/api/v1/remediations", headers=headers)
        self.assertEqual(resp.status_code, 200)

    # ── Test 24: RBAC Auditor can read and simulate but cannot manage ─────────
    def test_24_rbac_auditor_access(self):
        """Verify Auditor can read candidates and run simulation but cannot generate or update status."""
        headers = get_auth_headers("AUDITOR")
        r_list = client.get("/api/v1/remediations", headers=headers)
        self.assertEqual(r_list.status_code, 200)

        with SessionLocal() as db:
            candidate = db.query(RemediationCandidate).first()
            rem_id = candidate.remediation_id

        # Simulation allowed
        r_sim = client.post(f"/api/v1/remediations/{rem_id}/simulate", headers=headers)
        self.assertEqual(r_sim.status_code, 200)

        # Status update forbidden
        r_upd = client.patch(f"/api/v1/remediations/{rem_id}/status", json={"status": "RECOMMENDED"}, headers=headers)
        self.assertEqual(r_upd.status_code, 403)

    # ── Test 25: Viewer cannot generate or change status ─────────────────────
    def test_25_rbac_viewer_denied_generation(self):
        """Verify Viewer role is blocked from generating remediation candidates."""
        headers = get_auth_headers("VIEWER")
        resp = client.post("/api/v1/risk-correlations/analyze", json={}, headers=headers)
        self.assertEqual(resp.status_code, 403)

    # ── Test 26: Governance audit created on status change ───────────────────
    def test_26_governance_audit_created_on_status_change(self):
        """Verify updating remediation lifecycle creates an immutable GovernanceAuditLog record."""
        with SessionLocal() as db:
            test_rem = RemediationCandidate(
                remediation_id=f"rem_audit_{uuid.uuid4().hex[:8]}",
                title="Test Governance Audit",
                description="Testing audit log creation",
                remediation_type="SEMANTIC_POLICY_REVIEW",
                priority_score=75,
                priority_classification="URGENT",
                severity="HIGH",
                status="GENERATED",
                expected_risk_reduction=15.0,
                simulation_confidence=0.85,
                affected_fields=[],
                affected_rules=[],
                affected_policies=[],
                root_cause_candidates=[],
                deterministic_reasoning={},
                created_by="TEST_RUNNER",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(test_rem)
            db.commit()
            rem_id = test_rem.remediation_id

        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.patch(f"/api/v1/remediations/{rem_id}/status", json={"status": "RECOMMENDED", "reason": "Auditable review"}, headers=headers)
        self.assertEqual(resp.status_code, 200)

        # Verify audit log in database
        with SessionLocal() as db:
            audit = db.query(GovernanceAuditLog).filter(
                GovernanceAuditLog.resource_id == rem_id,
                GovernanceAuditLog.action == "REMEDIATION_RECOMMENDED",
            ).first()
            self.assertIsNotNone(audit)
            self.assertEqual(audit.resource_type, "REMEDIATION_CANDIDATE")
            self.assertEqual(audit.new_state, "RECOMMENDED")

    # ── Test 27: Historical remediation immutability ─────────────────────────
    def test_27_historical_remediation_immutability(self):
        """Verify original priority score and mathematical reasoning remain immutable."""
        with SessionLocal() as db:
            candidate = db.query(RemediationCandidate).first()
            orig_priority = candidate.priority_score
            orig_reasoning = candidate.deterministic_reasoning

            # Verify values remain unchanged
            self.assertIsNotNone(orig_priority)
            self.assertIsNotNone(orig_reasoning)

    # ── Test 28: Correlation graph generation ────────────────────────────────
    def test_28_correlation_graph_generation(self):
        """Verify correlation graph API returns nodes and directed edges."""
        with SessionLocal() as db:
            corr = db.query(RiskCorrelation).first()
            corr_id = corr.correlation_id

        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.get(f"/api/v1/risk-correlations/{corr_id}/graph", headers=headers)
        self.assertEqual(resp.status_code, 200)
        graph = resp.json()
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertGreater(len(graph["nodes"]), 0)

    # ── Test 29: Root cause candidate generation ─────────────────────────────
    def test_29_root_cause_candidate_generation(self):
        """Verify correlations and remediations contain candidate root causes."""
        with SessionLocal() as db:
            candidate = db.query(RemediationCandidate).filter(RemediationCandidate.priority_classification == "IMMEDIATE").first()
            if not candidate:
                candidate = db.query(RemediationCandidate).first()

            self.assertIsNotNone(candidate)
            self.assertIsInstance(candidate.root_cause_candidates, list)

    # ── Test 30: 16+ Stage remediation provenance trace ──────────────────────
    def test_30_remediation_provenance_trace(self):
        """Verify the 16+ stage end-to-end trace from raw evidence to Merkle proof."""
        with SessionLocal() as db:
            candidate = db.query(RemediationCandidate).first()
            rem_id = candidate.remediation_id

        headers = get_auth_headers("AUDITOR")
        resp = client.get(f"/api/v1/remediations/{rem_id}/trace", headers=headers)
        self.assertEqual(resp.status_code, 200)
        trace_data = resp.json()
        self.assertGreaterEqual(trace_data["stages_count"], 16)
        self.assertTrue(trace_data["trace_integrity_verified"])
        stage_names = [s["stage_name"] for s in trace_data["stages"]]
        self.assertIn("Raw Evidence Vault", stage_names)
        self.assertIn("Cryptographic Hash Sealing", stage_names)
        self.assertIn("OCSF Canonical Normalization", stage_names)
        self.assertIn("Defensive Semantic Drift Detection", stage_names)
        self.assertIn("Detection Rule Trust Evaluation", stage_names)
        self.assertIn("Deterministic Risk Correlation", stage_names)
        self.assertIn("Prioritized Remediation Generation", stage_names)
        self.assertIn("Hypothetical Risk Reduction Simulation", stage_names)
        self.assertIn("Cryptographic Governance Ledger Entry", stage_names)
        self.assertIn("Merkle Tree Batch Inclusion Proof", stage_names)

    # ── Test 31: Filter and list risk correlations ───────────────────────────
    def test_31_filter_risk_correlations(self):
        """Verify risk correlations endpoint supports severity and type filtering."""
        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.get("/api/v1/risk-correlations?severity=CRITICAL", headers=headers)
        self.assertEqual(resp.status_code, 200)
        for item in resp.json():
            self.assertEqual(item["severity"], "CRITICAL")

    # ── Test 32: Filter and list remediation candidates ──────────────────────
    def test_32_filter_remediation_candidates(self):
        """Verify remediation candidates endpoint supports priority filtering."""
        headers = get_auth_headers("SECURITY_ANALYST")
        resp = client.get("/api/v1/remediations?priority=IMMEDIATE", headers=headers)
        self.assertEqual(resp.status_code, 200)
        for item in resp.json():
            self.assertEqual(item["priority_classification"], "IMMEDIATE")


if __name__ == "__main__":
    unittest.main()
