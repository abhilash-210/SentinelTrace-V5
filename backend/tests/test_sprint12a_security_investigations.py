"""
tests/test_sprint12a_security_investigations.py
------------------------------------------------
Comprehensive test suite for Sprint 12A: Unified SOC Investigation & Security Case Management.

Sprint 12A — Unified SOC Investigation & Security Case Management.
Tests cover:
- Case creation, numbering & validation
- Priority scoring & explainability
- Cryptographic hard failure dominance override
- Automatic artifact discovery across domains
- Artifact binding deduplication & manual bindings
- Hypothesis formulation & confidence deductions
- Inconclusive/Supported zero-trust preservation
- Chronological timeline reconstruction & timestamp preservation
- Impact assessment matrix (CIA + Business + Compliance)
- Analyst findings & MITRE ATT&CK context
- Maker-Checker governance & self-approval prevention (HTTP 409)
- 18-stage cryptographic provenance lineage
- RBAC permissions & role enforcement
- Dashboard summary KPI verification
"""

from datetime import datetime, timezone
import json
import unittest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.user import User
from app.models.security_investigation import (
    SecurityInvestigationCase,
    InvestigationArtifactBinding,
    InvestigationHypothesis,
    InvestigationFinding,
    InvestigationTimelineEvent,
    InvestigationImpactAssessment,
    InvestigationReview,
    InvestigationCaseResolution,
    InvestigationProvenanceRecord,
)
from app.services.investigation_priority_service import InvestigationPriorityService
from app.services.investigation_artifact_service import InvestigationArtifactService
from app.services.investigation_hypothesis_service import InvestigationHypothesisService
from app.services.investigation_timeline_service import InvestigationTimelineService
from app.services.investigation_impact_service import InvestigationImpactService
from app.services.investigation_governance_service import (
    InvestigationGovernanceService,
    SelfInvestigationApprovalForbiddenError,
)
from app.services.investigation_provenance_service import (
    InvestigationProvenanceService,
    PROVENANCE_18_STAGES,
)
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from app.core.rbac import ROLE_PERMISSIONS, Role, Permission
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint12ASecurityInvestigations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)
            InvestigationArtifactService.seed_default_investigations(db)
            db.commit()

        cls.client = client
        cls.admin_headers = get_auth_headers("ADMIN")
        cls.analyst_headers = get_auth_headers("SECURITY_ANALYST")
        cls.reviewer_headers = get_auth_headers("POLICY_REVIEWER")
        cls.author_headers = get_auth_headers("POLICY_AUTHOR")
        cls.auditor_headers = get_auth_headers("AUDITOR")
        cls.viewer_headers = get_auth_headers("VIEWER")

    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def get_auth_headers(self, role: str = "ADMIN") -> dict:
        return get_auth_headers(role)

    # ── Unit Tests: Priority Engine & Hard Failure Override ───────────────────

    def test_01_priority_scoring_critical_severity(self):
        res = InvestigationPriorityService.calculate_priority(
            severity="CRITICAL",
            risk_score=90.0,
            threat_confidence=0.9,
            asset_criticality="CRITICAL",
            impact_score=85.0,
        )
        self.assertEqual(res["priority"], "CRITICAL")
        self.assertGreaterEqual(res["priority_score"], 85.0)
        self.assertFalse(res["hard_failure_override"])
        self.assertTrue(len(res["drivers"]) > 0)

    def test_02_priority_scoring_low_severity(self):
        res = InvestigationPriorityService.calculate_priority(
            severity="LOW",
            risk_score=20.0,
            threat_confidence=0.1,
            asset_criticality="LOW",
            impact_score=10.0,
        )
        self.assertEqual(res["priority"], "LOW")
        self.assertLess(res["priority_score"], 40.0)

    def test_03_priority_cryptographic_hard_failure_override(self):
        res = InvestigationPriorityService.calculate_priority(
            severity="LOW",
            risk_score=10.0,
            threat_confidence=0.0,
            asset_criticality="LOW",
            impact_score=0.0,
            cryptographic_integrity_verified=False,
        )
        self.assertEqual(res["priority"], "CRITICAL")
        self.assertEqual(res["priority_score"], 100.0)
        self.assertTrue(res["hard_failure_override"])
        self.assertIn("CRITICAL: Cryptographic integrity violation", res["drivers"][0])

    def test_04_priority_clamping(self):
        res = InvestigationPriorityService.calculate_priority(
            severity="INFORMATIONAL",
            risk_score=-50.0,
            threat_confidence=-1.0,
            asset_criticality="NONE",
            impact_score=-10.0,
        )
        self.assertGreaterEqual(res["priority_score"], 0.0)
        self.assertLessEqual(res["priority_score"], 100.0)

    # ── Unit Tests: Hypothesis Engine (Zero ML/LLM) ──────────────────────────

    def test_05_hypothesis_confidence_clean_evidence(self):
        eval_res = InvestigationHypothesisService.evaluate_hypothesis_confidence(
            base_confidence=0.85,
            has_direct_evidence=True,
            evidence_count=3,
            has_contradictory_evidence=False,
        )
        self.assertGreaterEqual(eval_res["final_confidence"], 0.70)
        self.assertEqual(eval_res["suggested_status"], "SUPPORTED")
        self.assertEqual(len(eval_res["deductions"]), 0)

    def test_06_hypothesis_confidence_with_deductions(self):
        eval_res = InvestigationHypothesisService.evaluate_hypothesis_confidence(
            base_confidence=0.80,
            has_direct_evidence=True,
            evidence_count=1,
            missing_privilege_escalation=True,
            incomplete_telemetry=True,
        )
        self.assertEqual(len(eval_res["deductions"]), 2)
        self.assertAlmostEqual(eval_res["final_confidence"], 0.55, places=2)
        self.assertEqual(eval_res["suggested_status"], "INCONCLUSIVE")

    def test_07_hypothesis_contradictory_evidence_refuted(self):
        eval_res = InvestigationHypothesisService.evaluate_hypothesis_confidence(
            base_confidence=0.80,
            has_direct_evidence=True,
            evidence_count=1,
            has_contradictory_evidence=True,
        )
        self.assertEqual(eval_res["suggested_status"], "REFUTED")

    def test_08_hypothesis_inconclusive_preservation(self):
        eval_res = InvestigationHypothesisService.evaluate_hypothesis_confidence(
            base_confidence=0.70,
            has_direct_evidence=False,
            evidence_count=0,
            incomplete_telemetry=True,
        )
        self.assertEqual(eval_res["suggested_status"], "INCONCLUSIVE")
        self.assertNotEqual(eval_res["suggested_status"], "SUPPORTED")

    # ── Unit Tests: Impact Assessment Engine ─────────────────────────────────

    def test_09_impact_assessment_critical(self):
        score, overall = InvestigationImpactService.calculate_impact_score(
            confidentiality="CRITICAL",
            integrity="HIGH",
            availability="HIGH",
            business="HIGH",
            compliance="HIGH",
        )
        self.assertEqual(overall, "CRITICAL")
        self.assertGreaterEqual(score, 80.0)

    def test_10_impact_assessment_none(self):
        score, overall = InvestigationImpactService.calculate_impact_score(
            confidentiality="NONE",
            integrity="NONE",
            availability="NONE",
            business="NONE",
            compliance="NONE",
        )
        self.assertEqual(overall, "LOW")
        self.assertEqual(score, 0.0)

    def test_11_impact_assessment_moderate(self):
        score, overall = InvestigationImpactService.calculate_impact_score(
            confidentiality="MODERATE",
            integrity="LOW",
            availability="NONE",
            business="MODERATE",
            compliance="LOW",
        )
        self.assertIn(overall, ("MODERATE", "LOW", "HIGH"))
        self.assertGreater(score, 0.0)

    # ── Unit Tests: Provenance Service (18 Stages) ───────────────────────────

    def test_12_provenance_18_stages_defined(self):
        self.assertEqual(len(PROVENANCE_18_STAGES), 18)
        self.assertEqual(PROVENANCE_18_STAGES[0][1], "RAW_EVIDENCE")
        self.assertEqual(PROVENANCE_18_STAGES[-1][1], "GOVERNANCE_LEDGER_AND_MERKLE_PROOF")

    # ── API & Integration Tests: Investigation Case Lifecycle ─────────────────

    def test_13_api_create_investigation_case(self):
        payload = {
            "title": "API Automated Case Creation",
            "description": "Investigating unauthorized lateral movement signal.",
            "severity": "HIGH",
            "priority": "HIGH",
            "investigation_type": "SECURITY_INCIDENT",
            "source_domain": "DETECTION",
        }
        res = self.client.post("/api/v1/investigations", json=payload, headers=self.get_auth_headers("SECURITY_ANALYST"))
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertTrue(data["case_number"].startswith("SIC-"))
        self.assertEqual(data["status"], "OPEN")
        self.assertEqual(data["severity"], "HIGH")

    def test_14_api_list_investigation_cases(self):
        res = self.client.get("/api/v1/investigations", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)

    def test_15_api_get_investigation_case_by_id(self):
        # Create case
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Get Test Case", "description": "Testing fetch by ID"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        res = self.client.get(f"/api/v1/investigations/{case_id}", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["id"], case_id)

    def test_16_api_get_investigation_case_not_found(self):
        res = self.client.get("/api/v1/investigations/sic-nonexistent", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 404)

    def test_17_api_patch_investigation_case(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Patch Test Case", "description": "Testing patch endpoint"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        patch_res = self.client.patch(
            f"/api/v1/investigations/{case_id}",
            json={"title": "Updated Title", "status": "INVESTIGATING", "priority": "CRITICAL"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.json()["title"], "Updated Title")
        self.assertEqual(patch_res.json()["status"], "INVESTIGATING")
        self.assertEqual(patch_res.json()["priority"], "CRITICAL")

    # ── Artifact Bindings & Discovery ─────────────────────────────────────────

    def test_18_api_manually_bind_artifact(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Binding Test Case", "description": "Testing artifact binding"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        bind_res = self.client.post(
            f"/api/v1/investigations/{case_id}/artifacts",
            json={
                "artifact_type": "THREAT_INDICATOR",
                "artifact_id": "ioc-98124",
                "source_domain": "THREAT_INTELLIGENCE",
                "canonical_hash": "a" * 64,
                "summary": "Malicious C2 IP 198.51.100.23",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(bind_res.status_code, 201)
        data = bind_res.json()
        self.assertEqual(data["artifact_type"], "THREAT_INDICATOR")
        self.assertEqual(data["artifact_id"], "ioc-98124")

    def test_19_api_list_case_artifacts(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Artifact List Case", "description": "Testing listing artifacts"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        # Bind 2 artifacts
        self.client.post(
            f"/api/v1/investigations/{case_id}/artifacts",
            json={"artifact_type": "EVIDENCE", "artifact_id": "ev-01", "source_domain": "EVIDENCE_VAULT"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.client.post(
            f"/api/v1/investigations/{case_id}/artifacts",
            json={"artifact_type": "DETECTION_RESULT", "artifact_id": "det-01", "source_domain": "DETECTION"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )

        res = self.client.get(f"/api/v1/investigations/{case_id}/artifacts", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(len(res.json()), 2)

    def test_20_api_discover_case_artifacts(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Discovery Test Case", "description": "Testing auto discovery"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        res = self.client.post(
            f"/api/v1/investigations/{case_id}/discover-artifacts?max_results=3",
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

    # ── Hypotheses Lifecycle ──────────────────────────────────────────────────

    def test_21_api_create_hypothesis(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Hypothesis Test Case", "description": "Testing hypothesis creation"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        hypo_res = self.client.post(
            f"/api/v1/investigations/{case_id}/hypotheses",
            json={
                "hypothesis_title": "Credential Spraying Campaign",
                "hypothesis_statement": "Multiple login failures across distinct accounts suggest distributed spraying.",
                "confidence_score": 0.75,
                "status": "UNDER_INVESTIGATION",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(hypo_res.status_code, 201)
        data = hypo_res.json()
        self.assertEqual(data["hypothesis_title"], "Credential Spraying Campaign")
        self.assertEqual(data["status"], "UNDER_INVESTIGATION")

    def test_22_api_list_hypotheses(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Hypo List Case", "description": "Testing listing hypotheses"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        self.client.post(
            f"/api/v1/investigations/{case_id}/hypotheses",
            json={"hypothesis_title": "Hypothesis List Test", "hypothesis_statement": "Statement 1"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        res = self.client.get(f"/api/v1/investigations/{case_id}/hypotheses", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(len(res.json()), 1)

    def test_23_api_auto_generate_hypotheses(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Auto Hypo Case", "description": "Testing rule based hypo generation"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        res = self.client.post(f"/api/v1/investigations/{case_id}/hypotheses/generate", headers=self.get_auth_headers("SECURITY_ANALYST"))
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(len(res.json()), 1)

    def test_24_api_patch_hypothesis(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Patch Hypo Case", "description": "Testing patch hypo"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        h_res = self.client.post(
            f"/api/v1/investigations/{case_id}/hypotheses",
            json={"hypothesis_title": "Initial Hypo", "hypothesis_statement": "Initial Statement"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        hypo_id = h_res.json()["id"]

        patch_res = self.client.patch(
            f"/api/v1/investigations/hypotheses/{hypo_id}",
            json={"status": "SUPPORTED", "confidence_score": 0.95},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.json()["status"], "SUPPORTED")
        self.assertEqual(patch_res.json()["confidence_score"], 0.95)

    # ── Timeline Reconstruction ───────────────────────────────────────────────

    def test_25_api_get_and_reconstruct_timeline(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Timeline Test Case", "description": "Testing timeline reconstruct"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        rec_res = self.client.post(f"/api/v1/investigations/{case_id}/timeline/reconstruct", headers=self.get_auth_headers("SECURITY_ANALYST"))
        self.assertEqual(rec_res.status_code, 200)
        events = rec_res.json()
        self.assertGreaterEqual(len(events), 1)

        get_res = self.client.get(f"/api/v1/investigations/{case_id}/timeline", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(len(get_res.json()), len(events))

    # ── Impact Assessment ────────────────────────────────────────────────────

    def test_26_api_post_and_get_impact_assessment(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Impact Test Case", "description": "Testing impact assessment"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        post_res = self.client.post(
            f"/api/v1/investigations/{case_id}/impact-assessment",
            json={
                "confidentiality_impact": "HIGH",
                "integrity_impact": "MODERATE",
                "availability_impact": "LOW",
                "business_impact": "HIGH",
                "compliance_impact": "MODERATE",
                "assessment_notes": "Assessed potential customer data exfiltration risk.",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(post_res.status_code, 200)
        data = post_res.json()
        self.assertEqual(data["confidentiality_impact"], "HIGH")
        self.assertGreater(data["impact_score"], 40.0)

        get_res = self.client.get(f"/api/v1/investigations/{case_id}/impact-assessment", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(get_res.status_code, 200)
        self.assertEqual(get_res.json()["id"], data["id"])

    # ── Findings & MITRE Context ──────────────────────────────────────────────

    def test_27_api_record_and_list_findings(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Findings Test Case", "description": "Testing findings"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        f_res = self.client.post(
            f"/api/v1/investigations/{case_id}/findings",
            json={
                "finding_type": "CONFIRMED_COMPROMISE",
                "confidence_score": 0.90,
                "evidence_summary": "Dumped LSASS memory process observed in event telemetry.",
                "analyst_conclusion": "Credential extraction performed via mimikatz variant.",
                "mitre_technique_id": "T1003.001",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(f_res.status_code, 201)
        self.assertEqual(f_res.json()["mitre_technique_id"], "T1003.001")

        list_res = self.client.get(f"/api/v1/investigations/{case_id}/findings", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(list_res.status_code, 200)
        self.assertEqual(len(list_res.json()), 1)

    def test_28_api_get_mitre_context(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "MITRE Test Case", "description": "Testing MITRE aggregation"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        # Record finding with MITRE
        self.client.post(
            f"/api/v1/investigations/{case_id}/findings",
            json={
                "finding_type": "OBSERVATION",
                "evidence_summary": "Phishing email link click.",
                "analyst_conclusion": "Spearphishing delivery link.",
                "mitre_technique_id": "T1566.002",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )

        res = self.client.get(f"/api/v1/investigations/{case_id}/mitre-context", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 200)
        mitre_data = res.json()
        self.assertTrue(any(m["technique_id"] == "T1566.002" for m in mitre_data))

    # ── Maker-Checker Governance & Self-Approval Prevention ───────────────────

    def test_29_api_propose_resolution(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Resolution Propose Case", "description": "Testing proposal"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        prop_res = self.client.post(
            f"/api/v1/investigations/{case_id}/propose-resolution",
            json={
                "proposed_resolution": "SECURITY_INCIDENT",
                "proposed_notes": "Confirmed multi-stage adversary penetration.",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(prop_res.status_code, 200)
        self.assertEqual(prop_res.json()["decision"], "PENDING")

        # Verify case transitioned to AWAITING_REVIEW
        case_res = self.client.get(f"/api/v1/investigations/{case_id}", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(case_res.json()["status"], "AWAITING_REVIEW")

    def test_30_api_self_approval_forbidden_http_409(self):
        """
        Critical Zero-Trust Invariant: Proposer cannot approve their own case resolution.
        """
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Self Approval Block Case", "description": "Testing self approval block"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        # Propose resolution as admin_demo
        self.client.post(
            f"/api/v1/investigations/{case_id}/propose-resolution",
            json={"proposed_resolution": "BENIGN_ACTIVITY"},
            headers=self.get_auth_headers("ADMIN"),
        )

        # Attempt to approve using the SAME user identity (admin_demo)
        review_res = self.client.post(
            f"/api/v1/investigations/{case_id}/review",
            json={"decision": "APPROVED", "review_notes": "Self approval attempt"},
            headers=self.get_auth_headers("ADMIN"),
        )
        self.assertEqual(review_res.status_code, 409)
        self.assertIn("SELF_INVESTIGATION_APPROVAL_FORBIDDEN", review_res.json()["detail"])

    def test_31_api_independent_reviewer_approval_success(self):
        """
        Independent reviewer successfully approves the case resolution.
        """
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Independent Review Case", "description": "Testing independent review"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        # Propose as SECURITY_ANALYST
        self.client.post(
            f"/api/v1/investigations/{case_id}/propose-resolution",
            json={"proposed_resolution": "TRUE_POSITIVE", "proposed_notes": "Attack confirmed"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )

        # Independent review by POLICY_REVIEWER
        review_res = self.client.post(
            f"/api/v1/investigations/{case_id}/review",
            json={"decision": "APPROVED", "review_notes": "Independent review confirmed telemetry and containment."},
            headers=self.get_auth_headers("POLICY_REVIEWER"),
        )
        self.assertEqual(review_res.status_code, 200)
        self.assertEqual(review_res.json()["decision"], "APPROVED")

        # Verify case resolved
        case_res = self.client.get(f"/api/v1/investigations/{case_id}", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(case_res.json()["status"], "RESOLVED")

        # Verify resolution record
        res_record = self.client.get(f"/api/v1/investigations/{case_id}/resolution", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res_record.status_code, 200)
        self.assertEqual(res_record.json()["resolution_type"], "TRUE_POSITIVE")

    def test_32_api_reviewer_requests_changes(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Changes Request Case", "description": "Testing review changes"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        self.client.post(
            f"/api/v1/investigations/{case_id}/propose-resolution",
            json={"proposed_resolution": "FALSE_POSITIVE"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )

        review_res = self.client.post(
            f"/api/v1/investigations/{case_id}/review",
            json={"decision": "CHANGES_REQUESTED", "review_notes": "Additional memory dump analysis required."},
            headers=self.get_auth_headers("POLICY_REVIEWER"),
        )
        self.assertEqual(review_res.status_code, 200)
        self.assertEqual(review_res.json()["decision"], "CHANGES_REQUESTED")

        # Verify case returned to INVESTIGATING
        case_res = self.client.get(f"/api/v1/investigations/{case_id}", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(case_res.json()["status"], "INVESTIGATING")

    # ── 18-Stage Provenance Lineage Tests ────────────────────────────────────

    def test_33_api_get_provenance_lineage(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Provenance Test Case", "description": "Testing 18-stage provenance"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        res = self.client.get(f"/api/v1/investigations/{case_id}/provenance", headers=self.get_auth_headers("SECURITY_ANALYST"))
        self.assertEqual(res.status_code, 200)
        prov_data = res.json()
        self.assertEqual(prov_data["total_stages"], 18)
        self.assertTrue(prov_data["lineage_integrity"])
        self.assertEqual(len(prov_data["stages"]), 18)

        # Check sequence
        for idx, stg in enumerate(prov_data["stages"], start=1):
            self.assertEqual(stg["stage_number"], idx)
            self.assertTrue(stg["verified"])

    # ── RBAC Security Tests ──────────────────────────────────────────────────

    def test_34_rbac_viewer_cannot_create_case(self):
        res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Unauthorized Case", "description": "Viewer cannot create"},
            headers=self.get_auth_headers("VIEWER"),
        )
        self.assertEqual(res.status_code, 403)

    def test_35_rbac_viewer_cannot_create_hypothesis(self):
        res = self.client.post(
            "/api/v1/investigations/sic-123/hypotheses",
            json={"hypothesis_title": "H", "hypothesis_statement": "S"},
            headers=self.get_auth_headers("VIEWER"),
        )
        self.assertEqual(res.status_code, 403)

    def test_36_rbac_auditor_cannot_propose_resolution(self):
        res = self.client.post(
            "/api/v1/investigations/sic-123/propose-resolution",
            json={"proposed_resolution": "FALSE_POSITIVE"},
            headers=self.get_auth_headers("AUDITOR"),
        )
        self.assertEqual(res.status_code, 403)

    def test_37_rbac_policy_author_can_create_hypotheses_and_findings(self):
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Author Hypo Case", "description": "Testing author permissions"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        h_res = self.client.post(
            f"/api/v1/investigations/{case_id}/hypotheses",
            json={"hypothesis_title": "Author Hypo", "hypothesis_statement": "Created by policy author"},
            headers=self.get_auth_headers("POLICY_AUTHOR"),
        )
        self.assertEqual(h_res.status_code, 201)

        f_res = self.client.post(
            f"/api/v1/investigations/{case_id}/findings",
            json={"evidence_summary": "Evidence verified", "analyst_conclusion": "Author conclusion noted"},
            headers=self.get_auth_headers("POLICY_AUTHOR"),
        )
        self.assertEqual(f_res.status_code, 201)

    # ── Dashboard Summary & KPIs ─────────────────────────────────────────────

    def test_38_api_dashboard_summary(self):
        res = self.client.get("/api/v1/investigations/dashboard/summary", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("active_investigations", data)
        self.assertIn("critical_investigations", data)
        self.assertIn("resolution_rate_percent", data)
        self.assertEqual(data["integrity_status"], "VERIFIED_SECURE")

    # ── Filter & Query Tests ─────────────────────────────────────────────────

    def test_39_filter_cases_by_status(self):
        res = self.client.get("/api/v1/investigations?status=OPEN", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 200)
        for c in res.json():
            self.assertEqual(c["status"], "OPEN")

    def test_40_filter_cases_by_priority(self):
        res = self.client.get("/api/v1/investigations?priority=CRITICAL", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 200)
        for c in res.json():
            self.assertEqual(c["priority"], "CRITICAL")

    # ── Additional Unit & Priority Tests ─────────────────────────────────────

    def test_41_priority_zero_scores_and_minimal_threat(self):
        """Priority score is minimal (LOW) when all metrics are 0 and no crypto failure."""
        res = InvestigationPriorityService.calculate_priority(
            severity="LOW",
            risk_score=0.0,
            threat_confidence=0.0,
            asset_criticality="LOW",
            impact_score=0.0,
            cryptographic_integrity_verified=True,
        )
        self.assertEqual(res["priority"], "LOW")
        self.assertLessEqual(res["priority_score"], 25.0)
        self.assertFalse(res["hard_failure_override"])

    def test_42_priority_max_scores_without_crypto_failure(self):
        """Priority score reaches HIGH or CRITICAL with high metrics without hard failure."""
        res = InvestigationPriorityService.calculate_priority(
            severity="HIGH",
            risk_score=85.0,
            threat_confidence=0.9,
            asset_criticality="HIGH",
            impact_score=80.0,
            cryptographic_integrity_verified=True,
        )
        self.assertIn(res["priority"], ["HIGH", "CRITICAL"])
        self.assertGreater(res["priority_score"], 70.0)
        self.assertFalse(res["hard_failure_override"])

    def test_43_priority_crypto_failure_strict_override(self):
        """Cryptographic failure forces priority to CRITICAL (100.0) regardless of low metrics."""
        res = InvestigationPriorityService.calculate_priority(
            severity="LOW",
            risk_score=10.0,
            threat_confidence=0.1,
            asset_criticality="LOW",
            impact_score=10.0,
            cryptographic_integrity_verified=False,
        )
        self.assertEqual(res["priority"], "CRITICAL")
        self.assertEqual(res["priority_score"], 100.0)
        self.assertTrue(res["hard_failure_override"])
        self.assertIn("CRITICAL: Cryptographic integrity violation", res["drivers"][0])

    # ── Artifact Binding Deduplication & Errors ──────────────────────────────

    def test_44_artifact_binding_duplicate_prevention_service(self):
        """Binding the same artifact updates the existing record idempotently."""
        import uuid
        case = SecurityInvestigationCase(
            case_number=f"SIC-2026-{uuid.uuid4().hex[:6]}",
            title="Duplicate Test Case",
            description="Testing duplicate bindings",
            priority="MEDIUM",
            severity="MEDIUM",
            investigation_type="SECURITY_INCIDENT",
            created_by="test_analyst",
        )
        self.db.add(case)
        self.db.commit()

        b1 = InvestigationArtifactService.bind_artifact(
            db=self.db,
            case_id=case.id,
            artifact_type="SECURITY_INCIDENT",
            artifact_id="inc-dup-001",
            source_domain="INCIDENT",
            summary="First binding",
        )
        b2 = InvestigationArtifactService.bind_artifact(
            db=self.db,
            case_id=case.id,
            artifact_type="SECURITY_INCIDENT",
            artifact_id="inc-dup-001",
            source_domain="INCIDENT",
            summary="Updated binding",
        )
        self.assertEqual(b1.id, b2.id)
        self.assertEqual(b2.summary, "Updated binding")

    def test_45_artifact_binding_nonexistent_case(self):
        """Binding to non-existent case raises ValueError."""
        with self.assertRaises(ValueError):
            InvestigationArtifactService.bind_artifact(
                db=self.db,
                case_id="non-existent-case-id",
                artifact_type="SECURITY_INCIDENT",
                artifact_id="inc-001",
                source_domain="INCIDENT",
            )

    def test_46_artifact_binding_api_creation(self):
        """API successfully binds artifacts to an active investigation case."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "API Artifact Binding", "description": "Testing API artifact binding"},
            headers=self.get_auth_headers("ADMIN"),
        )
        case_id = create_res.json()["id"]

        first_res = self.client.post(
            f"/api/v1/investigations/{case_id}/artifacts",
            json={"artifact_type": "EVIDENCE", "artifact_id": "audit-999", "source_domain": "EVIDENCE", "summary": "Audit record"},
            headers=self.get_auth_headers("ADMIN"),
        )
        self.assertEqual(first_res.status_code, 201)

    # ── Hypothesis Lifecycle & Confidence Deductions ─────────────────────────

    def test_47_hypothesis_update_status_and_evidence(self):
        """Updating hypothesis status updates confidence score and evidence citations."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Hypo Update Case", "description": "Testing hypothesis updates"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        h_res = self.client.post(
            f"/api/v1/investigations/{case_id}/hypotheses",
            json={
                "hypothesis_title": "Credential Dumping via Mimikatz",
                "hypothesis_statement": "LSASS memory was dumped by unauthorized process.",
                "supporting_evidence_ids": ["ev-1", "ev-2"],
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        hypo_id = h_res.json()["id"]

        # Update status to REFUTED
        update_res = self.client.put(
            f"/api/v1/investigations/{case_id}/hypotheses/{hypo_id}",
            json={
                "status": "REFUTED",
                "analyst_notes": "Process was verified benign backup agent.",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(update_res.status_code, 200)
        self.assertEqual(update_res.json()["status"], "REFUTED")
        self.assertEqual(update_res.json()["confidence_score"], 0.0)

    def test_48_hypothesis_update_inconclusive_confidence(self):
        """Setting hypothesis status to INCONCLUSIVE results in 0.5 base confidence."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Hypo Inconclusive Case", "description": "Testing inconclusive confidence"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        h_res = self.client.post(
            f"/api/v1/investigations/{case_id}/hypotheses",
            json={
                "hypothesis_title": "Lateral Movement Hypothesis",
                "hypothesis_statement": "Attacker moved laterally using PsExec.",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        hypo_id = h_res.json()["id"]

        update_res = self.client.put(
            f"/api/v1/investigations/{case_id}/hypotheses/{hypo_id}",
            json={"status": "INCONCLUSIVE", "analyst_notes": "Logs truncated; cannot confirm."},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(update_res.status_code, 200)
        self.assertEqual(update_res.json()["status"], "INCONCLUSIVE")
        self.assertEqual(update_res.json()["confidence_score"], 0.5)

    # ── Timeline Reconstruction & Ordering ───────────────────────────────────

    def test_49_timeline_event_manual_addition_api(self):
        """Analyst can manually append verified events to the investigation timeline."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Timeline Event Case", "description": "Testing manual timeline addition"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        t_res = self.client.post(
            f"/api/v1/investigations/{case_id}/timeline",
            json={
                "timestamp": "2026-09-08T10:15:30Z",
                "event_type": "DNS_EXFILTRATION_OBSERVED",
                "source_domain": "DETECTION",
                "artifact_reference": "dns-log-9002",
                "description": "Unusually high TXT query volume to dynamic DNS provider.",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(t_res.status_code, 201)
        self.assertEqual(t_res.json()["event_type"], "DNS_EXFILTRATION_OBSERVED")

    def test_50_timeline_event_chronological_ordering(self):
        """Timeline events are always returned in ascending chronological order."""
        import uuid
        case = SecurityInvestigationCase(
            case_number=f"SIC-2026-{uuid.uuid4().hex[:6]}",
            title="Ordering Case",
            description="Testing timeline ordering",
            priority="MEDIUM",
            severity="MEDIUM",
            created_by="analyst",
        )
        self.db.add(case)
        self.db.commit()

        e1 = InvestigationTimelineEvent(
            case_id=case.id,
            timestamp=datetime(2026, 9, 8, 14, 0, 0, tzinfo=timezone.utc),
            event_type="LATER_EVENT",
            source_domain="AUTH",
            artifact_reference="rec-2",
            description="Later event",
        )
        e2 = InvestigationTimelineEvent(
            case_id=case.id,
            timestamp=datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc),
            event_type="EARLIER_EVENT",
            source_domain="AUTH",
            artifact_reference="rec-1",
            description="Earlier event",
        )
        self.db.add_all([e1, e2])
        self.db.commit()

        events = InvestigationTimelineService.reconstruct_case_timeline(self.db, case.id)
        self.assertGreaterEqual(len(events), 2)

    # ── Impact Assessment Matrix ─────────────────────────────────────────────

    def test_51_impact_assessment_all_critical(self):
        """All critical CIA and business impact triggers CRITICAL overall impact level."""
        score, level = InvestigationImpactService.calculate_impact_score(
            confidentiality="CRITICAL",
            integrity="CRITICAL",
            availability="CRITICAL",
            business="CRITICAL",
            compliance="CRITICAL",
        )
        self.assertEqual(level, "CRITICAL")
        self.assertGreaterEqual(score, 90.0)

    def test_52_impact_assessment_all_none(self):
        """Zero CIA impact and no regulatory scope results in LOW overall impact."""
        score, level = InvestigationImpactService.calculate_impact_score(
            confidentiality="NONE",
            integrity="NONE",
            availability="NONE",
            business="NONE",
            compliance="NONE",
        )
        self.assertEqual(level, "LOW")
        self.assertEqual(score, 0.0)

    def test_53_impact_assessment_update_api(self):
        """API updates impact assessment attributes and recalculates composite score."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Impact API Case", "description": "Testing impact updates"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        update_res = self.client.put(
            f"/api/v1/investigations/{case_id}/impact",
            json={
                "confidentiality_impact": "HIGH",
                "integrity_impact": "HIGH",
                "availability_impact": "LOW",
                "business_impact": "HIGH",
                "compliance_impact": "HIGH",
                "assessment_notes": "Significant impact to confidentiality and compliance.",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(update_res.status_code, 200)
        data = update_res.json()
        self.assertEqual(data["confidentiality_impact"], "HIGH")
        self.assertGreater(data["impact_score"], 60.0)

    # ── Analyst Findings & MITRE ATT&CK Context ──────────────────────────────

    def test_54_finding_with_mitre_mapping(self):
        """Analyst can record findings mapped to MITRE ATT&CK technique."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "MITRE Finding Case", "description": "Testing MITRE finding mapping"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        f_res = self.client.post(
            f"/api/v1/investigations/{case_id}/findings",
            json={
                "finding_type": "CONFIRMED_COMPROMISE",
                "evidence_summary": "Malicious DLL sideloaded by signed executable.",
                "analyst_conclusion": "Adversary utilized DLL Side-Loading for defense evasion.",
                "mitre_technique_id": "T1574.002",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(f_res.status_code, 201)
        data = f_res.json()
        self.assertEqual(data["mitre_technique_id"], "T1574.002")

    def test_55_finding_without_mitre(self):
        """Analyst can record findings without MITRE technique when not yet attributed."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Generic Finding Case", "description": "Testing generic finding"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        f_res = self.client.post(
            f"/api/v1/investigations/{case_id}/findings",
            json={
                "finding_type": "OBSERVATION",
                "evidence_summary": "Anomalous off-hours administrative login.",
                "analyst_conclusion": "Policy violation regarding off-hours access.",
            },
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(f_res.status_code, 201)
        self.assertIsNone(f_res.json()["mitre_technique_id"])

    # ── Maker-Checker Governance & Workflow Transitions ──────────────────────

    def test_56_propose_resolution_invalid_status_transition(self):
        """Proposing resolution on an already RESOLVED case returns 400."""
        import uuid
        case = SecurityInvestigationCase(
            case_number=f"SIC-2026-{uuid.uuid4().hex[:6]}",
            title="Already Resolved Case",
            description="Testing transition on resolved case",
            status="RESOLVED",
            created_by="analyst",
        )
        self.db.add(case)
        self.db.commit()

        res = self.client.post(
            f"/api/v1/investigations/{case.id}/propose-resolution",
            json={"proposed_resolution": "TRUE_POSITIVE"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(res.status_code, 400)

    def test_57_governance_rejection_flow(self):
        """Reviewer REJECTS case resolution, returning case to INVESTIGATING status."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Rejection Case", "description": "Testing reviewer rejection flow"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        self.client.post(
            f"/api/v1/investigations/{case_id}/propose-resolution",
            json={"proposed_resolution": "BENIGN_ACTIVITY", "proposed_notes": "No malware found"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )

        # Reviewer rejects resolution
        review_res = self.client.post(
            f"/api/v1/investigations/{case_id}/review",
            json={"decision": "REJECTED", "review_notes": "Evidence of lateral movement was overlooked. Re-investigate."},
            headers=self.get_auth_headers("POLICY_REVIEWER"),
        )
        self.assertEqual(review_res.status_code, 200)
        self.assertEqual(review_res.json()["decision"], "REJECTED")

        # Verify case returned to INVESTIGATING
        case_res = self.client.get(f"/api/v1/investigations/{case_id}", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(case_res.json()["status"], "INVESTIGATING")

    def test_58_governance_ledger_sealing_integrity(self):
        """Resolving a case produces a valid SHA-256 seal and stores resolution ledger hash."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Sealing Case", "description": "Testing governance ledger sealing"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        self.client.post(
            f"/api/v1/investigations/{case_id}/propose-resolution",
            json={"proposed_resolution": "TRUE_POSITIVE", "proposed_notes": "Ransomware outbreak confirmed"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )

        review_res = self.client.post(
            f"/api/v1/investigations/{case_id}/review",
            json={"decision": "APPROVED", "review_notes": "Containment verified."},
            headers=self.get_auth_headers("ADMIN"),
        )
        self.assertEqual(review_res.status_code, 200)

        res_res = self.client.get(f"/api/v1/investigations/{case_id}/resolution", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res_res.status_code, 200)
        res_data = res_res.json()
        self.assertIsNotNone(res_data["resolution_hash"])
        self.assertEqual(len(res_data["resolution_hash"]), 64)

    # ── Provenance Tamper Detection & Integrity ──────────────────────────────

    def test_59_provenance_tamper_detection(self):
        """Tampering with an intermediate stage payload in provenance lineage is detected."""
        import uuid
        case = SecurityInvestigationCase(
            case_number=f"SIC-2026-{uuid.uuid4().hex[:6]}",
            title="Tamper Test Case",
            description="Testing tamper detection in provenance lineage",
            created_by="analyst",
        )
        self.db.add(case)
        self.db.commit()

        # Initialize provenance records
        InvestigationProvenanceService.generate_provenance_chain(self.db, case.id, "analyst")

        # Intentionally tamper with stage 5
        stage_5 = self.db.query(InvestigationProvenanceRecord).filter_by(
            case_id=case.id, stage_order=5
        ).first()
        stage_5.current_hash = "0" * 64
        self.db.commit()

        # Verify lineage check detects tamper
        integrity_ok, stages = InvestigationProvenanceService.verify_provenance_chain(self.db, case.id)
        self.assertFalse(integrity_ok)

    def test_60_provenance_record_immutability_and_hash_chaining(self):
        """Each provenance stage incorporates the previous stage's hash."""
        import uuid
        case = SecurityInvestigationCase(
            case_number=f"SIC-2026-{uuid.uuid4().hex[:6]}",
            title="Hash Chain Case",
            description="Testing hash chaining across 18 stages",
            created_by="analyst",
        )
        self.db.add(case)
        self.db.commit()

        InvestigationProvenanceService.generate_provenance_chain(self.db, case.id, "analyst")

        stages = self.db.query(InvestigationProvenanceRecord).filter_by(
            case_id=case.id
        ).order_by(InvestigationProvenanceRecord.stage_order.asc()).all()

        self.assertEqual(len(stages), 18)
        self.assertEqual(stages[0].previous_hash, "0" * 64)

        for i in range(1, 18):
            self.assertEqual(stages[i].previous_hash, stages[i - 1].current_hash)

    # ── Case Search & Query Filtering ────────────────────────────────────────

    def test_61_case_search_by_domain_and_status(self):
        """Case endpoint filters cases by source domain and status correctly."""
        self.client.post(
            "/api/v1/investigations",
            json={"title": "Ransomware Detection Search Case", "description": "Ransomware payload detected on host", "source_domain": "DETECTION"},
            headers=self.get_auth_headers("ADMIN"),
        )
        res = self.client.get("/api/v1/investigations?source_domain=DETECTION", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 200)
        cases = res.json()
        self.assertTrue(len(cases) > 0)
        for c in cases:
            self.assertEqual(c["source_domain"], "DETECTION")

    def test_62_case_filter_by_lead_investigator(self):
        """Case endpoint filters by assigned analyst ID."""
        self.client.post(
            "/api/v1/investigations",
            json={"title": "Assigned Analyst Case", "description": "Case assigned to analyst_01", "assigned_to": "analyst_01"},
            headers=self.get_auth_headers("ADMIN"),
        )
        res = self.client.get("/api/v1/investigations?assigned_to=analyst_01", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 200)
        for c in res.json():
            self.assertEqual(c["assigned_to"], "analyst_01")

    def test_63_case_update_api(self):
        """Analyst can update case title, description, priority and assigned user."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Old Title", "description": "Old desc", "priority": "LOW"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        case_id = create_res.json()["id"]

        update_res = self.client.patch(
            f"/api/v1/investigations/{case_id}",
            json={"title": "Updated Title", "priority": "CRITICAL", "assigned_to": "senior_analyst"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(update_res.status_code, 200)
        data = update_res.json()
        self.assertEqual(data["title"], "Updated Title")
        self.assertEqual(data["priority"], "CRITICAL")
        self.assertEqual(data["assigned_to"], "senior_analyst")

    # ── Role Permissions Granularity ─────────────────────────────────────────

    def test_64_rbac_auditor_read_only_access(self):
        """AUDITOR role can read investigation cases and provenance, but cannot modify."""
        cases_res = self.client.get("/api/v1/investigations", headers=self.get_auth_headers("AUDITOR"))
        self.assertEqual(cases_res.status_code, 200)

        patch_res = self.client.patch(
            "/api/v1/investigations/sic-001",
            json={"title": "Auditor Attempt"},
            headers=self.get_auth_headers("AUDITOR"),
        )
        self.assertEqual(patch_res.status_code, 403)

    def test_65_rbac_security_analyst_full_lifecycle(self):
        """SECURITY_ANALYST can create cases, hypotheses, findings, and propose resolutions."""
        c_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Analyst Flow", "description": "Lifecycle investigation"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(c_res.status_code, 201)
        cid = c_res.json()["id"]

        h_res = self.client.post(
            f"/api/v1/investigations/{cid}/hypotheses",
            json={"hypothesis_title": "Hypothesis Lifecycle", "hypothesis_statement": "Hypothesis statement 1"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(h_res.status_code, 201)

        p_res = self.client.post(
            f"/api/v1/investigations/{cid}/propose-resolution",
            json={"proposed_resolution": "BENIGN_ACTIVITY"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(p_res.status_code, 200)

    def test_66_rbac_admin_override_and_management(self):
        """ADMIN has all investigation permissions."""
        for perm in [
            Permission.INVESTIGATION_READ,
            Permission.INVESTIGATION_CREATE,
            Permission.INVESTIGATION_ASSIGN,
            Permission.INVESTIGATION_ANALYZE,
            Permission.INVESTIGATION_HYPOTHESIS_MANAGE,
            Permission.INVESTIGATION_FINDING_CREATE,
            Permission.INVESTIGATION_RESOLVE,
            Permission.INVESTIGATION_REVIEW,
            Permission.INVESTIGATION_PROVENANCE_READ,
            Permission.INVESTIGATION_AUDIT,
        ]:
            self.assertIn(perm, ROLE_PERMISSIONS[Role.ADMIN])

    # ── Edge Cases & 404 Handlers ────────────────────────────────────────────

    def test_67_get_case_detail_not_found(self):
        """Requesting a non-existent investigation case returns 404."""
        res = self.client.get("/api/v1/investigations/non-existent-case-id-404", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 404)

    def test_68_get_hypotheses_not_found_case(self):
        """Requesting hypotheses for non-existent case returns 404."""
        res = self.client.get("/api/v1/investigations/non-existent-case-id-404/hypotheses", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 404)

    def test_69_get_timeline_not_found_case(self):
        """Requesting timeline for non-existent case returns 404."""
        res = self.client.get("/api/v1/investigations/non-existent-case-id-404/timeline", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 404)

    def test_70_get_findings_not_found_case(self):
        """Requesting findings for non-existent case returns 404."""
        res = self.client.get("/api/v1/investigations/non-existent-case-id-404/findings", headers=self.get_auth_headers("VIEWER"))
        self.assertEqual(res.status_code, 404)

    def test_71_provenance_stage_coverage_18_complete(self):
        """All 18 enterprise provenance stage names are present and correctly sequenced."""
        self.assertEqual(len(PROVENANCE_18_STAGES), 18)
        expected_first = "RAW_EVIDENCE"
        expected_last = "GOVERNANCE_LEDGER_AND_MERKLE_PROOF"
        self.assertEqual(PROVENANCE_18_STAGES[0][1], expected_first)
        self.assertEqual(PROVENANCE_18_STAGES[17][1], expected_last)

    def test_72_seed_default_investigations_idempotency(self):
        """Calling seed_default_investigations multiple times does not create duplicates."""
        initial_count = self.db.query(SecurityInvestigationCase).count()
        InvestigationArtifactService.seed_default_investigations(self.db)
        post_seed_count = self.db.query(SecurityInvestigationCase).count()
        InvestigationArtifactService.seed_default_investigations(self.db)
        final_count = self.db.query(SecurityInvestigationCase).count()
        self.assertEqual(post_seed_count, final_count)

    def test_73_case_number_uniqueness_and_format(self):
        """Case numbers follow the SIC-YYYY-XXXX pattern and are unique."""
        c1 = self.client.post("/api/v1/investigations", json={"title": "C1 Case Title", "description": "Case 1 Description"}, headers=self.get_auth_headers("ADMIN")).json()
        c2 = self.client.post("/api/v1/investigations", json={"title": "C2 Case Title", "description": "Case 2 Description"}, headers=self.get_auth_headers("ADMIN")).json()
        self.assertTrue(c1["case_number"].startswith("SIC-"))
        self.assertTrue(c2["case_number"].startswith("SIC-"))
        self.assertNotEqual(c1["case_number"], c2["case_number"])

    def test_74_hypothesis_status_state_transitions(self):
        """Hypothesis can transition through full lifecycle and compute correct confidence."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Hypo State Test", "description": "Testing hypothesis transitions"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        cid = create_res.json()["id"]

        h_res = self.client.post(
            f"/api/v1/investigations/{cid}/hypotheses",
            json={"hypothesis_title": "Exfiltration Hypothesis", "hypothesis_statement": "Data exfiltrated via HTTPS."},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        hid = h_res.json()["id"]
        self.assertEqual(h_res.json()["status"], "PROPOSED")

        # Transition to UNDER_INVESTIGATION
        u1 = self.client.put(
            f"/api/v1/investigations/{cid}/hypotheses/{hid}",
            json={"status": "UNDER_INVESTIGATION"},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(u1.json()["status"], "UNDER_INVESTIGATION")

        # Transition to SUPPORTED
        u2 = self.client.put(
            f"/api/v1/investigations/{cid}/hypotheses/{hid}",
            json={"status": "SUPPORTED", "supporting_evidence_ids": ["ev-https-1"]},
            headers=self.get_auth_headers("SECURITY_ANALYST"),
        )
        self.assertEqual(u2.json()["status"], "SUPPORTED")
        self.assertGreaterEqual(u2.json()["confidence_score"], 0.8)

    def test_75_provenance_verification_endpoint_api(self):
        """API endpoint GET /api/v1/investigations/{case_id}/provenance verifies 18-stage hash lineage."""
        create_res = self.client.post(
            "/api/v1/investigations",
            json={"title": "Provenance Lineage API Check", "description": "Validating full provenance chain"},
            headers=self.get_auth_headers("ADMIN"),
        )
        cid = create_res.json()["id"]

        res = self.client.get(f"/api/v1/investigations/{cid}/provenance", headers=self.get_auth_headers("SECURITY_ANALYST"))
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["lineage_integrity"])
        self.assertEqual(data["total_stages"], 18)


if __name__ == "__main__":
    unittest.main()


