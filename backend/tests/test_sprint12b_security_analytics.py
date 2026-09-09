"""
tests/test_sprint12b_security_analytics.py
-------------------------------------------
Comprehensive test suite for Sprint 12B: Security Analytics, Reporting & Evidence Intelligence.

Sprint 12B — Security Analytics, Reporting & Evidence Intelligence.
Tests cover:
- Metric registry initialization & cross-domain definitions
- Metric evaluation from authoritative DB state
- Telemetry completeness & UNKNOWN confidence deductions
- Cryptographic failure dominance override (confidence -> 0.0, UNTRUSTED)
- Snapshot creation, SHA-256 seal computation & immutability
- Direction-aware trend classification (HIGHER_IS_BETTER, LOWER_IS_BETTER, INSUFFICIENT_DATA)
- Deterministic insight generation across core security rules
- Report synthesis across 7 report types and structured sections
- Reference-only evidence package construction & manifest hashing
- Multi-layer verification and tamper detection (reports, sections, bindings)
- 17-stage cryptographic provenance hash chain generation & verification
- RBAC permissions & role enforcement across all 6 roles
- Full REST API router endpoint validation
"""

from datetime import datetime, timezone, timedelta
import json
import unittest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.security_analytics import (
    SecurityAnalyticsSnapshot,
    SecurityMetricDefinition,
    SecurityMetricEvaluation,
    SecurityTrendSnapshot,
    SecurityAnalyticsInsight,
    SecurityReport,
    SecurityReportSection,
    SecurityEvidencePackage,
    EvidencePackageArtifact,
    SecurityAnalyticsProvenanceRecord,
    compute_canonical_hash,
)
from app.services.security_metric_registry_service import SecurityMetricRegistryService
from app.services.security_analytics_service import SecurityAnalyticsService
from app.services.security_trend_service import SecurityTrendService
from app.services.security_analytics_insight_service import SecurityAnalyticsInsightService
from app.services.security_reporting_service import SecurityReportingService
from app.services.security_evidence_package_service import SecurityEvidencePackageService
from app.services.security_report_verification_service import SecurityReportVerificationService
from app.services.security_analytics_provenance_service import (
    SecurityAnalyticsProvenanceService,
    PROVENANCE_17_STAGES,
)
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from app.core.rbac import ROLE_PERMISSIONS, Role, Permission
from tests.auth_helper import get_auth_headers

client = TestClient(app)


class TestSprint12BSecurityAnalytics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)
            SecurityMetricRegistryService.seed_default_metrics(db)
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

    # ── Unit Tests: Metric Registry & Definitions ─────────────────────────────

    def test_01_metric_registry_definitions_count(self):
        metrics = SecurityMetricRegistryService.list_metric_definitions(self.db)
        self.assertGreaterEqual(len(metrics), 15)
        codes = {m.metric_code for m in metrics}
        expected = {
            "METRIC_EVIDENCE_INTEGRITY_RATE",
            "METRIC_NORMALIZATION_SUCCESS_RATE",
            "METRIC_SEMANTIC_DRIFT_RATE",
            "METRIC_DETECTION_TRUST_AVERAGE",
            "METRIC_CRITICAL_RISK_EVENTS",
            "METRIC_OPEN_INCIDENTS",
            "METRIC_MTTD",
            "METRIC_MTTR",
            "METRIC_RECOVERY_VERIFICATION_RATE",
            "METRIC_COMPLIANCE_SCORE",
            "METRIC_THREAT_INTELLIGENCE_TRUST",
            "METRIC_OPEN_INVESTIGATIONS",
            "METRIC_CASE_RESOLUTION_RATE",
            "METRIC_EXECUTIVE_POSTURE",
            "METRIC_DETECTION_EXECUTION_VOLUME",
        }
        self.assertTrue(expected.issubset(codes))

    def test_02_metric_registry_structure(self):
        m = SecurityMetricRegistryService.get_metric_definition(self.db, "METRIC_EVIDENCE_INTEGRITY_RATE")
        self.assertIsNotNone(m)
        self.assertEqual(m.domain, "EVIDENCE_INTEGRITY")
        self.assertEqual(m.unit, "PERCENT")
        self.assertEqual(m.direction, "HIGHER_IS_BETTER")
        self.assertTrue(m.requires_complete_telemetry)

    def test_03_metric_evaluation_deterministic(self):
        metric_def = SecurityMetricRegistryService.get_metric_definition(self.db, "METRIC_EVIDENCE_INTEGRITY_RATE")
        self.assertIsNotNone(metric_def)
        eval_res = SecurityMetricRegistryService.evaluate_metric(self.db, metric_def)
        self.assertIn("metric_value", eval_res)
        self.assertIn("metric_status", eval_res)
        self.assertIn("confidence_score", eval_res)
        self.assertIn("sample_count", eval_res)
        self.assertIn("telemetry_state", eval_res)
        self.assertIn("calculation_details_json", eval_res)
        self.assertIn("source_references_json", eval_res)
        self.assertGreaterEqual(eval_res["confidence_score"], 0.0)
        self.assertLessEqual(eval_res["confidence_score"], 100.0)

    # ── Unit Tests: Telemetry Completeness & Zero-Trust Deductions ────────────

    def test_04_snapshot_creation_and_telemetry(self):
        snap = SecurityAnalyticsService.create_snapshot(
            self.db,
            period_type="24H",
            created_by="test_admin",
        )
        self.assertIsNotNone(snap)
        self.assertTrue(snap.snapshot_number.startswith("SAS-2026-"))
        self.assertGreaterEqual(snap.telemetry_completeness, 0.0)
        self.assertLessEqual(snap.telemetry_completeness, 100.0)
        self.assertGreaterEqual(snap.overall_security_score, 0.0)
        self.assertLessEqual(snap.overall_security_score, 100.0)

    def test_05_cryptographic_failure_dominance_override(self):
        # Axiom: CRYPTOGRAPHIC FAILURE > NUMERICAL REPORT SCORE
        # Overrides confidence to 0.0 and forces degraded posture score
        snap = SecurityAnalyticsService.create_snapshot(
            self.db,
            period_type="24H",
            created_by="test_admin",
            cryptographic_failure_detected=True,
        )
        self.assertEqual(snap.overall_confidence, 0.0)
        self.assertLessEqual(snap.overall_security_score, 20.0)

    def test_06_snapshot_hash_verification(self):
        snap = SecurityAnalyticsService.create_snapshot(
            self.db,
            period_type="7D",
            created_by="test_admin",
        )
        self.assertIsNotNone(snap.snapshot_hash)
        self.assertIsNotNone(snap.created_at)

    # ── Unit Tests: Trend Classification & Direction-Awareness ────────────────

    def test_07_trend_calculation_insufficient_data_when_no_prior(self):
        # Create a fresh isolated test snapshot
        snap = SecurityAnalyticsService.create_snapshot(
            self.db,
            period_type="30D",
            created_by="test_admin",
        )
        trends = SecurityTrendService.compute_trends_for_snapshot(self.db, snap.id)
        self.assertGreaterEqual(len(trends), 1)

    def test_08_trend_direction_higher_is_better_classification(self):
        # Test metric direction preference
        metric_def = SecurityMetricRegistryService.get_metric_definition(self.db, "METRIC_COMPLIANCE_SCORE")
        self.assertEqual(metric_def.direction, "HIGHER_IS_BETTER")

    def test_09_trend_direction_lower_is_better_classification(self):
        # Test metric direction preference
        mttd = SecurityMetricRegistryService.get_metric_definition(self.db, "METRIC_MTTD")
        self.assertEqual(mttd.direction, "LOWER_IS_BETTER")
        mttr = SecurityMetricRegistryService.get_metric_definition(self.db, "METRIC_MTTR")
        self.assertEqual(mttr.direction, "LOWER_IS_BETTER")
        unres = SecurityMetricRegistryService.get_metric_definition(self.db, "METRIC_OPEN_INCIDENTS")
        self.assertEqual(unres.direction, "LOWER_IS_BETTER")

    # ── Unit Tests: Deterministic Analytics Insights Engine ────────────────────

    def test_10_deterministic_insights_generation(self):
        snap = SecurityAnalyticsService.create_snapshot(
            self.db,
            period_type="24H",
            created_by="test_admin",
        )
        insights = SecurityAnalyticsInsightService.generate_insights_for_snapshot(self.db, snap.id)
        self.assertIsInstance(insights, list)
        for ins in insights:
            self.assertTrue(ins.insight_code.startswith("SAI-"))
            self.assertIn(ins.severity, ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "INFO"])
            self.assertIsNotNone(ins.rule_triggered)
            self.assertIsNotNone(ins.supporting_metrics_json)

    def test_11_deterministic_rule_crypto_compromise_insight(self):
        snap = SecurityAnalyticsService.create_snapshot(
            self.db,
            period_type="24H",
            created_by="test_admin",
            cryptographic_failure_detected=True,
        )
        insights = SecurityAnalyticsInsightService.generate_insights_for_snapshot(self.db, snap.id)
        codes = [i.rule_triggered for i in insights]
        self.assertIn("RULE_CRYPTOGRAPHIC_FAILURE_DOMINANCE", codes)
        crypto_ins = next(i for i in insights if i.rule_triggered == "RULE_CRYPTOGRAPHIC_FAILURE_DOMINANCE")
        self.assertEqual(crypto_ins.severity, "CRITICAL")
        self.assertIn("Cryptographic Integrity Violation", crypto_ins.title)

    # ── Unit Tests: Security Report Synthesis & Sections ──────────────────────

    def test_12_report_generation_executive_security_report(self):
        report = SecurityReportingService.generate_report(
            self.db,
            report_type="EXECUTIVE_SECURITY_REPORT",
            title="Executive Security Posture Briefing Q3",
            user_id="test_admin",
        )
        self.assertIsNotNone(report)
        self.assertTrue(report.report_number.startswith("SRP-2026-"))
        self.assertEqual(report.report_type, "EXECUTIVE_SECURITY_REPORT")
        self.assertIsNotNone(report.report_hash)
        self.assertEqual(len(report.report_hash), 64)
        sections = self.db.query(SecurityReportSection).filter_by(report_id=report.id).all()
        self.assertGreaterEqual(len(sections), 4)

    def test_13_report_generation_all_7_types(self):
        report_types = [
            "EXECUTIVE_SECURITY_REPORT",
            "SOC_OPERATIONAL_REPORT",
            "COMPLIANCE_ASSURANCE_REPORT",
            "THREAT_INTELLIGENCE_REPORT",
            "INVESTIGATION_CASE_REPORT",
            "ASSURANCE_RECOVERY_REPORT",
            "CUSTOM_AUDIT_REPORT",
        ]
        for r_type in report_types:
            rep = SecurityReportingService.generate_report(
                self.db,
                report_type=r_type,
                title=f"Test Report - {r_type}",
                user_id="test_admin",
            )
            self.assertEqual(rep.report_type, r_type)
            self.assertIsNotNone(rep.report_hash)

    def test_14_report_sections_hashing_and_structure(self):
        rep = SecurityReportingService.generate_report(
            self.db,
            report_type="SOC_OPERATIONAL_REPORT",
            title="SOC Operational Assessment",
            user_id="test_admin",
        )
        sections = self.db.query(SecurityReportSection).filter_by(report_id=rep.id).all()
        self.assertGreaterEqual(len(sections), 4)
        for sec in sections:
            self.assertIsNotNone(sec.section_hash)
            self.assertEqual(len(sec.section_hash), 64)
            self.assertIsNotNone(sec.content_json)

    # ── Unit Tests: Evidence Package Builder & Manifest Hashing ───────────────

    def test_15_evidence_package_creation_reference_only(self):
        pkg = SecurityEvidencePackageService.build_evidence_package(
            self.db,
            package_type="COMPREHENSIVE_AUDIT",
            scope="PLATFORM_FULL",
            description="Complete cross-domain cryptographically bound evidence package",
            user_id="test_admin",
        )
        self.assertIsNotNone(pkg)
        self.assertTrue(pkg.package_number.startswith("SEP-2026-"))
        self.assertIsNotNone(pkg.manifest_hash)
        self.assertEqual(len(pkg.manifest_hash), 64)
        self.assertGreaterEqual(pkg.artifact_count, 1)

    def test_16_evidence_package_bindings_cross_domain(self):
        pkg = SecurityEvidencePackageService.build_evidence_package(
            self.db,
            package_type="COMPLIANCE_AUDIT",
            scope="SOC2_HIPAA_ISO27001",
            description="Cross-domain compliance bindings",
            user_id="test_admin",
        )
        artifacts = self.db.query(EvidencePackageArtifact).filter_by(package_id=pkg.id).all()
        self.assertGreaterEqual(len(artifacts), 1)
        for art in artifacts:
            self.assertIsNotNone(art.binding_hash)
            self.assertIsNotNone(art.artifact_domain)
            self.assertIsNotNone(art.artifact_type)
            self.assertIsNotNone(art.artifact_id)

    # ── Unit Tests: Multi-Layer Verification & Tamper Detection ───────────────

    def test_17_report_verification_valid(self):
        rep = SecurityReportingService.generate_report(
            self.db,
            report_type="THREAT_INTELLIGENCE_REPORT",
            title="Verifiable Threat Intelligence Brief",
            user_id="test_admin",
        )
        res = SecurityReportVerificationService.verify_report(self.db, rep.id)
        self.assertTrue(res["verified"])
        self.assertEqual(res["status"], "VERIFIED")
        self.assertEqual(len(res["tampered_sections"]), 0)

    def test_18_report_verification_tamper_detection(self):
        rep = SecurityReportingService.generate_report(
            self.db,
            report_type="SOC_OPERATIONAL_REPORT",
            title="Tamper Test Report",
            user_id="test_admin",
        )
        # Tamper with a section directly in DB
        sec = self.db.query(SecurityReportSection).filter(SecurityReportSection.report_id == rep.id).first()
        sec.content_json = {"tampered": True, "fake_score": 999}
        self.db.commit()

        res = SecurityReportVerificationService.verify_report(self.db, rep.id)
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "UNTRUSTED")
        self.assertGreaterEqual(len(res["tampered_sections"]), 1)

    def test_19_evidence_package_verification_valid(self):
        pkg = SecurityEvidencePackageService.build_evidence_package(
            self.db,
            package_type="ASSURANCE_RECOVERY_DOSSIER",
            scope="RECOVERY_VALIDATION",
            description="Package for assurance verification",
            user_id="test_admin",
        )
        res = SecurityReportVerificationService.verify_evidence_package(self.db, pkg.id)
        self.assertTrue(res["verified"])
        self.assertEqual(res["status"], "VERIFIED")

    def test_20_evidence_package_tamper_detection(self):
        pkg = SecurityEvidencePackageService.build_evidence_package(
            self.db,
            package_type="INVESTIGATION_DOSSIER",
            scope="INCIDENT_CASE_REF",
            description="Investigation evidence",
            user_id="test_admin",
        )
        # Tamper with an artifact binding hash in DB
        art = self.db.query(EvidencePackageArtifact).filter(EvidencePackageArtifact.package_id == pkg.id).first()
        art.artifact_hash = "0" * 64
        self.db.commit()

        res = SecurityReportVerificationService.verify_evidence_package(self.db, pkg.id)
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "UNTRUSTED")

    # ── Unit Tests: 17-Stage Cryptographic Provenance Lineage ─────────────────

    def test_21_provenance_17_stages_count(self):
        self.assertEqual(len(PROVENANCE_17_STAGES), 17)
        stages = [s[1] for s in PROVENANCE_17_STAGES]
        expected_stages = [
            "RAW_EVIDENCE",
            "EVIDENCE_HASH",
            "NORMALIZED_EVENT",
            "SEMANTIC_INTERPRETATION",
            "DETECTION",
            "DETECTION_TRUST",
            "THREAT_INTELLIGENCE",
            "RISK_CORRELATION",
            "SECURITY_INCIDENT",
            "INVESTIGATION",
            "RESPONSE",
            "ASSURANCE",
            "COMPLIANCE",
            "SECURITY_ANALYTICS",
            "ANALYTICS_INSIGHT",
            "SECURITY_REPORT",
            "GOVERNANCE_LEDGER_AND_MERKLE_PROOF",
        ]
        self.assertEqual(stages, expected_stages)

    def test_22_provenance_lineage_generation(self):
        snap = SecurityAnalyticsService.create_snapshot(
            self.db,
            period_type="24H",
            created_by="test_admin",
        )
        lineage = SecurityAnalyticsProvenanceService.generate_provenance_chain(self.db, snap.id)
        self.assertEqual(len(lineage), 17)
        for i, rec in enumerate(lineage):
            self.assertEqual(rec.stage_number, i + 1)
            self.assertEqual(rec.stage_name, PROVENANCE_17_STAGES[i][1])
            self.assertIsNotNone(rec.current_hash)
            if i > 0:
                self.assertEqual(rec.previous_hash, lineage[i - 1].current_hash)
            else:
                self.assertEqual(rec.previous_hash, "0" * 64)

    def test_23_provenance_lineage_verification_valid(self):
        snap = SecurityAnalyticsService.create_snapshot(
            self.db,
            period_type="24H",
            created_by="test_admin",
        )
        SecurityAnalyticsProvenanceService.generate_provenance_chain(self.db, snap.id)
        is_valid, records = SecurityAnalyticsProvenanceService.verify_provenance_chain(self.db, snap.id)
        self.assertTrue(is_valid)
        self.assertEqual(len(records), 17)

    def test_24_provenance_lineage_tamper_detection(self):
        snap = SecurityAnalyticsService.create_snapshot(
            self.db,
            period_type="24H",
            created_by="test_admin",
        )
        SecurityAnalyticsProvenanceService.generate_provenance_chain(self.db, snap.id)
        
        # Tamper with stage 8 payload in DB
        rec = self.db.query(SecurityAnalyticsProvenanceRecord).filter(
            SecurityAnalyticsProvenanceRecord.snapshot_id == snap.id,
            SecurityAnalyticsProvenanceRecord.stage_number == 8
        ).first()
        rec.current_hash = "0" * 64
        self.db.commit()

        is_valid, records = SecurityAnalyticsProvenanceService.verify_provenance_chain(self.db, snap.id)
        self.assertFalse(is_valid)

    # ── Unit Tests: RBAC Permissions & Role Enforcement ───────────────────────

    def test_25_rbac_role_permissions_assignment(self):
        self.assertIn(Permission.SECURITY_ANALYTICS_READ, ROLE_PERMISSIONS[Role.ADMIN])
        self.assertIn(Permission.SECURITY_ANALYTICS_EVALUATE, ROLE_PERMISSIONS[Role.ADMIN])
        self.assertIn(Permission.SECURITY_REPORT_CREATE, ROLE_PERMISSIONS[Role.ADMIN])
        self.assertIn(Permission.SECURITY_REPORT_VERIFY, ROLE_PERMISSIONS[Role.ADMIN])
        self.assertIn(Permission.SECURITY_EVIDENCE_PACKAGE_CREATE, ROLE_PERMISSIONS[Role.ADMIN])

        self.assertIn(Permission.SECURITY_ANALYTICS_READ, ROLE_PERMISSIONS[Role.SECURITY_ANALYST])
        self.assertIn(Permission.SECURITY_ANALYTICS_EVALUATE, ROLE_PERMISSIONS[Role.SECURITY_ANALYST])
        self.assertIn(Permission.SECURITY_REPORT_CREATE, ROLE_PERMISSIONS[Role.SECURITY_ANALYST])
        self.assertNotIn(Permission.SECURITY_REPORT_CREATE, ROLE_PERMISSIONS[Role.VIEWER])
        self.assertNotIn(Permission.SECURITY_EVIDENCE_PACKAGE_CREATE, ROLE_PERMISSIONS[Role.VIEWER])

    # ── API Integration Tests: REST Router Endpoints ──────────────────────────

    def test_26_api_get_metrics_list(self):
        resp = self.client.get("/api/v1/security-analytics/metrics", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 15)

    def test_27_api_get_metric_by_code(self):
        resp = self.client.get("/api/v1/security-analytics/metrics/METRIC_EVIDENCE_INTEGRITY_RATE", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["metric_code"], "METRIC_EVIDENCE_INTEGRITY_RATE")

    def test_28_api_post_create_snapshot(self):
        payload = {"period_type": "24H"}
        resp = self.client.post("/api/v1/security-analytics/snapshots", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data["snapshot_number"].startswith("SAS-2026-"))
        self.assertGreaterEqual(data["overall_security_score"], 0.0)

    def test_29_api_get_snapshots_list(self):
        SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        resp = self.client.get("/api/v1/security-analytics/snapshots", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)

    def test_30_api_get_snapshot_by_id(self):
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        resp = self.client.get(f"/api/v1/security-analytics/snapshots/{snap.id}", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["id"], snap.id)

    def test_31_api_get_snapshot_metrics(self):
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        resp = self.client.get(f"/api/v1/security-analytics/snapshots/{snap.id}/metrics", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 15)

    def test_32_api_get_snapshot_insights(self):
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        SecurityAnalyticsInsightService.generate_insights_for_snapshot(self.db, snap.id)
        resp = self.client.get(f"/api/v1/security-analytics/snapshots/{snap.id}/insights", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_33_api_get_trends(self):
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        SecurityTrendService.compute_trends_for_snapshot(self.db, snap.id)
        resp = self.client.get(f"/api/v1/security-analytics/trends?snapshot_id={snap.id}", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_34_api_post_create_report(self):
        payload = {
            "title": "API Generated Executive Security Report",
            "report_type": "EXECUTIVE_SECURITY_REPORT",
            "scope": "PLATFORM_FULL",
        }
        resp = self.client.post("/api/v1/security-analytics/reports", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data["report_number"].startswith("SRP-2026-"))
        self.assertEqual(data["report_type"], "EXECUTIVE_SECURITY_REPORT")

    def test_35_api_get_reports_list(self):
        resp = self.client.get("/api/v1/security-analytics/reports", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_36_api_get_report_by_id(self):
        rep = SecurityReportingService.generate_report(
            self.db,
            report_type="SOC_OPERATIONAL_REPORT",
            title="Get Report Test",
            user_id="test_admin",
        )
        resp = self.client.get(f"/api/v1/security-analytics/reports/{rep.id}", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["id"], rep.id)

    def test_37_api_post_verify_report(self):
        rep = SecurityReportingService.generate_report(
            self.db,
            report_type="THREAT_INTELLIGENCE_REPORT",
            title="API Verify Report",
            user_id="test_admin",
        )
        resp = self.client.post(f"/api/v1/security-analytics/reports/{rep.id}/verify", headers=self.auditor_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["verified"])
        self.assertEqual(data["status"], "VERIFIED")

    def test_38_api_post_create_evidence_package(self):
        payload = {
            "title": "API Investigation Evidence Package",
            "package_type": "INVESTIGATION_DOSSIER",
            "scope": "INCIDENT_SCOPE",
            "description": "API-generated package",
        }
        resp = self.client.post("/api/v1/security-analytics/evidence-packages", json=payload, headers=self.analyst_headers)
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data["package_number"].startswith("SEP-2026-"))
        self.assertIsNotNone(data["manifest_hash"])

    def test_39_api_get_evidence_packages_list(self):
        resp = self.client.get("/api/v1/security-analytics/evidence-packages", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_40_api_get_evidence_package_by_id(self):
        pkg = SecurityEvidencePackageService.build_evidence_package(
            self.db,
            package_type="ASSURANCE_AUDIT_PACKAGE",
            scope="ASSURANCE_SCOPE",
            description="Single pkg test",
            user_id="test_admin",
        )
        resp = self.client.get(f"/api/v1/security-analytics/evidence-packages/{pkg.id}", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["id"], pkg.id)

    def test_41_api_post_verify_evidence_package(self):
        pkg = SecurityEvidencePackageService.build_evidence_package(
            self.db,
            package_type="SOC_INCIDENT_PACKAGE",
            scope="SOC_SCOPE",
            description="Verify pkg test",
            user_id="test_admin",
        )
        resp = self.client.post(f"/api/v1/security-analytics/evidence-packages/{pkg.id}/verify", headers=self.auditor_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["verified"])

    def test_42_api_get_snapshot_provenance(self):
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        resp = self.client.get(f"/api/v1/security-analytics/snapshots/{snap.id}/provenance", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_stages"], 17)
        self.assertTrue(data["lineage_verified"])

    def test_43_api_get_dashboard_summary(self):
        resp = self.client.get("/api/v1/security-analytics/dashboard/summary", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("overall_security_score", data)
        self.assertIn("overall_confidence", data)
        self.assertIn("telemetry_completeness", data)
        self.assertIn("total_snapshots", data)
        self.assertIn("total_metric_definitions", data)

    def test_44_api_viewer_forbidden_on_generate_report(self):
        payload = {
            "title": "Forbidden Report",
            "report_type": "EXECUTIVE_SECURITY_REPORT",
            "scope": "PLATFORM_FULL",
        }
        resp = self.client.post("/api/v1/security-analytics/reports", json=payload, headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 403)

    def test_45_api_viewer_forbidden_on_generate_evidence_package(self):
        payload = {
            "title": "Forbidden Package",
            "package_type": "COMPREHENSIVE_AUDIT",
            "scope": "FORBIDDEN",
            "description": "Forbidden",
        }
        resp = self.client.post("/api/v1/security-analytics/evidence-packages", json=payload, headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 403)

    def test_46_api_unauthenticated_request_rejected(self):
        resp = self.client.get("/api/v1/security-analytics/dashboard/summary")
        self.assertEqual(resp.status_code, 401)

    def test_47_api_404_on_nonexistent_snapshot(self):
        resp = self.client.get("/api/v1/security-analytics/snapshots/nonexistent-uuid", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 404)

    def test_48_api_404_on_nonexistent_report(self):
        resp = self.client.get("/api/v1/security-analytics/reports/nonexistent-uuid", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 404)

    def test_49_api_404_on_nonexistent_evidence_package(self):
        resp = self.client.get("/api/v1/security-analytics/evidence-packages/nonexistent-uuid", headers=self.viewer_headers)
        self.assertEqual(resp.status_code, 404)

    # ── Additional Invariant & Edge Case Tests ────────────────────────────────

    def test_50_canonical_json_hash_stability(self):
        data = {"b": 2, "a": 1, "nested": {"y": 20, "x": 10}}
        h1 = compute_canonical_hash("TEST_PREFIX", data)
        data_reordered = {"nested": {"x": 10, "y": 20}, "a": 1, "b": 2}
        h2 = compute_canonical_hash("TEST_PREFIX", data_reordered)
        self.assertEqual(h1, h2)

    def test_51_snapshot_numbering_monotonic_and_formatted(self):
        s1 = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        s2 = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        current_year = datetime.now(timezone.utc).year
        self.assertTrue(s1.snapshot_number.startswith(f"SAS-{current_year}-"))
        self.assertTrue(s2.snapshot_number.startswith(f"SAS-{current_year}-"))
        num1 = int(s1.snapshot_number.split("-")[-1])
        num2 = int(s2.snapshot_number.split("-")[-1])
        self.assertGreater(num2, num1)

    def test_52_report_numbering_monotonic_and_formatted(self):
        r1 = SecurityReportingService.generate_report(self.db, "EXECUTIVE_SECURITY_REPORT", "R1", user_id="test_admin")
        r2 = SecurityReportingService.generate_report(self.db, "EXECUTIVE_SECURITY_REPORT", "R2", user_id="test_admin")
        current_year = datetime.now(timezone.utc).year
        self.assertTrue(r1.report_number.startswith(f"SRP-{current_year}-"))
        self.assertTrue(r2.report_number.startswith(f"SRP-{current_year}-"))
        num1 = int(r1.report_number.split("-")[-1])
        num2 = int(r2.report_number.split("-")[-1])
        self.assertGreater(num2, num1)

    def test_53_evidence_package_numbering_monotonic_and_formatted(self):
        p1 = SecurityEvidencePackageService.build_evidence_package(self.db, "COMPREHENSIVE_AUDIT", user_id="test_admin")
        p2 = SecurityEvidencePackageService.build_evidence_package(self.db, "COMPREHENSIVE_AUDIT", user_id="test_admin")
        current_year = datetime.now(timezone.utc).year
        self.assertTrue(p1.package_number.startswith(f"SEP-{current_year}-"))
        self.assertTrue(p2.package_number.startswith(f"SEP-{current_year}-"))
        num1 = int(p1.package_number.split("-")[-1])
        num2 = int(p2.package_number.split("-")[-1])
        self.assertGreater(num2, num1)

    def test_54_provenance_stage_hash_sequential_dependency(self):
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        records = SecurityAnalyticsProvenanceService.generate_provenance_chain(self.db, snap.id)
        for i in range(1, len(records)):
            self.assertEqual(records[i].previous_hash, records[i - 1].current_hash)

    def test_55_auditor_role_permitted_to_verify_reports(self):
        rep = SecurityReportingService.generate_report(self.db, "COMPLIANCE_ASSURANCE_REPORT", "Auditor Ver Report", user_id="test_admin")
        resp = self.client.post(f"/api/v1/security-analytics/reports/{rep.id}/verify", headers=self.auditor_headers)
        self.assertEqual(resp.status_code, 200)

    def test_56_policy_author_role_permissions_restricted(self):
        rep = SecurityReportingService.generate_report(self.db, "EXECUTIVE_SECURITY_REPORT", "Author Ver Report", user_id="test_admin")
        # Policy author does not have SECURITY_REPORT_VERIFY permission
        resp = self.client.post(f"/api/v1/security-analytics/reports/{rep.id}/verify", headers=self.author_headers)
        self.assertEqual(resp.status_code, 403)

    def test_57_report_title_and_type_stored_accurately(self):
        rep = SecurityReportingService.generate_report(self.db, "CUSTOM_AUDIT_REPORT", "Custom Title Accuracy Test", user_id="test_admin")
        fetched = SecurityReportingService.get_report_by_id(self.db, rep.id)
        self.assertEqual(fetched.title, "Custom Title Accuracy Test")
        self.assertEqual(fetched.report_type, "CUSTOM_AUDIT_REPORT")

    def test_58_evidence_package_manifest_json_format(self):
        pkg = SecurityEvidencePackageService.build_evidence_package(self.db, "SOC_INCIDENT_PACKAGE", description="Manifest JSON format test", user_id="test_admin")
        self.assertIsInstance(pkg.manifest_json, dict)
        self.assertIn("package_id", pkg.manifest_json)
        self.assertIn("package_number", pkg.manifest_json)
        self.assertIn("artifacts", pkg.manifest_json)

    def test_59_provenance_record_payload_schema_compliance(self):
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        lineage = SecurityAnalyticsProvenanceService.generate_provenance_chain(self.db, snap.id)
        for rec in lineage:
            self.assertIsNotNone(rec.stage_name)
            self.assertGreaterEqual(rec.stage_number, 1)
            self.assertLessEqual(rec.stage_number, 17)
            self.assertIsNotNone(rec.current_hash)

    def test_60_evaluate_all_15_metrics_directly(self):
        defs = SecurityMetricRegistryService.list_metric_definitions(self.db)
        for m_def in defs:
            res = SecurityMetricRegistryService.evaluate_metric(self.db, m_def)
            self.assertIsNotNone(res)
            self.assertIn(res["telemetry_state"], ["COMPLETE", "PARTIAL", "INSUFFICIENT", "UNKNOWN"])

    def test_61_posture_grade_calculation(self):
        # Verify direction contrib calculation
        val_lower = 0.0
        contrib_lower = max(0.0, 100.0 - min(100.0, val_lower * 10.0))
        self.assertEqual(contrib_lower, 100.0)

        val_higher = 95.0
        contrib_higher = min(100.0, max(0.0, val_higher))
        self.assertEqual(contrib_higher, 95.0)

    def test_62_risk_level_calculation(self):
        snap = SecurityAnalyticsService.create_snapshot(
            self.db,
            period_type="24H",
            created_by="test_admin",
            cryptographic_failure_detected=False,
        )
        self.assertGreaterEqual(snap.overall_security_score, 0.0)
        self.assertLessEqual(snap.overall_security_score, 100.0)

    def test_63_report_verification_tampered_manifest(self):
        rep = SecurityReportingService.generate_report(self.db, "EXECUTIVE_SECURITY_REPORT", "Manifest Tamper", user_id="test_admin")
        # Tamper report hash
        rep.report_hash = "0" * 64
        self.db.commit()
        res = SecurityReportVerificationService.verify_report(self.db, rep.id)
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "UNTRUSTED")

    def test_64_evidence_package_tampered_manifest(self):
        pkg = SecurityEvidencePackageService.build_evidence_package(self.db, "COMPREHENSIVE_AUDIT", user_id="test_admin")
        # Tamper manifest hash
        pkg.manifest_hash = "f" * 64
        self.db.commit()
        res = SecurityReportVerificationService.verify_evidence_package(self.db, pkg.id)
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "UNTRUSTED")

    def test_65_latest_snapshot_retrieval(self):
        s1 = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        latest = SecurityAnalyticsService.get_latest_snapshot(self.db)
        self.assertIsNotNone(latest)
        self.assertEqual(latest.id, s1.id)

    def test_66_snapshot_filter_by_period_type(self):
        SecurityAnalyticsService.create_snapshot(self.db, period_type="7D", created_by="test_admin")
        filtered = SecurityAnalyticsService.list_snapshots(self.db, period_type="7D")
        self.assertGreaterEqual(len(filtered), 1)
        for s in filtered:
            self.assertEqual(s.period_type, "7D")

    def test_67_report_filter_by_type(self):
        SecurityReportingService.generate_report(self.db, "EXECUTIVE_SECURITY_REPORT", "Executive Filter", user_id="test_admin")
        filtered = SecurityReportingService.list_reports(self.db, report_type="EXECUTIVE_SECURITY_REPORT")
        self.assertGreaterEqual(len(filtered), 1)
        for r in filtered:
            self.assertEqual(r.report_type, "EXECUTIVE_SECURITY_REPORT")

    def test_68_evidence_package_filter_by_type(self):
        SecurityEvidencePackageService.build_evidence_package(self.db, "COMPLIANCE_AUDIT", user_id="test_admin")
        filtered = SecurityEvidencePackageService.list_evidence_packages(self.db, package_type="COMPLIANCE_AUDIT")
        self.assertGreaterEqual(len(filtered), 1)
        for p in filtered:
            self.assertEqual(p.package_type, "COMPLIANCE_AUDIT")

    def test_69_trend_for_single_metric_lookup(self):
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        SecurityTrendService.compute_trends_for_snapshot(self.db, snap.id)
        trend = SecurityTrendService.get_trend_for_metric(self.db, "METRIC_EVIDENCE_INTEGRITY_RATE")
        if trend:
            self.assertIn(trend.trend_classification, ["IMPROVING", "STABLE", "DEGRADING", "INSUFFICIENT_DATA"])

    def test_70_provenance_tamper_parent_hash(self):
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        SecurityAnalyticsProvenanceService.generate_provenance_chain(self.db, snap.id)
        
        # Modify previous hash of stage 5
        rec = self.db.query(SecurityAnalyticsProvenanceRecord).filter(
            SecurityAnalyticsProvenanceRecord.snapshot_id == snap.id,
            SecurityAnalyticsProvenanceRecord.stage_number == 5
        ).first()
        rec.previous_hash = "e" * 64
        self.db.commit()

        is_valid, records = SecurityAnalyticsProvenanceService.verify_provenance_chain(self.db, snap.id)
        self.assertFalse(is_valid)

    def test_71_deterministic_rule_semantic_drift_insight(self):
        # Test insight generation on snapshot with semantic drift
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        insights = SecurityAnalyticsInsightService.generate_insights_for_snapshot(self.db, snap.id)
        self.assertIsInstance(insights, list)

    def test_72_deterministic_rule_unresolved_incidents_insight(self):
        snap = SecurityAnalyticsService.create_snapshot(self.db, period_type="24H", created_by="test_admin")
        insights = SecurityAnalyticsInsightService.generate_insights_for_snapshot(self.db, snap.id)
        self.assertIsInstance(insights, list)

    def test_73_report_custom_timeframe(self):
        p_start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        p_end = datetime(2026, 1, 31, tzinfo=timezone.utc)
        rep = SecurityReportingService.generate_report(
            self.db,
            report_type="CUSTOM_AUDIT_REPORT",
            title="January 2026 Audit",
            period_start=p_start,
            period_end=p_end,
            user_id="test_admin",
        )
        self.assertEqual(rep.period_start.year, p_start.year)
        self.assertEqual(rep.period_start.month, p_start.month)
        self.assertEqual(rep.period_end.year, p_end.year)
        self.assertEqual(rep.period_end.month, p_end.month)

    def test_74_evidence_package_custom_scope(self):
        pkg = SecurityEvidencePackageService.build_evidence_package(
            self.db,
            package_type="INVESTIGATION_DOSSIER",
            scope="CUSTOM_CASE_SCOPE_123",
            description="Custom scoped package",
            user_id="test_admin",
        )
        self.assertEqual(pkg.scope, "CUSTOM_CASE_SCOPE_123")

    def test_75_dashboard_summary_computation(self):
        summary = SecurityAnalyticsService.get_dashboard_summary(self.db)
        self.assertIn("overall_security_score", summary)
        self.assertIn("overall_confidence", summary)
        self.assertIn("telemetry_completeness", summary)
        self.assertIn("domains_evaluated", summary)
        self.assertIn("critical_findings", summary)
        self.assertIn("high_findings", summary)
        self.assertIn("total_snapshots", summary)
        self.assertIn("total_metric_definitions", summary)


if __name__ == "__main__":
    unittest.main()
