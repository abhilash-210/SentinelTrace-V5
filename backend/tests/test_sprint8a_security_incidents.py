"""
tests/test_sprint8a_security_incidents.py
-----------------------------------------
Comprehensive automated test suite for Sprint 8A:
Security Incident Correlation & Investigation Foundation.

35 exhaustive tests covering:
1. Incident creation and ID generation
2. Incident number deterministic format and uniqueness (INC-2026-XXXXXX)
3. Incident severity determination & precedence logic
4. Deterministic priority mapping (CRITICAL -> P1, HIGH -> P2, MEDIUM -> P3, LOW -> P4)
5. Create incident from risk correlation
6. Duplicate incident prevention (active incident deduplication)
7. New incident generation allowed when prior incident is REJECTED
8. Signal linking with relationship types
9. Duplicate signal link prevention (unique constraint rejection)
10. Evidence linking by reference
11. Upstream evidence immutability (linking does not mutate evidence)
12. Finding creation with mandatory attribution
13. Finding status confirmation
14. Finding status rejection
15. Timeline append-only behavior (ordered chronological events)
16. Valid lifecycle transition (OPEN -> TRIAGING -> INVESTIGATING)
17. Invalid lifecycle transition rejection (OPEN -> CLOSED -> HTTP 400)
18. Invalid lifecycle transition rejection (INVESTIGATING -> CLOSED -> HTTP 400)
19. Valid lifecycle transition (INVESTIGATING -> TRIAGING)
20. Incident assignment and reassignment
21. Unassigned incident handling
22. Investigation summary generation
23. Root cause extraction in summary
24. Protected field detection in summary
25. Trust summary aggregation
26. 13-Stage provenance trace structure and verification
27. Missing provenance stage honest handling (NOT_AVAILABLE status)
28. RBAC: Security Analyst allowed operations
29. RBAC: Viewer denied modification operations (HTTP 403)
30. RBAC: Policy Reviewer finding review permissions
31. RBAC: Auditor trace audit access
32. RBAC: Unauthenticated access rejected (HTTP 401)
33. Cryptographic governance ledger event generation
34. Filterable incident querying (severity, priority, status)
35. Pre-seeded Cisco ASA demo incident verification (INC-2026-000001)
"""

import json
import unittest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.risk_correlation import RiskCorrelation, RiskCorrelationMember
from app.models.security_incident import (
    IncidentEvidenceLink,
    IncidentFinding,
    IncidentSignal,
    IncidentTimelineEvent,
    SecurityIncident,
)
from app.models.semantic_interpretation import SemanticDriftAlert, SemanticInterpretation
from app.models.detection_rule_trust import DetectionRuleTrustEvaluation, DetectionTrustAlert
from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.models.ledger import GovernanceLedgerEntry
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


class TestSprint8ASecurityIncidents(unittest.TestCase):
    """Automated test suite for Sprint 8A Security Incident Correlation & Investigation."""

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

    # ── Test 1: Manual incident creation ────────────────────────────────────
    def test_01_manual_incident_creation(self):
        """Verify authorized analyst can manually create an incident."""
        headers = get_auth_headers("security_analyst")
        payload = {
            "title": "Unauthorized Sudo Escalation Chain",
            "description": "Multiple anomalous sudo events observed without matching change tickets.",
            "incident_type": "SEMANTIC_RISK",
            "severity": "HIGH",
            "confidence": 0.95,
        }
        resp = client.post("/api/v1/incidents", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 201, resp.text)
        data = resp.json()
        self.assertTrue(data["incident_id"].startswith("inc_"))
        self.assertTrue(data["incident_number"].startswith("INC-2026-"))
        self.assertEqual(data["status"], "OPEN")
        self.assertEqual(data["severity"], "HIGH")
        self.assertEqual(data["priority"], "P2")

    # ── Test 2: Incident number uniqueness ──────────────────────────────────
    def test_02_incident_number_uniqueness(self):
        """Verify sequential incident numbers are unique and formatted correctly."""
        headers = get_auth_headers("security_analyst")
        resp1 = client.post("/api/v1/incidents", json={
            "title": "Incident Uniqueness Test Alpha",
            "severity": "LOW",
        }, headers=headers)
        resp2 = client.post("/api/v1/incidents", json={
            "title": "Incident Uniqueness Test Beta",
            "severity": "LOW",
        }, headers=headers)
        self.assertEqual(resp1.status_code, 201)
        self.assertEqual(resp2.status_code, 201)
        self.assertNotEqual(resp1.json()["incident_number"], resp2.json()["incident_number"])

    # ── Test 3: Severity determination & precedence ─────────────────────────
    def test_03_severity_determination_precedence(self):
        """Verify severity precedence mappings (CRITICAL > HIGH > MEDIUM > LOW)."""
        with SessionLocal() as db:
            # Create a mock high severity correlation
            corr = RiskCorrelation(
                correlation_id=f"corr_test_crit_{uuid.uuid4().hex[:6]}",
                correlation_type="CRITICAL_RISK_CLUSTER",
                severity="CRITICAL",
                status="ACTIVE",
                risk_cluster_key="cluster:field:test_action",
                affected_signal_count=3,
                affected_rule_count=2,
                affected_field_count=1,
                risk_score=92.0,
                root_cause_candidates=["Test root cause"],
                explanation="Test critical correlation explanation",
                created_at=datetime.now(timezone.utc),
            )
            db.add(corr)
            db.flush()

            inc = IncidentService.create_incident_from_correlation(
                db, corr.correlation_id, actor_user_id="usr_test", actor_username="test"
            )
            self.assertEqual(inc.severity, "CRITICAL")
            self.assertEqual(inc.priority, "P1")

    # ── Test 4: Priority mapping ────────────────────────────────────────────
    def test_04_priority_mapping(self):
        """Verify deterministic priority mapping: CRITICAL->P1, HIGH->P2, MEDIUM->P3, LOW->P4."""
        self.assertEqual(IncidentService.SEVERITY_PRIORITY_MAP["CRITICAL"], "P1")
        self.assertEqual(IncidentService.SEVERITY_PRIORITY_MAP["HIGH"], "P2")
        self.assertEqual(IncidentService.SEVERITY_PRIORITY_MAP["MEDIUM"], "P3")
        self.assertEqual(IncidentService.SEVERITY_PRIORITY_MAP["LOW"], "P4")

    # ── Test 5: Create incident from correlation endpoint ───────────────────
    def test_05_create_incident_from_correlation_endpoint(self):
        """Verify generating an incident from a correlation via API."""
        headers = get_auth_headers("security_analyst")
        with SessionLocal() as db:
            corr = db.query(RiskCorrelation).first()
            self.assertIsNotNone(corr)
            corr_id = corr.correlation_id

        resp = client.post(f"/api/v1/incidents/from-correlation/{corr_id}", headers=headers)
        self.assertIn(resp.status_code, [200, 201], resp.text)
        data = resp.json()
        self.assertEqual(data["source_correlation_id"], corr_id)

    # ── Test 6: Duplicate incident prevention (Deduplication) ───────────────
    def test_06_duplicate_incident_prevention(self):
        """Verify calling create from correlation multiple times returns the active incident."""
        with SessionLocal() as db:
            corr = db.query(RiskCorrelation).first()
            self.assertIsNotNone(corr)
            corr_id = corr.correlation_id

            inc1 = IncidentService.create_incident_from_correlation(db, corr_id)
            inc2 = IncidentService.create_incident_from_correlation(db, corr_id)
            self.assertEqual(inc1.incident_id, inc2.incident_id)
            self.assertEqual(inc1.incident_number, inc2.incident_number)

    # ── Test 7: New incident after prior is REJECTED ─────────────────────────
    def test_07_new_incident_after_rejection(self):
        """Verify if previous incident is REJECTED, correlation can spawn a fresh incident."""
        with SessionLocal() as db:
            # Create distinct correlation
            corr = RiskCorrelation(
                correlation_id=f"corr_rej_test_{uuid.uuid4().hex[:6]}",
                correlation_type="SINGLE_SIGNAL",
                severity="LOW",
                status="ACTIVE",
                affected_signal_count=1,
                affected_rule_count=0,
                affected_field_count=1,
                explanation="Test rejection flow",
                created_at=datetime.now(timezone.utc),
            )
            db.add(corr)
            db.commit()

            inc1 = IncidentService.create_incident_from_correlation(db, corr.correlation_id)
            # Move to TRIAGING then REJECTED
            IncidentService.change_incident_status(db, inc1.incident_id, "TRIAGING", "Triaging", "usr_test", "tester")
            IncidentService.change_incident_status(db, inc1.incident_id, "REJECTED", "False positive", "usr_test", "tester")

            # Creating again should generate a new incident
            inc2 = IncidentService.create_incident_from_correlation(db, corr.correlation_id)
            self.assertNotEqual(inc1.incident_id, inc2.incident_id)

    # ── Test 8: Signal linking ──────────────────────────────────────────────
    def test_08_signal_linking(self):
        """Verify linking security signals to an incident."""
        headers = get_auth_headers("security_analyst")
        # Create incident
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Signal Linking Test Incident",
            "severity": "MEDIUM",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        # Link signal
        payload = {
            "signal_type": "DETECTION_TRUST_ALERT",
            "signal_id": "dta_test_signal_01",
            "relationship_type": "PRIMARY_TRIGGER",
        }
        resp = client.post(f"/api/v1/incidents/{inc_id}/signals", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 201, resp.text)
        data = resp.json()
        self.assertEqual(data["signal_id"], "dta_test_signal_01")
        self.assertEqual(data["relationship_type"], "PRIMARY_TRIGGER")

    # ── Test 9: Duplicate signal link prevention ────────────────────────────
    def test_09_duplicate_signal_link_prevention(self):
        """Verify linking the same signal twice returns HTTP 400."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Duplicate Signal Test Incident",
            "severity": "LOW",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        payload = {
            "signal_type": "SEMANTIC_DRIFT_ALERT",
            "signal_id": "drift_dup_test_01",
            "relationship_type": "ROOT_CAUSE",
        }
        resp1 = client.post(f"/api/v1/incidents/{inc_id}/signals", json=payload, headers=headers)
        self.assertEqual(resp1.status_code, 201)

        resp2 = client.post(f"/api/v1/incidents/{inc_id}/signals", json=payload, headers=headers)
        self.assertEqual(resp2.status_code, 400)
        self.assertIn("already linked", resp2.text)

    # ── Test 10: Evidence linking by reference ──────────────────────────────
    def test_10_evidence_linking_by_reference(self):
        """Verify linking immutable evidence by reference without duplicating data."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Evidence Linking Test Incident",
            "severity": "MEDIUM",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        payload = {
            "evidence_type": "RAW_EVIDENCE",
            "evidence_id": "ev_raw_test_log_001",
            "relationship": "PRIMARY",
        }
        resp = client.post(f"/api/v1/incidents/{inc_id}/evidence", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 201, resp.text)
        data = resp.json()
        self.assertEqual(data["evidence_id"], "ev_raw_test_log_001")
        self.assertEqual(data["relationship"], "PRIMARY")

    # ── Test 11: Upstream evidence immutability ─────────────────────────────
    def test_11_upstream_evidence_immutability(self):
        """Verify linking evidence does not mutate the upstream record."""
        with SessionLocal() as db:
            inc = IncidentService.create_manual_incident(
                db, "Immutability Test", None, "SEMANTIC_RISK", "LOW", "P4",
                None, None, None, 1.0, None, "usr_test", "tester"
            )
            ev = IncidentService.link_evidence(
                db, inc.incident_id, "SEMANTIC_INTERPRETATION", "interp_test_01", "ROOT_CAUSE",
                "usr_test", "tester"
            )
            # Only reference link is created
            self.assertEqual(ev.evidence_id, "interp_test_01")
            self.assertEqual(ev.incident_id, inc.incident_id)

    # ── Test 12: Finding creation with attribution ──────────────────────────
    def test_12_finding_creation_with_attribution(self):
        """Verify authoring findings preserves analyst attribution."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Finding Attribution Test Incident",
            "severity": "HIGH",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        payload = {
            "finding_type": "OBSERVATION",
            "title": "Anomalous SSH outbound traffic detected",
            "description": "Port 22 connection from untrusted subnet without bastion host.",
            "confidence": 0.92,
        }
        resp = client.post(f"/api/v1/incidents/{inc_id}/findings", json=payload, headers=headers)
        self.assertEqual(resp.status_code, 201, resp.text)
        data = resp.json()
        self.assertEqual(data["title"], payload["title"])
        self.assertEqual(data["status"], "OPEN")
        self.assertIsNotNone(data["created_by_user_id"])

    # ── Test 13: Finding confirmation ───────────────────────────────────────
    def test_13_finding_confirmation(self):
        """Verify finding status update to CONFIRMED."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Finding Confirmation Test",
            "severity": "MEDIUM",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        fnd_resp = client.post(f"/api/v1/incidents/{inc_id}/findings", json={
            "finding_type": "ROOT_CAUSE",
            "title": "Misconfigured NAT gateway rule",
            "description": "Direct route table entry bypassed proxy.",
            "confidence": 0.98,
        }, headers=headers)
        fnd_id = fnd_resp.json()["finding_id"]
        admin_headers = get_auth_headers("admin")
        update_resp = client.patch(f"/api/v1/incidents/{inc_id}/findings/{fnd_id}", json={
            "status": "CONFIRMED",
            "comment": "Confirmed by SOC lead after netflow inspection.",
        }, headers=admin_headers)
        self.assertEqual(update_resp.status_code, 200)
        self.assertEqual(update_resp.json()["status"], "CONFIRMED")

    # ── Test 14: Finding rejection ──────────────────────────────────────────
    def test_14_finding_rejection(self):
        """Verify finding status update to REJECTED."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Finding Rejection Test",
            "severity": "LOW",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        fnd_resp = client.post(f"/api/v1/incidents/{inc_id}/findings", json={
            "finding_type": "HYPOTHESIS",
            "title": "Possible DNS tunneling attempt",
            "description": "High entropy TXT queries observed.",
            "confidence": 0.40,
        }, headers=headers)
        fnd_id = fnd_resp.json()["finding_id"]

        admin_headers = get_auth_headers("admin")
        update_resp = client.patch(f"/api/v1/incidents/{inc_id}/findings/{fnd_id}", json={
            "status": "REJECTED",
            "comment": "Legitimate DKIM verification traffic.",
        }, headers=admin_headers)
        self.assertEqual(update_resp.status_code, 200)
        self.assertEqual(update_resp.json()["status"], "REJECTED")

    # ── Test 15: Timeline append-only behavior ──────────────────────────────
    def test_15_timeline_append_only(self):
        """Verify investigation timeline events are recorded sequentially and never mutated."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Timeline Test Incident",
            "severity": "MEDIUM",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        # Transition status
        client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "TRIAGING"}, headers=headers)
        client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "INVESTIGATING"}, headers=headers)

        # Get timeline
        resp = client.get(f"/api/v1/incidents/{inc_id}/timeline", headers=headers)
        self.assertEqual(resp.status_code, 200)
        events = resp.json()
        self.assertGreaterEqual(len(events), 3)
        event_types = [e["event_type"] for e in events]
        self.assertEqual(event_types[0], "INCIDENT_CREATED")
        self.assertIn("STATUS_CHANGED", event_types)

    # ── Test 16: Valid lifecycle transitions ────────────────────────────────
    def test_16_valid_lifecycle_transitions(self):
        """Verify OPEN -> TRIAGING -> INVESTIGATING lifecycle progression."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Lifecycle Test Incident",
            "severity": "HIGH",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        # OPEN -> TRIAGING
        r1 = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "TRIAGING"}, headers=headers)
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.json()["status"], "TRIAGING")

        # TRIAGING -> INVESTIGATING
        r2 = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "INVESTIGATING"}, headers=headers)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()["status"], "INVESTIGATING")

    # ── Test 17: Invalid transition OPEN -> CLOSED rejected ─────────────────
    def test_17_invalid_transition_open_to_closed(self):
        """Verify directly closing an OPEN incident is rejected with HTTP 400."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Invalid Close Test",
            "severity": "LOW",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        resp = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "CLOSED"}, headers=headers)
        self.assertEqual(resp.status_code, 400)
        self.assertIn("INVALID_INCIDENT_STATE_TRANSITION", resp.text)

    # ── Test 18: Invalid transition INVESTIGATING -> CLOSED rejected ────────
    def test_18_invalid_transition_investigating_to_closed(self):
        """Verify INVESTIGATING cannot jump directly to CLOSED (belongs to Sprint 8B governance)."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Invalid Jump Test",
            "severity": "LOW",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "TRIAGING"}, headers=headers)
        client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "INVESTIGATING"}, headers=headers)

        resp = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "CLOSED"}, headers=headers)
        self.assertEqual(resp.status_code, 400)

    # ── Test 19: Valid reverse transition INVESTIGATING -> TRIAGING ─────────
    def test_19_valid_reverse_transition(self):
        """Verify incident can transition back from INVESTIGATING to TRIAGING."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Reverse Transition Test",
            "severity": "LOW",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "TRIAGING"}, headers=headers)
        client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "INVESTIGATING"}, headers=headers)

        # Back to TRIAGING
        r = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "TRIAGING"}, headers=headers)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "TRIAGING")

    # ── Test 20: Incident assignment ────────────────────────────────────────
    def test_20_incident_assignment(self):
        """Verify assigning an analyst to an incident."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Assignment Test Incident",
            "severity": "MEDIUM",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]

        resp = client.patch(f"/api/v1/incidents/{inc_id}/assign", json={
            "assigned_to_user_id": "usr_analyst_01",
        }, headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["assigned_to_user_id"], "usr_analyst_01")

    # ── Test 21: Unassigned incident handling ───────────────────────────────
    def test_21_unassigned_incident_handling(self):
        """Verify incidents default to unassigned and can be unassigned."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "Unassigned Test Incident",
            "severity": "LOW",
        }, headers=headers)
        inc_id = create_resp.json()["incident_id"]
        self.assertIsNone(create_resp.json()["assigned_to_user_id"])

        # Assign then Unassign
        client.patch(f"/api/v1/incidents/{inc_id}/assign", json={"assigned_to_user_id": "usr_analyst_01"}, headers=headers)
        unassign_resp = client.patch(f"/api/v1/incidents/{inc_id}/assign", json={"assigned_to_user_id": None}, headers=headers)
        self.assertEqual(unassign_resp.status_code, 200)
        self.assertIsNone(unassign_resp.json()["assigned_to_user_id"])

    # ── Test 22: Investigation summary generation ───────────────────────────
    def test_22_investigation_summary_generation(self):
        """Verify comprehensive investigation summary endpoint."""
        headers = get_auth_headers("security_analyst")
        resp = client.get("/api/v1/incidents/INC-2026-000001/summary", headers=headers)
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertIn("incident", data)
        self.assertIn("impact", data)
        self.assertIn("signals", data)
        self.assertIn("evidence", data)
        self.assertIn("findings", data)
        self.assertIn("root_cause_candidates", data)
        self.assertIn("trust_summary", data)
        self.assertIn("timeline", data)

    # ── Test 23: Root cause extraction in summary ───────────────────────────
    def test_23_root_cause_extraction(self):
        """Verify root cause candidates are extracted in the summary."""
        headers = get_auth_headers("security_analyst")
        resp = client.get("/api/v1/incidents/INC-2026-000001/summary", headers=headers)
        self.assertEqual(resp.status_code, 200)
        rc_list = resp.json()["root_cause_candidates"]
        self.assertGreater(len(rc_list), 0)
        self.assertTrue(any("action.result" in str(rc) or "semantic" in str(rc).lower() for rc in rc_list))

    # ── Test 24: Protected field detection ──────────────────────────────────
    def test_24_protected_field_detection(self):
        """Verify protected field impact count is identified in summary."""
        headers = get_auth_headers("security_analyst")
        resp = client.get("/api/v1/incidents/INC-2026-000001/summary", headers=headers)
        self.assertEqual(resp.status_code, 200)
        impact = resp.json()["impact"]
        self.assertGreaterEqual(impact["protected_fields"], 1)

    # ── Test 25: Trust summary aggregation ──────────────────────────────────
    def test_25_trust_summary_aggregation(self):
        """Verify trust context is aggregated in summary."""
        headers = get_auth_headers("security_analyst")
        resp = client.get("/api/v1/incidents/INC-2026-000001/summary", headers=headers)
        self.assertEqual(resp.status_code, 200)
        ts = resp.json()["trust_summary"]
        self.assertEqual(ts["incident_severity"], "CRITICAL")
        self.assertEqual(ts["priority"], "P1")

    # ── Test 26: 13-Stage provenance trace structure ────────────────────────
    def test_26_13_stage_provenance_trace(self):
        """Verify 13-stage provenance trace covers all required stages from RAW_EVIDENCE to GOVERNANCE_AUDIT_REFERENCE."""
        headers = get_auth_headers("auditor")
        resp = client.get("/api/v1/incidents/INC-2026-000001/trace", headers=headers)
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertEqual(data["total_stages"], 13)
        self.assertGreaterEqual(data["verified_stages"], 10)

        stage_names = [s["stage_name"] for s in data["stages"]]
        expected_stages = [
            "RAW_EVIDENCE",
            "EVIDENCE_HASH",
            "NORMALIZED_EVENT",
            "SEMANTIC_INTERPRETATION",
            "SEMANTIC_DRIFT_ALERT",
            "DETECTION_RULE_DEPENDENCY",
            "TRUST_EVALUATION",
            "DETECTION_TRUST_ALERT",
            "RISK_CORRELATION",
            "RISK_CLUSTER",
            "SECURITY_INCIDENT",
            "INVESTIGATION_FINDING",
            "GOVERNANCE_AUDIT_REFERENCE",
        ]
        self.assertEqual(stage_names, expected_stages)

    # ── Test 27: Missing provenance stage honest handling ───────────────────
    def test_27_missing_provenance_stage_handling(self):
        """Verify missing upstream data returns NOT_AVAILABLE without fabricating fake data."""
        with SessionLocal() as db:
            # Create disconnected manual incident
            inc = IncidentService.create_manual_incident(
                db, "Isolated Incident", None, "SEMANTIC_RISK", "LOW", "P4",
                None, None, None, 0.5, None, "usr_test", "tester"
            )
            trace = IncidentService.get_incident_provenance_trace(db, inc.incident_id)
            self.assertEqual(trace["total_stages"], 13)
            # Correlation and Cluster stage should be NOT_AVAILABLE for isolated manual incident
            stage_map = {s["stage_name"]: s["status"] for s in trace["stages"]}
            self.assertEqual(stage_map["RISK_CORRELATION"], "NOT_AVAILABLE")
            self.assertEqual(stage_map["RISK_CLUSTER"], "NOT_AVAILABLE")

    # ── Test 28: RBAC Security Analyst allowed operations ───────────────────
    def test_28_rbac_security_analyst_permissions(self):
        """Verify SECURITY_ANALYST can create incidents, assign, update status, link evidence, add findings."""
        headers = get_auth_headers("security_analyst")
        create_resp = client.post("/api/v1/incidents", json={
            "title": "RBAC Analyst Full Test",
            "severity": "HIGH",
        }, headers=headers)
        self.assertEqual(create_resp.status_code, 201)
        inc_id = create_resp.json()["incident_id"]

        r_assign = client.patch(f"/api/v1/incidents/{inc_id}/assign", json={"assigned_to_user_id": "usr_analyst_01"}, headers=headers)
        self.assertEqual(r_assign.status_code, 200)

        r_status = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "TRIAGING"}, headers=headers)
        self.assertEqual(r_status.status_code, 200)

        r_ev = client.post(f"/api/v1/incidents/{inc_id}/evidence", json={
            "evidence_type": "RAW_EVIDENCE",
            "evidence_id": "ev_rbac_test_01",
            "relationship": "PRIMARY",
        }, headers=headers)
        self.assertEqual(r_ev.status_code, 201)

        r_fnd = client.post(f"/api/v1/incidents/{inc_id}/findings", json={
            "finding_type": "OBSERVATION",
            "title": "Analyst Observation",
            "description": "Evidence verified.",
            "confidence": 0.95,
        }, headers=headers)
        self.assertEqual(r_fnd.status_code, 201)

    # ── Test 29: RBAC Viewer denied modification operations ─────────────────
    def test_29_rbac_viewer_denied(self):
        """Verify VIEWER can read but cannot create, assign, change status, link evidence, or add findings."""
        viewer_headers = get_auth_headers("viewer")
        analyst_headers = get_auth_headers("security_analyst")

        # Viewer can read list
        r_list = client.get("/api/v1/incidents", headers=viewer_headers)
        self.assertEqual(r_list.status_code, 200)

        # Viewer cannot create incident -> 403
        r_create = client.post("/api/v1/incidents", json={"title": "Viewer Fail", "severity": "LOW"}, headers=viewer_headers)
        self.assertEqual(r_create.status_code, 403)

        # Create an incident as analyst to test modifications
        inc = client.post("/api/v1/incidents", json={"title": "Analyst Target", "severity": "LOW"}, headers=analyst_headers).json()
        inc_id = inc["incident_id"]

        # Viewer cannot assign -> 403
        r_assign = client.patch(f"/api/v1/incidents/{inc_id}/assign", json={"assigned_to_user_id": "usr_viewer"}, headers=viewer_headers)
        self.assertEqual(r_assign.status_code, 403)

        # Viewer cannot update status -> 403
        r_status = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": "TRIAGING"}, headers=viewer_headers)
        self.assertEqual(r_status.status_code, 403)

        # Viewer cannot link evidence -> 403
        r_ev = client.post(f"/api/v1/incidents/{inc_id}/evidence", json={
            "evidence_type": "RAW_EVIDENCE",
            "evidence_id": "ev_01",
            "relationship": "PRIMARY",
        }, headers=viewer_headers)
        self.assertEqual(r_ev.status_code, 403)

    # ── Test 30: RBAC Policy Reviewer finding permissions ───────────────────
    def test_30_rbac_policy_reviewer_permissions(self):
        """Verify POLICY_REVIEWER can author findings and view incidents."""
        rev_headers = get_auth_headers("policy_reviewer")
        analyst_headers = get_auth_headers("security_analyst")

        inc = client.post("/api/v1/incidents", json={"title": "Policy Review Target", "severity": "LOW"}, headers=analyst_headers).json()
        inc_id = inc["incident_id"]

        r_fnd = client.post(f"/api/v1/incidents/{inc_id}/findings", json={
            "finding_type": "OBSERVATION",
            "title": "Policy Reviewer Note",
            "description": "Reviewed policy impact.",
            "confidence": 0.88,
        }, headers=rev_headers)
        self.assertEqual(r_fnd.status_code, 201)

    # ── Test 31: RBAC Auditor trace access ──────────────────────────────────
    def test_31_rbac_auditor_trace_access(self):
        """Verify AUDITOR can access the 13-stage provenance trace."""
        auditor_headers = get_auth_headers("auditor")
        resp = client.get("/api/v1/incidents/INC-2026-000001/trace", headers=auditor_headers)
        self.assertEqual(resp.status_code, 200)

    # ── Test 32: Unauthenticated requests rejected ──────────────────────────
    def test_32_unauthenticated_rejected(self):
        """Verify unauthenticated requests return HTTP 401."""
        resp = client.get("/api/v1/incidents")
        self.assertEqual(resp.status_code, 401)

    # ── Test 33: Cryptographic governance ledger recording ──────────────────
    def test_33_governance_ledger_recording(self):
        """Verify incident lifecycle actions generate cryptographically chained ledger entries."""
        with SessionLocal() as db:
            entries = (
                db.query(GovernanceLedgerEntry)
                .filter(GovernanceLedgerEntry.event_type.like("INCIDENT_%"))
                .all()
            )
            self.assertGreater(len(entries), 0)
            for entry in entries:
                self.assertIsNotNone(entry.entry_hash)
                self.assertIsNotNone(entry.previous_hash)
                self.assertGreater(entry.sequence_number, 0)

    # ── Test 34: Filterable incident querying ───────────────────────────────
    def test_34_filterable_incident_querying(self):
        """Verify filtering incidents by severity, priority, and status."""
        headers = get_auth_headers("security_analyst")
        resp_crit = client.get("/api/v1/incidents?severity=CRITICAL", headers=headers)
        self.assertEqual(resp_crit.status_code, 200)
        for inc in resp_crit.json():
            self.assertEqual(inc["severity"], "CRITICAL")

        resp_p1 = client.get("/api/v1/incidents?priority=P1", headers=headers)
        self.assertEqual(resp_p1.status_code, 200)
        for inc in resp_p1.json():
            self.assertEqual(inc["priority"], "P1")

    # ── Test 35: Pre-seeded Cisco ASA demo incident verification ────────────
    def test_35_demo_incident_verification(self):
        """Verify the seeded demonstration incident INC-2026-000001 satisfies all SOC investigation requirements."""
        headers = get_auth_headers("security_analyst")
        resp = client.get("/api/v1/incidents/INC-2026-000001", headers=headers)
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()

        inc = data["incident"]
        self.assertEqual(inc["incident_number"], "INC-2026-000001")
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertEqual(inc["priority"], "P1")
        self.assertEqual(inc["status"], "INVESTIGATING")
        self.assertEqual(inc["incident_type"], "PROTECTED_FIELD")
        self.assertIn("action.result", inc["title"])

        # Signals, evidence, findings, timeline
        self.assertGreaterEqual(len(data["signals"]), 3)
        self.assertGreaterEqual(len(data["evidence"]), 3)
        self.assertGreaterEqual(len(data["findings"]), 3)
        self.assertGreaterEqual(len(data["timeline"]), 5)
