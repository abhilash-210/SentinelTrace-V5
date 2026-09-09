"""
test_sprint3b_semantic_interpretation.py
----------------------------------------
Comprehensive automated test suite for Sprint 3B:
Semantic Interpretation Engine, Semantic Drift Detection, and Explainable Audit Trail.

Tests:
1. Cisco ASA PERMIT maps to ALLOWED (COMPATIBLE).
2. Demo Vendor PERMIT maps to MONITORED (AMBIGUOUS).
3. Same raw token PERMIT produces different vendor-specific interpretations (Vendor Isolation).
4. No global mapping fallback exists; unmapped vendor produces UNMAPPED status.
5. Unknown semantic value produces UNMAPPED status.
6. Unmapped value creates UNMAPPED_VALUE drift alert.
7. AMBIGUOUS rule creates AMBIGUOUS_MAPPING alert.
8. Protected semantic field ambiguity creates PROTECTED_FIELD_RISK.
9. Conflicting rules create POLICY_CONFLICT status and alert.
10. Semantic confidence scoring is deterministic with explainable reasons.
11. Repeated interpretation is idempotent (returns existing record).
12. Original normalized event in database remains 100% unchanged.
13. Raw evidence in Evidence Vault remains 100% unchanged.
14. End-to-end trace endpoint returns the full audit chain.
"""

import json
import unittest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.semantic_interpretation import (
    SemanticDriftAlert,
    SemanticInterpretation,
)
from app.models.semantic_policy import (
    ProtectedSemanticField,
    SemanticPolicy,
    SemanticPolicyRule,
)
from app.models.source_profile import SourceProfile
from app.services.event_service import EventService
from app.services.normalization_service import NormalizationService
from app.services.semantic_interpretation_service import SemanticInterpretationService
from app.services.semantic_policy_service import SemanticPolicyService
from tests.auth_helper import get_auth_headers

client = TestClient(app, headers=get_auth_headers("ADMIN"))


class TestSprint3BSemanticInterpretation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)

    def _ingest_and_normalize(self, source_name: str, source_type: str, raw_content: str, file_format: str = "text") -> str:
        """Helper to ingest raw log and normalize it."""
        ingest_res = client.post("/api/v1/ingest", json={
            "source_name": source_name,
            "source_type": source_type,
            "file_format": file_format,
            "raw_content": raw_content,
        })
        self.assertEqual(ingest_res.status_code, 201)
        raw_event_id = ingest_res.json()["event_id"]

        norm_res = client.post(f"/api/v1/events/{raw_event_id}/normalize")
        self.assertEqual(norm_res.status_code, 200)
        return norm_res.json()["normalized_event_id"]

    def test_01_cisco_permit_maps_to_allowed(self):
        """TEST 1: Cisco ASA PERMIT maps to ALLOWED."""
        raw_log = "<134>1 2026-09-06T12:00:00Z fw-cisco-01 %ASA-6-302013: Built inbound TCP connection 12 for outside:198.51.100.1/80 to inside:10.0.0.1/5000 action=PERMIT"
        norm_id = self._ingest_and_normalize("Cisco ASA Firewall", "firewall", raw_log)

        interp_res = client.post(f"/api/v1/normalized-events/{norm_id}/interpret")
        self.assertEqual(interp_res.status_code, 200)
        data = interp_res.json()

        self.assertEqual(data["vendor_name"], "Cisco ASA")
        self.assertEqual(data["policy_id"], "spol_cisco_asa_v1")
        self.assertEqual(data["source_value"], "PERMIT")
        self.assertEqual(data["canonical_field"], "action.result")
        self.assertEqual(data["interpreted_value"], "ALLOWED")
        self.assertEqual(data["equivalence_classification"], "COMPATIBLE")
        self.assertEqual(data["interpretation_status"], "INTERPRETED")
        self.assertEqual(data["risk_level"], "LOW")
        self.assertAlmostEqual(data["confidence_score"], 0.90, places=2)

    def test_02_demo_vendor_permit_maps_to_monitored(self):
        """TEST 2: Demo Vendor PERMIT maps to MONITORED."""
        raw_log = json.dumps({
            "timestamp": "2026-09-06T12:00:00Z",
            "vendor": "Demo Vendor",
            "action": "PERMIT",
            "src_ip": "10.10.10.10",
        })
        norm_id = self._ingest_and_normalize("Demo Vendor Tap Appliance", "firewall", raw_log, file_format="json")

        interp_res = client.post(f"/api/v1/normalized-events/{norm_id}/interpret")
        self.assertEqual(interp_res.status_code, 200)
        data = interp_res.json()

        self.assertEqual(data["vendor_name"], "Demo Vendor")
        self.assertEqual(data["policy_id"], "spol_demo_vendor_v1")
        self.assertEqual(data["source_value"], "PERMIT")
        self.assertEqual(data["canonical_field"], "action.result")
        self.assertEqual(data["interpreted_value"], "MONITORED")
        self.assertEqual(data["equivalence_classification"], "AMBIGUOUS")
        self.assertEqual(data["interpretation_status"], "AMBIGUOUS")
        self.assertEqual(data["risk_level"], "HIGH")  # Elevated due to protected field ambiguity
        self.assertAlmostEqual(data["confidence_score"], 0.60, places=2)  # 1.0 - 0.25 (ambiguous) - 0.15 (protected)

    def test_03_same_token_vendor_isolation(self):
        """TEST 3: Same raw token 'PERMIT' produces distinct interpretations across vendors."""
        # Cisco event
        cisco_norm = self._ingest_and_normalize(
            "Cisco ASA Node", "firewall",
            "<134>1 2026-09-06T12:00:00Z cisco-node %ASA-6-302013: action=PERMIT",
        )
        cisco_data = client.post(f"/api/v1/normalized-events/{cisco_norm}/interpret").json()

        # Demo Vendor event
        demo_norm = self._ingest_and_normalize(
            "Demo Vendor Node", "firewall",
            json.dumps({"vendor": "Demo Vendor", "action": "PERMIT"}),
            file_format="json",
        )
        demo_data = client.post(f"/api/v1/normalized-events/{demo_norm}/interpret").json()

        # Verify exact same raw token yields different canonical values
        self.assertEqual(cisco_data["source_value"], demo_data["source_value"])
        self.assertEqual(cisco_data["interpreted_value"], "ALLOWED")
        self.assertEqual(demo_data["interpreted_value"], "MONITORED")
        self.assertNotEqual(cisco_data["interpreted_value"], demo_data["interpreted_value"])

    def test_04_no_global_mapping_fallback(self):
        """TEST 4: No global fallback mapping exists; unknown vendor results in UNMAPPED."""
        raw_log = json.dumps({
            "timestamp": "2026-09-06T12:00:00Z",
            "action": "PERMIT",
            "service": "custom-unregistered-vendor",
        })
        norm_id = self._ingest_and_normalize("Unregistered Vendor Appliance", "system", raw_log, file_format="json")

        interp_res = client.post(f"/api/v1/normalized-events/{norm_id}/interpret")
        self.assertEqual(interp_res.status_code, 200)
        data = interp_res.json()

        self.assertEqual(data["interpretation_status"], "UNMAPPED")
        self.assertIsNone(data["interpreted_value"])
        self.assertIn("No active vendor-scoped semantic policy exists", data["explanation"])

    def test_05_unknown_semantic_value_produces_unmapped(self):
        """TEST 5: Unknown semantic value produces UNMAPPED status."""
        raw_log = "<134>1 2026-09-06T12:00:00Z cisco-node %ASA-6-302013: action=UNKNOWN_CUSTOM_OP"
        norm_id = self._ingest_and_normalize("Cisco ASA Gateway", "firewall", raw_log)

        interp_res = client.post(f"/api/v1/normalized-events/{norm_id}/interpret")
        self.assertEqual(interp_res.status_code, 200)
        data = interp_res.json()

        self.assertEqual(data["interpretation_status"], "UNMAPPED")
        self.assertEqual(data["source_value"], "UNKNOWN_CUSTOM_OP")
        self.assertIsNone(data["interpreted_value"])
        self.assertEqual(data["risk_level"], "MEDIUM")

    def test_06_unmapped_value_creates_drift_alert(self):
        """TEST 6: Unmapped value creates UNMAPPED_VALUE drift alert."""
        raw_log = "<134>1 2026-09-06T12:00:00Z cisco-node %ASA-6-302013: action=UNRECOGNIZED_ACTION"
        norm_id = self._ingest_and_normalize("Cisco ASA Alert Probe", "firewall", raw_log)

        interp_data = client.post(f"/api/v1/normalized-events/{norm_id}/interpret").json()
        alerts = interp_data["drift_alerts"]

        self.assertGreaterEqual(len(alerts), 1)
        unmapped_alert = next((a for a in alerts if a["drift_type"] == "UNMAPPED_VALUE"), None)
        self.assertIsNotNone(unmapped_alert)
        self.assertEqual(unmapped_alert["severity"], "MEDIUM")
        self.assertEqual(unmapped_alert["status"], "OPEN")

    def test_07_ambiguous_rule_creates_drift_alert(self):
        """TEST 7: AMBIGUOUS rule creates AMBIGUOUS_MAPPING alert."""
        raw_log = json.dumps({"vendor": "Demo Vendor", "action": "PERMIT"})
        norm_id = self._ingest_and_normalize("Demo Vendor Ambiguity Test", "firewall", raw_log, file_format="json")

        interp_data = client.post(f"/api/v1/normalized-events/{norm_id}/interpret").json()
        alerts = interp_data["drift_alerts"]

        ambig_alert = next((a for a in alerts if a["drift_type"] == "AMBIGUOUS_MAPPING"), None)
        self.assertIsNotNone(ambig_alert)
        self.assertEqual(ambig_alert["severity"], "MEDIUM")

    def test_08_protected_field_ambiguity_creates_high_risk_alert(self):
        """TEST 8: Protected semantic field ambiguity creates PROTECTED_FIELD_RISK alert."""
        raw_log = json.dumps({"vendor": "Demo Vendor", "action": "PERMIT"})
        norm_id = self._ingest_and_normalize("Demo Vendor Protected Risk Test", "firewall", raw_log, file_format="json")

        interp_data = client.post(f"/api/v1/normalized-events/{norm_id}/interpret").json()
        alerts = interp_data["drift_alerts"]

        protected_alert = next((a for a in alerts if a["drift_type"] == "PROTECTED_FIELD_RISK"), None)
        self.assertIsNotNone(protected_alert)
        self.assertEqual(protected_alert["severity"], "HIGH")
        self.assertIn("action.result", protected_alert["description"])

    def test_09_conflicting_rules_create_policy_conflict(self):
        """TEST 9: Conflicting policy rules create POLICY_CONFLICT status and alert."""
        with SessionLocal() as db:
            # Clean up existing test policy if rerun
            existing = db.query(SemanticPolicy).filter(SemanticPolicy.policy_id == "spol_conflict_test_v1").first()
            if existing:
                db.delete(existing)
                db.commit()

            # Create a test policy with intentionally conflicting rules
            conflict_pol = SemanticPolicy(
                policy_id="spol_conflict_test_v1",
                policy_name="Conflict Demo Policy",
                vendor_name="Conflict Vendor",
                source_profile_id="sp_firewall_syslog",
                status="ACTIVE",
            )
            db.add(conflict_pol)
            db.flush()

            # Rule 1: ALLOW -> ALLOWED
            rule1 = SemanticPolicyRule(
                rule_id="srule_conf_01",
                policy_id=conflict_pol.policy_id,
                source_field="action",
                source_value="ALLOW",
                canonical_field="action.result",
                canonical_value="ALLOWED",
            )
            # Rule 2: ALLOW -> DENIED (Conflicting!)
            rule2 = SemanticPolicyRule(
                rule_id="srule_conf_02",
                policy_id=conflict_pol.policy_id,
                source_field="action",
                source_value="ALLOW",
                canonical_field="action.result",
                canonical_value="DENIED",
            )
            db.add(rule1)
            db.add(rule2)
            db.commit()

        # Ingest event for Conflict Vendor
        raw_log = "<134>1 2026-09-06T12:00:00Z conflict-device %ASA: action=ALLOW"
        norm_id = self._ingest_and_normalize("Conflict Vendor Device", "firewall", raw_log)

        interp_data = client.post(f"/api/v1/normalized-events/{norm_id}/interpret").json()
        self.assertEqual(interp_data["interpretation_status"], "CONFLICT")
        self.assertEqual(interp_data["risk_level"], "HIGH")
        self.assertEqual(interp_data["confidence_score"], 0.0)

        alerts = interp_data["drift_alerts"]
        conflict_alert = next((a for a in alerts if a["drift_type"] == "POLICY_CONFLICT"), None)
        self.assertIsNotNone(conflict_alert)
        self.assertEqual(conflict_alert["severity"], "HIGH")

    def test_10_confidence_scoring_is_deterministic(self):
        """TEST 10: Confidence scoring is deterministic with explainable reasons."""
        raw_log = "<134>1 2026-09-06T12:00:00Z fw-01 %ASA-6-302013: action=DENY"
        norm_id = self._ingest_and_normalize("Cisco ASA Det Test", "firewall", raw_log)

        data = client.post(f"/api/v1/normalized-events/{norm_id}/interpret").json()
        # DENY is EQUIVALENT -> score should be 1.00
        self.assertEqual(data["confidence_score"], 1.00)
        self.assertEqual(data["equivalence_classification"], "EQUIVALENT")
        self.assertEqual(len(data["confidence_reasons"]), 0)

    def test_11_repeated_interpretation_is_idempotent(self):
        """TEST 11: Repeated interpretation is idempotent (returns existing record)."""
        raw_log = "<134>1 2026-09-06T12:00:00Z fw-01 %ASA-6-302013: action=ALLOW"
        norm_id = self._ingest_and_normalize("Cisco Idempotency Test", "firewall", raw_log)

        first_res = client.post(f"/api/v1/normalized-events/{norm_id}/interpret").json()
        second_res = client.post(f"/api/v1/normalized-events/{norm_id}/interpret").json()

        self.assertEqual(first_res["interpretation_id"], second_res["interpretation_id"])
        self.assertEqual(first_res["id"], second_res["id"])

    def test_12_normalized_event_remains_unchanged(self):
        """TEST 12: Original normalized event in database remains 100% unchanged."""
        raw_log = "<134>1 2026-09-06T12:00:00Z fw-01 %ASA-6-302013: action=ALLOW"
        norm_id = self._ingest_and_normalize("Cisco Immutability Test", "firewall", raw_log)

        # Inspect normalized event before interpretation
        with SessionLocal() as db:
            norm_before = db.query(NormalizedEvent).filter(NormalizedEvent.normalized_event_id == norm_id).first().to_dict()

        # Run interpretation
        client.post(f"/api/v1/normalized-events/{norm_id}/interpret")

        # Inspect normalized event after interpretation
        with SessionLocal() as db:
            norm_after = db.query(NormalizedEvent).filter(NormalizedEvent.normalized_event_id == norm_id).first().to_dict()

        self.assertEqual(norm_before, norm_after)

    def test_13_raw_evidence_remains_unchanged(self):
        """TEST 13: Raw evidence in Evidence Vault remains 100% unchanged."""
        raw_content = "   <14> RAW UNTOUCHED CISCO ASA LOG action=PERMIT  \n"
        ingest_res = client.post("/api/v1/ingest", json={
            "source_name": "Cisco Raw Integrity Test",
            "source_type": "firewall",
            "file_format": "text",
            "raw_content": raw_content,
        }).json()
        raw_event_id = ingest_res["event_id"]
        original_hash = ingest_res["raw_content_hash"]

        # Normalize and Interpret
        norm_id = client.post(f"/api/v1/events/{raw_event_id}/normalize").json()["normalized_event_id"]
        client.post(f"/api/v1/normalized-events/{norm_id}/interpret")

        # Verify raw event hash and content in DB
        with SessionLocal() as db:
            raw_db = EventService.get_event_by_id(db, raw_event_id)
            self.assertEqual(raw_db.raw_content, raw_content)
            self.assertEqual(raw_db.raw_content_hash, original_hash)

        # Verify integrity endpoint returns VERIFIED
        verify_res = client.get(f"/api/v1/events/{raw_event_id}/verify").json()
        self.assertEqual(verify_res["integrity_status"], "VERIFIED")

    def test_14_trace_endpoint_shows_complete_chain(self):
        """TEST 14: Trace endpoint returns full audit chain from raw evidence to interpretation."""
        raw_log = "<134>1 2026-09-06T12:00:00Z fw-01 %ASA-6-302013: action=PERMIT"
        norm_id = self._ingest_and_normalize("Cisco ASA Trace Audit", "firewall", raw_log)

        interp_data = client.post(f"/api/v1/normalized-events/{norm_id}/interpret").json()
        interp_id = interp_data["interpretation_id"]

        trace_res = client.get(f"/api/v1/semantic-interpretations/{interp_id}/trace")
        self.assertEqual(trace_res.status_code, 200)
        trace = trace_res.json()

        self.assertEqual(trace["interpretation_id"], interp_id)
        self.assertIn("raw_evidence", trace)
        self.assertIn("normalized_event", trace)
        self.assertIn("source_profile", trace)
        self.assertEqual(trace["vendor"], "Cisco ASA")
        self.assertIsNotNone(trace["semantic_policy"])
        self.assertEqual(trace["semantic_policy"]["policy_id"], "spol_cisco_asa_v1")
        self.assertIsNotNone(trace["matched_rule"])
        self.assertEqual(trace["semantic_decision"]["interpreted_value"], "ALLOWED")


if __name__ == "__main__":
    unittest.main()
