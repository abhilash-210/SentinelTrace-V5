"""
test_sprint2_normalization.py
-----------------------------
Comprehensive automated test suite for Sprint 2:
Source Parsing & OCSF-Aligned Canonical Normalization.

Tests:
1. Syslog parser extracts network, action, and header fields.
2. JSON parser extracts structured authentication fields.
3. CSV parser extracts system process audit fields.
4. Normalization strictly links back to original_event_id.
5. Normalized event record is successfully persisted in PostgreSQL.
6. Missing fields remain None/null (no data fabrication).
7. Malformed input fails safely with appropriate status.
8. Deterministic confidence scoring correctly computes penalties.
9. Repeated normalization is idempotent (returns existing record).
10. Raw evidence in Evidence Vault remains completely immutable.
"""

import json
import unittest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.parsers.csv_parser import CSVParser
from app.parsers.json_parser import JSONParser
from app.parsers.syslog_parser import SyslogParser
from app.services.event_service import EventService
from app.services.normalization_service import NormalizationService
from tests.auth_helper import get_auth_headers

client = TestClient(app, headers=get_auth_headers("ADMIN"))


class TestSprint2Normalization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)

    def test_01_syslog_parser_extracts_fields(self):
        """TEST 1: Syslog parser extracts network, action, and header fields."""
        parser = SyslogParser()
        raw = "<134>1 2026-09-06T12:00:01.120Z perimeter-fw-01 cisco-asa 4120 - - %ASA-6-302013: Built inbound TCP connection 982103 for outside:198.51.100.45/443 to inside:10.0.10.14/52140 action=ALLOW"
        res = parser.parse(raw)
        self.assertTrue(res["success"])
        fields = res["fields"]
        self.assertEqual(fields.get("action"), "ALLOW")
        self.assertEqual(fields.get("src_ip"), "198.51.100.45")
        self.assertEqual(fields.get("src_port"), 443)
        self.assertEqual(fields.get("dst_ip"), "10.0.10.14")
        self.assertEqual(fields.get("dst_port"), 52140)
        self.assertEqual(fields.get("protocol"), "TCP")
        self.assertIsNotNone(res["timestamp"])

    def test_02_json_parser_extracts_fields(self):
        """TEST 2: JSON parser extracts structured authentication fields."""
        parser = JSONParser()
        raw = json.dumps({
            "timestamp": "2026-09-06T12:05:30.450Z",
            "service": "auth-gateway",
            "event_type": "AUTHENTICATION_FAILURE",
            "client_ip": "198.51.100.77",
            "username": "svc_monitoring",
            "error_code": "AUTH_INVALID_TOKEN",
        })
        res = parser.parse(raw)
        self.assertTrue(res["success"])
        fields = res["fields"]
        self.assertEqual(fields.get("action"), "FAILURE")
        self.assertEqual(fields.get("src_ip"), "198.51.100.77")
        self.assertEqual(fields.get("user_name"), "svc_monitoring")
        self.assertEqual(fields.get("app_name"), "auth-gateway")
        self.assertIsNotNone(res["timestamp"])

    def test_03_csv_parser_extracts_fields(self):
        """TEST 3: CSV parser extracts system process audit fields."""
        parser = CSVParser()
        raw = "timestamp,hostname,process_name,process_id,parent_process,user,action,status\n2026-09-06T12:10:00Z,srv-app-prod-01,sshd,4120,systemd,root,LOGIN_SUCCESS,0"
        res = parser.parse(raw)
        self.assertTrue(res["success"])
        fields = res["fields"]
        self.assertEqual(fields.get("hostname"), "srv-app-prod-01")
        self.assertEqual(fields.get("process_name"), "sshd")
        self.assertEqual(fields.get("process_id"), 4120)
        self.assertEqual(fields.get("user_name"), "root")
        self.assertEqual(fields.get("action"), "SUCCESS")
        self.assertIsNotNone(res["timestamp"])

    def test_04_normalization_preserves_original_event_id(self):
        """TEST 4: Normalization strictly links back to original_event_id."""
        # 1. Ingest raw event
        ingest_payload = {
            "source_name": "Test Firewall",
            "source_type": "firewall",
            "file_format": "text",
            "raw_content": "%ASA-6-302013: Built inbound TCP connection 123 for outside:1.1.1.1/80 to inside:10.0.0.1/50000 action=ALLOW",
        }
        ingest_res = client.post("/api/v1/ingest", json=ingest_payload)
        self.assertEqual(ingest_res.status_code, 201)
        raw_event_id = ingest_res.json()["event_id"]

        # 2. Normalize
        norm_res = client.post(f"/api/v1/events/{raw_event_id}/normalize")
        self.assertEqual(norm_res.status_code, 200)
        norm_data = norm_res.json()
        self.assertEqual(norm_data["original_event_id"], raw_event_id)
        self.assertTrue(norm_data["normalized_event_id"].startswith("norm_"))

    def test_05_normalized_event_persisted_in_db(self):
        """TEST 5: Normalized event record is successfully persisted in PostgreSQL."""
        ingest_payload = {
            "source_name": "Test Auth Node",
            "source_type": "authentication",
            "file_format": "json",
            "raw_content": json.dumps({"timestamp": "2026-09-06T12:00:00Z", "username": "admin", "action": "LOGIN_SUCCESS"}),
        }
        raw_id = client.post("/api/v1/ingest", json=ingest_payload).json()["event_id"]
        norm_id = client.post(f"/api/v1/events/{raw_id}/normalize").json()["normalized_event_id"]

        # Verify directly in DB
        with SessionLocal() as db:
            norm_db = NormalizationService.get_normalized_by_id(db, norm_id)
            self.assertIsNotNone(norm_db)
            self.assertEqual(norm_db.original_event_id, raw_id)
            self.assertEqual(norm_db.class_name, "Authentication")
            self.assertEqual(norm_db.user_name, "admin")

    def test_06_missing_fields_remain_null(self):
        """TEST 6: Missing fields remain None/null (no data fabrication)."""
        ingest_payload = {
            "source_name": "Incomplete Source",
            "source_type": "firewall",
            "file_format": "text",
            "raw_content": "Just an arbitrary message without IP or port",
        }
        raw_id = client.post("/api/v1/ingest", json=ingest_payload).json()["event_id"]
        norm_data = client.post(f"/api/v1/events/{raw_id}/normalize").json()
        self.assertIsNone(norm_data["src_ip"])
        self.assertIsNone(norm_data["dst_ip"])
        self.assertIsNone(norm_data["src_port"])
        self.assertIsNone(norm_data["dst_port"])

    def test_07_malformed_input_fails_safely(self):
        """TEST 7: Malformed input fails safely with status FAILED/PARTIAL."""
        ingest_payload = {
            "source_name": "Broken JSON Provider",
            "source_type": "authentication",
            "file_format": "json",
            "raw_content": "{ this is definitely not valid json : [",
        }
        raw_id = client.post("/api/v1/ingest", json=ingest_payload).json()["event_id"]
        norm_data = client.post(f"/api/v1/events/{raw_id}/normalize").json()
        self.assertEqual(norm_data["normalization_status"], "FAILED")
        self.assertLessEqual(norm_data["normalization_confidence"], 0.50)

    def test_08_confidence_calculation_works(self):
        """TEST 8: Deterministic confidence scoring correctly computes penalties."""
        ingest_payload = {
            "source_name": "Full Firewall",
            "source_type": "firewall",
            "file_format": "text",
            "raw_content": "<134>1 2026-09-06T12:00:00Z fw-01 %ASA-6-302013: Built inbound TCP connection 1 for outside:1.1.1.1/80 to inside:2.2.2.2/80 action=ALLOW",
        }
        raw_id = client.post("/api/v1/ingest", json=ingest_payload).json()["event_id"]
        norm_data = client.post(f"/api/v1/events/{raw_id}/normalize").json()
        self.assertGreaterEqual(norm_data["normalization_confidence"], 0.80)
        self.assertIsInstance(norm_data["confidence_reasons"], list)

    def test_09_repeated_normalization_is_idempotent(self):
        """TEST 9: Repeated normalization is idempotent (returns existing record)."""
        ingest_payload = {
            "source_name": "Idempotency Test",
            "source_type": "system",
            "file_format": "csv",
            "raw_content": "timestamp,hostname,action\n2026-09-06T12:00:00Z,srv-1,EXEC",
        }
        raw_id = client.post("/api/v1/ingest", json=ingest_payload).json()["event_id"]

        first_norm = client.post(f"/api/v1/events/{raw_id}/normalize").json()
        second_norm = client.post(f"/api/v1/events/{raw_id}/normalize").json()

        self.assertEqual(first_norm["normalized_event_id"], second_norm["normalized_event_id"])
        self.assertEqual(first_norm["id"], second_norm["id"])

    def test_10_raw_evidence_remains_unchanged(self):
        """TEST 10: Raw evidence in Evidence Vault remains completely immutable after normalization."""
        raw_string = "  <14> RAW UNMUTATED LOG   action=ALLOW  \t\n"
        ingest_payload = {
            "source_name": "Evidence Protection Test",
            "source_type": "firewall",
            "file_format": "text",
            "raw_content": raw_string,
        }
        ingest_res = client.post("/api/v1/ingest", json=ingest_payload).json()
        raw_id = ingest_res["event_id"]
        initial_hash = ingest_res["raw_content_hash"]

        # Normalize
        client.post(f"/api/v1/events/{raw_id}/normalize")

        # Verify raw event in DB and integrity endpoint
        with SessionLocal() as db:
            raw_db = EventService.get_event_by_id(db, raw_id)
            self.assertEqual(raw_db.raw_content, raw_string)
            self.assertEqual(raw_db.raw_content_hash, initial_hash)

        verify_res = client.get(f"/api/v1/events/{raw_id}/verify").json()
        self.assertEqual(verify_res["integrity_status"], "VERIFIED")


    def test_11_loss_aware_normalization_mapped_only(self):
        """TEST 11: Event containing only mapped fields results in empty unmapped_data."""
        ingest_payload = {
            "source_name": "Mapped Only Source",
            "source_type": "authentication",
            "file_format": "json",
            "raw_content": json.dumps({"action": "SUCCESS", "src_ip": "10.0.0.1", "user_name": "admin"}),
        }
        raw_id = client.post("/api/v1/ingest", json=ingest_payload).json()["event_id"]
        norm_data = client.post(f"/api/v1/events/{raw_id}/normalize").json()
        
        self.assertEqual(norm_data["action"], "SUCCESS")
        self.assertEqual(norm_data["src_ip"], "10.0.0.1")
        self.assertEqual(norm_data["user_name"], "admin")
        self.assertEqual(norm_data["unmapped_data"], {})

    def test_12_loss_aware_normalization_mapped_and_unmapped(self):
        """TEST 12: Event containing mapped + unmapped fields properly separates them."""
        ingest_payload = {
            "source_name": "Mixed Source",
            "source_type": "authentication",
            "file_format": "json",
            "raw_content": json.dumps({
                "action": "FAILURE",
                "src_ip": "192.168.1.5",
                "user_name": "jdoe",
                "vendor_specific_reason": "password_expired",
                "custom_correlation_id": "ABC-123"
            }),
        }
        raw_id = client.post("/api/v1/ingest", json=ingest_payload).json()["event_id"]
        norm_data = client.post(f"/api/v1/events/{raw_id}/normalize").json()
        
        self.assertEqual(norm_data["action"], "FAILURE")
        self.assertEqual(norm_data["src_ip"], "192.168.1.5")
        self.assertEqual(norm_data["user_name"], "jdoe")
        self.assertIn("vendor_specific_reason", norm_data["unmapped_data"])
        self.assertEqual(norm_data["unmapped_data"]["vendor_specific_reason"], "password_expired")
        self.assertIn("custom_correlation_id", norm_data["unmapped_data"])
        self.assertEqual(norm_data["unmapped_data"]["custom_correlation_id"], "ABC-123")

    def test_13_loss_aware_normalization_multiple_vendor_fields(self):
        """TEST 13: Event containing multiple vendor-specific fields preserves all of them."""
        ingest_payload = {
            "source_name": "Heavy Vendor Source",
            "source_type": "firewall",
            "file_format": "json",
            "raw_content": json.dumps({
                "action": "ALLOW",
                "v_field_1": 100,
                "v_field_2": [1, 2, 3],
                "v_field_3": {"nested": "value"}
            }),
        }
        raw_id = client.post("/api/v1/ingest", json=ingest_payload).json()["event_id"]
        norm_data = client.post(f"/api/v1/events/{raw_id}/normalize").json()
        
        self.assertEqual(norm_data["unmapped_data"]["v_field_1"], 100)
        self.assertEqual(norm_data["unmapped_data"]["v_field_2"], [1, 2, 3])
        self.assertEqual(norm_data["unmapped_data"]["v_field_3"], {"nested": "value"})

    def test_14_empty_unmapped_data_case(self):
        """TEST 14: Empty unmapped_data case explicitly handled."""
        ingest_payload = {
            "source_name": "Empty Unmapped",
            "source_type": "authentication",
            "file_format": "json",
            "raw_content": json.dumps({}),
        }
        raw_id = client.post("/api/v1/ingest", json=ingest_payload).json()["event_id"]
        norm_data = client.post(f"/api/v1/events/{raw_id}/normalize").json()
        
        self.assertEqual(norm_data["unmapped_data"], {})

    def test_15_raw_evidence_unchanged_with_unmapped(self):
        """TEST 15: Raw evidence remains unchanged even with heavy unmapped data processing."""
        raw_payload = json.dumps({"action": "SUCCESS", "weird_field": "X"})
        ingest_payload = {
            "source_name": "Immutability Source",
            "source_type": "authentication",
            "file_format": "json",
            "raw_content": raw_payload,
        }
        ingest_res = client.post("/api/v1/ingest", json=ingest_payload).json()
        raw_id = ingest_res["event_id"]
        initial_hash = ingest_res["raw_content_hash"]
        
        client.post(f"/api/v1/events/{raw_id}/normalize")
        
        verify_res = client.get(f"/api/v1/events/{raw_id}/verify").json()
        self.assertEqual(verify_res["integrity_status"], "VERIFIED")
        
        with SessionLocal() as db:
            raw_db = EventService.get_event_by_id(db, raw_id)
            self.assertEqual(raw_db.raw_content, raw_payload)
            self.assertEqual(raw_db.raw_content_hash, initial_hash)

if __name__ == "__main__":
    unittest.main()
