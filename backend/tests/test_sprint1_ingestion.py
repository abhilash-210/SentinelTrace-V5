"""
test_sprint1_ingestion.py
-------------------------
Comprehensive automated test suite for Sprint 1:
Raw Event Preservation & Traceable Ingestion.

Using standard library unittest and FastAPI TestClient.
"""

import hashlib
import unittest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.event import IngestedEvent
from app.services.event_service import EventService, compute_sha256
from tests.auth_helper import get_auth_headers

client = TestClient(app, headers=get_auth_headers("ADMIN"))


class TestSprint1Ingestion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)

    def test_01_raw_event_ingestion_succeeds(self):
        """TEST 1: Ingesting a raw security event succeeds with HTTP 201."""
        payload = {
            "source_name": "Cisco ASA Firewall",
            "source_type": "firewall",
            "file_format": "text",
            "raw_content": "<13>Sep 06 12:34:56 firewall-01 %ASA-6-302013: Built inbound TCP connection 12345 action=ALLOW",
            "metadata": {"environment": "test-env", "rack": "r1"},
        }
        response = client.post("/api/v1/ingest", json=payload)
        self.assertEqual(response.status_code, 201, f"Response: {response.text}")
        data = response.json()
        self.assertIn("event_id", data)
        self.assertEqual(data["source_name"], "Cisco ASA Firewall")
        self.assertEqual(data["processing_status"], "PRESERVED")
        self.assertIn("raw_content_hash", data)

    def test_02_event_identifier_generated(self):
        """TEST 2: Unique event ID (evt_...) is generated and non-empty."""
        payload = {
            "source_name": "Linux Auth Gateway",
            "source_type": "authentication",
            "file_format": "text",
            "raw_content": "sshd[18420]: Failed password for invalid user admin from 192.168.1.105 port 58214 ssh2",
        }
        response = client.post("/api/v1/ingest", json=payload)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertTrue(data["event_id"].startswith("evt_"))
        self.assertGreaterEqual(len(data["event_id"]), 10)

    def test_03_sha256_hash_generated(self):
        """TEST 3: SHA-256 hash is generated and exactly 64 hex characters."""
        payload = {
            "source_name": "Endpoint EDR",
            "source_type": "endpoint",
            "file_format": "json",
            "raw_content": '{"process": "powershell.exe", "pid": 4120, "action": "spawn"}',
        }
        response = client.post("/api/v1/ingest", json=payload)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(len(data["raw_content_hash"]), 64)
        expected_hash = hashlib.sha256(payload["raw_content"].encode("utf-8")).hexdigest()
        self.assertEqual(data["raw_content_hash"], expected_hash)

    def test_04_stored_raw_content_equals_submitted_exactly(self):
        """TEST 4: Stored raw_content in PostgreSQL matches the submitted string EXACTLY."""
        raw_text = "  <13>Sep 06 12:34:56\twith-tabs-and-spaces   action=ALLOW\n\r"
        payload = {
            "source_name": "Exactness Test Device",
            "source_type": "test",
            "file_format": "text",
            "raw_content": raw_text,
        }
        response = client.post("/api/v1/ingest", json=payload)
        self.assertEqual(response.status_code, 201)
        event_id = response.json()["event_id"]

        db = SessionLocal()
        try:
            stored = EventService.get_event_by_id(db, event_id)
            self.assertIsNotNone(stored)
            self.assertEqual(stored.raw_content, raw_text)
            self.assertEqual(stored.content_size, len(raw_text.encode("utf-8")))
        finally:
            db.close()

    def test_05_evidence_retrieval_works(self):
        """TEST 5: Retrieval via GET /api/v1/events and GET /api/v1/events/{id} works."""
        list_resp = client.get("/api/v1/events?limit=10&offset=0")
        self.assertEqual(list_resp.status_code, 200)
        list_data = list_resp.json()
        self.assertIn("items", list_data)
        self.assertGreaterEqual(list_data["total"], 1)
        sample_id = list_data["items"][0]["event_id"]

        detail_resp = client.get(f"/api/v1/events/{sample_id}")
        self.assertEqual(detail_resp.status_code, 200)
        detail_data = detail_resp.json()
        self.assertEqual(detail_data["event_id"], sample_id)
        self.assertIn("raw_content", detail_data)

    def test_06_integrity_verification_succeeds_for_unchanged_event(self):
        """TEST 6: Integrity verification returns VERIFIED for an untouched event."""
        payload = {
            "source_name": "Integrity Check Node",
            "source_type": "network",
            "file_format": "text",
            "raw_content": "Packet accepted from 10.0.0.1 to 10.0.0.2 port 80",
        }
        ingest_resp = client.post("/api/v1/ingest", json=payload)
        event_id = ingest_resp.json()["event_id"]

        verify_resp = client.get(f"/api/v1/events/{event_id}/verify")
        self.assertEqual(verify_resp.status_code, 200)
        verify_data = verify_resp.json()
        self.assertEqual(verify_data["integrity_status"], "VERIFIED")
        self.assertEqual(verify_data["stored_hash"], verify_data["calculated_hash"])

    def test_07_tampering_causes_verification_failure(self):
        """TEST 7: Modifying raw_content directly in DB triggers MISMATCH on verification."""
        payload = {
            "source_name": "Tamper Target",
            "source_type": "firewall",
            "file_format": "text",
            "raw_content": "connection action=ALLOW from 10.0.0.1",
        }
        ingest_resp = client.post("/api/v1/ingest", json=payload)
        event_id = ingest_resp.json()["event_id"]

        # Tamper with raw_content directly in database WITHOUT updating hash
        db = SessionLocal()
        try:
            event = EventService.get_event_by_id(db, event_id)
            self.assertIsNotNone(event)
            event.raw_content = "connection action=DENY from 10.0.0.1"  # Tampered!
            db.commit()
        finally:
            db.close()

        # Verify integrity live
        verify_resp = client.get(f"/api/v1/events/{event_id}/verify")
        self.assertEqual(verify_resp.status_code, 200)
        verify_data = verify_resp.json()
        self.assertEqual(verify_data["integrity_status"], "MISMATCH")
        self.assertNotEqual(verify_data["stored_hash"], verify_data["calculated_hash"])

    def test_08_hash_remains_deterministic(self):
        """TEST 8: compute_sha256 produces identical hash for identical inputs."""
        sample = "deterministic-security-evidence-payload"
        hash1 = compute_sha256(sample)
        hash2 = compute_sha256(sample)
        self.assertEqual(hash1, hash2)
        self.assertEqual(hash1, hashlib.sha256(sample.encode("utf-8")).hexdigest())


if __name__ == "__main__":
    unittest.main()
