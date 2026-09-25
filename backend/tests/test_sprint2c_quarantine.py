import json
import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base, engine, SessionLocal
from app.models.quarantined_event import QuarantinedEvent
from app.models.event import IngestedEvent
from tests.auth_helper import get_auth_headers

client = TestClient(app, headers=get_auth_headers("ADMIN"))

class TestSprint2CQuarantine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)

    def setUp(self):
        self.db = SessionLocal()
        # Avoid deleting events that might be needed by subsequent tests, but keep isolation by querying what we create.

    def tearDown(self):
        self.db.close()

    def test_01_malformed_log_enters_quarantine(self):
        """1. Verify that a malformed log fails parsing and enters quarantine."""
        # Ingest a malformed event (JSON parser will fail on this raw text if source_type implies JSON)
        malformed_content = "{ this is not valid json! ["
        res = client.post(
            "/api/v1/ingest",
            json={
                "source_name": "Test Firewall",
                "source_type": "FIREWALL",
                "file_format": "json",
                "raw_content": malformed_content,
                "metadata": {"test": "true"},
            },
        )
        self.assertEqual(res.status_code, 201)
        event_id = res.json()["event_id"]

        # Call normalize, which should fail parsing and quarantine it, but still return 200 with FAILED status
        norm_res = client.post(f"/api/v1/events/{event_id}/normalize")
        self.assertEqual(norm_res.status_code, 200)
        self.assertEqual(norm_res.json()["normalization_status"], "FAILED")

        # Check quarantine
        q_event = self.db.query(QuarantinedEvent).filter(QuarantinedEvent.raw_content == malformed_content).first()
        self.assertIsNotNone(q_event)
        self.assertEqual(q_event.status, "QUARANTINED")
        self.assertIn("json syntax error", q_event.failure_reason.lower())

    def test_02_validation_failure_enters_quarantine(self):
        """2. Verify that an event failing schema validation enters quarantine."""
        # Create a valid JSON but missing required fields or having invalid data
        invalid_content = '{"action": "SUCCESS", "src_ip": "invalid-ip", "src_port": -5}'
        res = client.post(
            "/api/v1/ingest",
            json={
                "source_name": "Test Auth",
                "source_type": "AUTHENTICATION",
                "file_format": "json",
                "raw_content": invalid_content,
                "metadata": {"test": "true"},
            },
        )
        self.assertEqual(res.status_code, 201)
        event_id = res.json()["event_id"]

        norm_res = client.post(f"/api/v1/events/{event_id}/normalize")
        self.assertEqual(norm_res.status_code, 422) # Unprocessable Entity

        q_event = self.db.query(QuarantinedEvent).filter(QuarantinedEvent.raw_content == invalid_content).first()
        self.assertIsNotNone(q_event)
        self.assertEqual(q_event.status, "QUARANTINED")
        self.assertIn("validation failed", q_event.failure_reason.lower())

    def test_03_raw_payload_is_preserved(self):
        """3. Verify the raw payload is exactly preserved in quarantine."""
        content = '{"broken": "data"'
        res = client.post(
            "/api/v1/ingest",
            json={
                "source_name": "Broken Source",
                "source_type": "APPLICATION",
                "file_format": "json",
                "raw_content": content,
                "metadata": {"test": "true"},
            },
        )
        event_id = res.json()["event_id"]
        client.post(f"/api/v1/events/{event_id}/normalize")
        
        q_event = self.db.query(QuarantinedEvent).filter(QuarantinedEvent.raw_content == content).first()
        self.assertIsNotNone(q_event)
        self.assertEqual(q_event.raw_content, content)

    def test_04_valid_events_do_not_enter_quarantine(self):
        """4. Verify that a valid event normalizes successfully and is NOT quarantined."""
        valid_content = '{"action": "SUCCESS", "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 12345, "dst_port": 443}'
        res = client.post(
            "/api/v1/ingest",
            json={
                "source_name": "Test Valid Firewall",
                "source_type": "FIREWALL",
                "file_format": "json",
                "raw_content": valid_content,
                "metadata": {"test": "true"},
            },
        )
        event_id = res.json()["event_id"]
        norm_res = client.post(f"/api/v1/events/{event_id}/normalize")
        self.assertEqual(norm_res.status_code, 200)

        q_event = self.db.query(QuarantinedEvent).filter(QuarantinedEvent.raw_content == valid_content).first()
        self.assertIsNone(q_event)

    def test_05_quarantine_api_works(self):
        """5. Verify the quarantine list API returns paginated data."""
        res = client.get("/api/v1/quarantine")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("items", data)
        self.assertIn("total", data)
        self.assertGreaterEqual(data["total"], 3) # from previous tests

    def test_06_quarantine_replay_failed_preserves_evidence(self):
        """6. Verify failed replay generates history and preserves evidence."""
        res_list = client.get("/api/v1/quarantine?limit=1")
        item = res_list.json()["items"][0]
        q_id = item["quarantine_id"]

        # Replay without payload (uses original)
        res = client.post(f"/api/v1/quarantine/{q_id}/replay", json={})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["result"], "FAILED")
        self.assertIsNone(data["resulting_normalized_event_id"])
        
        # Check history
        hist_res = client.get(f"/api/v1/quarantine/{q_id}/history")
        self.assertEqual(hist_res.status_code, 200)
        hist = hist_res.json()
        self.assertGreaterEqual(len(hist), 1)
        self.assertEqual(hist[0]["result"], "FAILED")
        self.assertEqual(hist[0]["quarantine_id"], q_id)
        
    def test_07_replay_successful_updates_status(self):
        """7. Verify a successful replay updates status and generates history."""
        # To simulate a successful replay of a quarantined event without altering the raw payload,
        # we can mock NormalizationService.normalize_event to return a SUCCESS event for this test.
        from unittest.mock import patch
        from app.models.normalized_event import NormalizedEvent
        
        res_list = client.get("/api/v1/quarantine?limit=1")
        item = res_list.json()["items"][0]
        q_id = item["quarantine_id"]
        original_event_id = item["original_event_id"]
        
        mock_event = NormalizedEvent(
            normalized_event_id="norm_mocked_123",
            original_event_id=original_event_id,
            normalization_status="NORMALIZED"
        )
        
        with patch('app.services.normalization_service.NormalizationService.normalize_event', return_value=mock_event):
            res = client.post(f"/api/v1/quarantine/{q_id}/replay", json={})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["result"], "SUCCESS")
            self.assertEqual(data["resulting_normalized_event_id"], "norm_mocked_123")
            
            # Check history
            hist_res = client.get(f"/api/v1/quarantine/{q_id}/history")
            self.assertEqual(hist_res.status_code, 200)
            hist = hist_res.json()
            self.assertEqual(hist[0]["result"], "SUCCESS")
