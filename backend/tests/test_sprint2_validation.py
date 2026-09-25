import json
import unittest
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, engine, SessionLocal
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.services.validation_service import ValidationService
from tests.auth_helper import get_auth_headers

client = TestClient(app, headers=get_auth_headers("ADMIN"))

class TestSprint2Validation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)

    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _ingest_event(self, payload: Dict[str, Any]) -> str:
        response = client.post("/api/v1/ingest", json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["event_id"]

    def test_01_valid_normalized_event(self):
        """TEST 01: Valid normalized event passes validation without error."""
        raw_id = self._ingest_event({
            "source_name": "Valid Source",
            "source_type": "firewall",
            "file_format": "syslog",
            "raw_content": "<134>Jan 12 10:52:14 firewall 10.0.0.1 10.0.0.2 12345 443 ALLOW"
        })
        
        response = client.post(f"/api/v1/events/{raw_id}/normalize")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["normalization_status"], "NORMALIZED")
        self.assertEqual(data["class_name"], "Network Activity")

    def test_02_invalid_ip_structure(self):
        """TEST 02: Invalid IP address triggers validation failure."""
        raw_id = self._ingest_event({
            "source_name": "Bad IP Source",
            "source_type": "firewall",
            "file_format": "json",
            "raw_content": json.dumps({
                "action": "ALLOW",
                "src_ip": "not_an_ip",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        })
        
        response = client.post(f"/api/v1/events/{raw_id}/normalize")
        self.assertEqual(response.status_code, 422)
        data = response.json()
        self.assertFalse(data["valid"])
        self.assertEqual(data["failure_stage"], "NORMALIZATION_VALIDATION")
        self.assertIn("Invalid IP address structure", data["message"])
        self.assertEqual(data["field"], "src_ip")

    def test_03_invalid_port_value(self):
        """TEST 03: Invalid port out of bounds triggers validation failure."""
        raw_id = self._ingest_event({
            "source_name": "Bad Port Source",
            "source_type": "firewall",
            "file_format": "json",
            "raw_content": json.dumps({
                "action": "ALLOW",
                "src_ip": "192.168.1.1",
                "src_port": 99999,  # out of bounds
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        })
        
        response = client.post(f"/api/v1/events/{raw_id}/normalize")
        self.assertEqual(response.status_code, 422)
        data = response.json()
        self.assertFalse(data["valid"])
        self.assertIn("Invalid port value", data["message"])
        self.assertEqual(data["field"], "src_port")

    def test_04_invalid_port_type(self):
        """TEST 04: Invalid port data type triggers validation failure."""
        raw_id = self._ingest_event({
            "source_name": "Bad Port Type Source",
            "source_type": "firewall",
            "file_format": "json",
            "raw_content": json.dumps({
                "action": "ALLOW",
                "src_ip": "192.168.1.1",
                "src_port": "eighty",  # invalid type
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        })
        
        response = client.post(f"/api/v1/events/{raw_id}/normalize")
        self.assertEqual(response.status_code, 422)
        data = response.json()
        self.assertFalse(data["valid"])
        self.assertIn("Invalid port value", data["message"])
        self.assertEqual(data["field"], "src_port")

    def test_05_internal_validation_missing_fields(self):
        """TEST 05: Directly test ValidationService logic for missing core fields."""
        # This tests missing original_event_id and class_name directly
        # since the normal API flow always supplies them.
        event = NormalizedEvent(
            original_event_id=None,
            class_name=None,
            event_time=None
        )
        result = ValidationService.validate_normalized_event(event)
        self.assertFalse(result["valid"])
        self.assertIn("Missing required field: original_event_id", result["message"])
        self.assertIn("Missing required field: class_name", result["message"])
        self.assertIn("Missing or invalid event_time", result["message"])

    def test_06_internal_validation_invalid_ocsf_class(self):
        """TEST 06: Directly test ValidationService logic for bad class_name."""
        event = NormalizedEvent(
            original_event_id="test_id",
            class_name="Nonexistent Activity",
            event_time=datetime.now(timezone.utc)
        )
        result = ValidationService.validate_normalized_event(event)
        self.assertFalse(result["valid"])
        self.assertIn("Invalid OCSF class_name", result["message"])
