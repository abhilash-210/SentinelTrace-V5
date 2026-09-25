import unittest
import os
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, get_db, SessionLocal, engine
from app.routers.auth import get_current_user
from app.models.user import User
from app.services.log_forwarder_service import SIEM_STREAM_FILE

def override_get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def override_get_current_user():
    return User(
        user_id="user_admin",
        username="admin",
        role="ADMIN",
        is_active=True
    )

app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user

client = TestClient(app)

class TestSIEMForwarder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        cls.event_id = None
        cls.normalized_id = None

    def test_01_clear_stream(self):
        res = client.delete("/api/v1/forwarder/stream")
        self.assertEqual(res.status_code, 204)
        
        # Verify it's empty
        res = client.get("/api/v1/forwarder/stream")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["total_returned"], 0)

    def test_02_ingest_event(self):
        payload = {
            "source_name": "Test Firewall",
            "source_type": "firewall",
            "file_format": "json",
            "raw_content": '{"action": "ACCEPT", "src_ip": "192.168.1.10", "timestamp": "2026-09-24T12:00:00Z"}'
        }
        res = client.post("/api/v1/ingest", json=payload)
        self.assertEqual(res.status_code, 201)
        TestSIEMForwarder.event_id = res.json()["event_id"]

    def test_03_normalize_and_forward(self):
        # Normalizing should automatically forward to the stream
        res = client.post(f"/api/v1/events/{self.event_id}/normalize")
        self.assertEqual(res.status_code, 200)
        TestSIEMForwarder.normalized_id = res.json()["normalized_event_id"]

    def test_04_verify_forwarded_stream(self):
        res = client.get("/api/v1/forwarder/stream")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        
        self.assertGreaterEqual(data["total_returned"], 1)
        events = data["events"]
        
        # Look for our specific event
        found = False
        for evt in events:
            if evt.get("original_event_id") == self.event_id:
                self.assertEqual(evt["event_id"], self.normalized_id)
                self.assertEqual(evt["action"], "ACCEPT")
                self.assertEqual(evt["src_ip"], "192.168.1.10")
                found = True
                break
                
        self.assertTrue(found, "Forwarded event not found in SIEM stream")
