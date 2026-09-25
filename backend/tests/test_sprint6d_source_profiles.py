import unittest

from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, get_db, SessionLocal, engine
from app.routers.auth import get_current_user
from app.models.user import User

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
        role="admin",
        is_active=True
    )

app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user

client = TestClient(app)

class TestSourceProfiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        cls.profile_id = None
        cls.approval_id = None

    def test_01_create_draft_profile(self):
        payload = {
            "profile_name": "Test Firewall Profile",
            "source_type": "firewall",
            "supported_format": "syslog",
            "parser_type": "syslog",
            "configuration": {
                "field_mappings": {
                    "src_ip": "source_ip",
                    "dst_ip": "destination_ip",
                    "action": "action"
                }
            }
        }
        res = client.post("/api/v1/source-profiles", json=payload)
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertEqual(data["status"], "DRAFT")
        self.assertFalse(data["is_active"])
        self.assertEqual(data["profile_name"], "Test Firewall Profile")
        TestSourceProfiles.profile_id = data["source_profile_id"]

    def test_02_update_draft_profile(self):
        payload = {
            "profile_name": "Updated Firewall Profile"
        }
        res = client.put(f"/api/v1/source-profiles/{self.profile_id}", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["profile_name"], "Updated Firewall Profile")

    def test_03_test_profile_sample(self):
        payload = {
            "supported_format": "json",
            "parser_type": "json",
            "configuration": {
                "field_mappings": {
                    "src_ip": "source_ip",
                    "action": "log_action"
                }
            },
            "sample_event": '{"source_ip": "10.0.0.1", "log_action": "ACCEPT", "hostname": "fw"}'
        }
        res = client.post("/api/v1/source-profiles/test", json=payload)
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        print("TEST_03 DATA:", data)
        self.assertTrue(data["success"])
        self.assertIn("src_ip", data["mapped_fields"])
        self.assertEqual(data["mapped_fields"]["src_ip"], "10.0.0.1")
        self.assertEqual(data["mapped_fields"]["action"], "ACCEPT")

    def test_04_submit_for_approval(self):
        res = client.post(f"/api/v1/source-profiles/{self.profile_id}/submit")
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertEqual(data["approval_status"], "PENDING")
        TestSourceProfiles.approval_id = data["approval_id"]
        
        # Verify status changed
        res2 = client.get(f"/api/v1/source-profiles/{self.profile_id}")
        self.assertEqual(res2.json()["status"], "PENDING_APPROVAL")

    def test_05_approve_profile_self_forbidden(self):
        res = client.post(f"/api/v1/source-profiles/approvals/{self.approval_id}/approve", params={"comment": "LGTM"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("Author cannot approve their own profile", res.text)

    def test_06_approve_profile_reviewer(self):
        # Debug db state
        with SessionLocal() as db:
            from app.models.source_profile import SourceProfileApprovalRequest
            all_approvals = db.query(SourceProfileApprovalRequest).all()
            print("DB APPROVALS:", [a.to_dict() for a in all_approvals])
            print("SELF.APPROVAL_ID IS:", self.approval_id)

        # Override user to be reviewer
        def override_reviewer():
            return User(user_id="user_reviewer", username="reviewer", role="admin", is_active=True)
        app.dependency_overrides[get_current_user] = override_reviewer
        
        res = client.post(f"/api/v1/source-profiles/approvals/{self.approval_id}/approve", params={"comment": "LGTM"})
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertEqual(data["status"], "APPROVED")
        
        # Verify status
        res2 = client.get(f"/api/v1/source-profiles/{self.profile_id}")
        self.assertEqual(res2.json()["status"], "APPROVED")
        
        # Restore admin
        app.dependency_overrides[get_current_user] = override_get_current_user

    def test_07_activate_profile(self):
        res = client.post(f"/api/v1/source-profiles/{self.profile_id}/activate")
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertEqual(data["status"], "ACTIVE")
        self.assertTrue(data["is_active"])

    def test_08_deactivate_profile(self):
        res = client.post(f"/api/v1/source-profiles/{self.profile_id}/deactivate")
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertEqual(data["status"], "INACTIVE")
        self.assertFalse(data["is_active"])
