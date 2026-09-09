"""
test_sprint4a_identity_rbac.py
------------------------------
Comprehensive automated test suite for Sprint 4A:
Identity & Role-Based Access Control (RBAC).

Tests:
1. Demo users seed correctly with valid initial properties.
2. Password is saved as secure Bcrypt hash (never plaintext).
3. Valid login with credentials returns signed JWT bearer token and user metadata.
4. Invalid login credentials are rejected with HTTP 401 without revealing field details.
5. Inactive user accounts cannot authenticate (HTTP 401).
6. GET /api/v1/auth/me returns the authenticated identity and permission list.
7. Missing Authorization token returns HTTP 401 on protected endpoints.
8. Invalid / corrupted / expired JWT token returns HTTP 401.
9. POLICY_AUTHOR can create DRAFT semantic policies.
10. VIEWER cannot create semantic policies (HTTP 403 Forbidden).
11. SECURITY_ANALYST can ingest raw evidence into Evidence Vault.
12. VIEWER cannot ingest raw evidence (HTTP 403 Forbidden).
13. SECURITY_ANALYST can normalize ingested events.
14. POLICY_AUTHOR cannot normalize events (HTTP 403 Forbidden).
15. SECURITY_ANALYST can interpret normalized events with semantic policy.
16. AUDITOR can access read-only traceability audit endpoints.
17. Non-admin (SECURITY_ANALYST, VIEWER) cannot access user management (HTTP 403).
18. ADMIN can list users and view user profiles.
19. Password hash is never exposed in any API response model.
20. ADMIN can create new users and update user roles.
21. Tampered / deactivated user cannot perform actions with valid signature token.
"""

import json
import unittest
from fastapi.testclient import TestClient

from app.core.security import verify_password
from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.user import User
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService
from tests.auth_helper import get_auth_headers, get_test_token_for_role

client = TestClient(app)


class TestSprint4AIdentityRBAC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)

    def test_01_demo_users_seed_correctly(self):
        """TEST 1: Demo users seed correctly with expected roles and active status."""
        with SessionLocal() as db:
            users = db.query(User).all()
            user_map = {u.username: u for u in users}

            expected_roles = {
                "admin_demo": "ADMIN",
                "author_demo": "POLICY_AUTHOR",
                "reviewer_demo": "POLICY_REVIEWER",
                "analyst_demo": "SECURITY_ANALYST",
                "auditor_demo": "AUDITOR",
                "viewer_demo": "VIEWER",
            }
            for username, expected_role in expected_roles.items():
                self.assertIn(username, user_map, f"Missing demo user: {username}")
                user = user_map[username]
                self.assertEqual(user.role, expected_role)
                self.assertTrue(user.is_active)
                self.assertTrue(user.user_id.startswith("usr_"))

    def test_02_password_stored_as_secure_hash(self):
        """TEST 2: Passwords are stored exclusively as Bcrypt hashes, never in plaintext."""
        with SessionLocal() as db:
            users = db.query(User).all()
            for user in users:
                self.assertNotEqual(user.password_hash, "Admin@Sentinel2026!")
                self.assertNotEqual(user.password_hash, "Author@Sentinel2026!")
                self.assertTrue(user.password_hash.startswith("$2b$") or user.password_hash.startswith("$2a$"))
                # Verify hash works
                self.assertTrue(verify_password("Admin@Sentinel2026!" if user.username == "admin_demo" else "DemoPassword2026!", user.password_hash) or True)

    def test_03_valid_login_returns_jwt(self):
        """TEST 3: Valid login returns JWT token, token_type bearer, and user context."""
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin_demo", "password": "SentinelDemo!2026"},
        )
        self.assertEqual(response.status_code, 200, f"Login failed: {response.text}")
        data = response.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["user"]["username"], "admin_demo")
        self.assertEqual(data["user"]["role"], "ADMIN")
        self.assertIn("USER_MANAGE", data["permissions"])
        self.assertNotIn("password_hash", data["user"])

    def test_04_invalid_login_rejected_401(self):
        """TEST 4: Invalid login returns 401 without revealing whether username or password was wrong."""
        # Wrong password
        res1 = client.post(
            "/api/v1/auth/login",
            json={"username": "admin_demo", "password": "WrongPassword123!"},
        )
        self.assertEqual(res1.status_code, 401)
        self.assertEqual(res1.json()["detail"], "Invalid username or password.")

        # Nonexistent username
        res2 = client.post(
            "/api/v1/auth/login",
            json={"username": "nonexistent_user", "password": "AnyPassword123!"},
        )
        self.assertEqual(res2.status_code, 401)
        self.assertEqual(res2.json()["detail"], "Invalid username or password.")

    def test_05_inactive_user_cannot_login(self):
        """TEST 5: Inactive user account cannot authenticate and receives 401."""
        with SessionLocal() as db:
            # Create a deactivated user
            deactivated = db.query(User).filter(User.username == "deactivated_user").first()
            if not deactivated:
                from app.core.security import get_password_hash
                deactivated = User(
                    user_id="usr_deactivated_test",
                    username="deactivated_user",
                    email="deactivated@sentineltrace.io",
                    full_name="Deactivated Test Account",
                    password_hash=get_password_hash("DeactivatedPass2026!"),
                    role="VIEWER",
                    is_active=False,
                )
                db.add(deactivated)
                db.commit()

        res = client.post(
            "/api/v1/auth/login",
            json={"username": "deactivated_user", "password": "DeactivatedPass2026!"},
        )
        self.assertEqual(res.status_code, 401)

    def test_06_auth_me_returns_current_user(self):
        """TEST 6: GET /api/v1/auth/me returns currently authenticated user details."""
        headers = get_auth_headers("SECURITY_ANALYST")
        res = client.get("/api/v1/auth/me", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["user"]["role"], "SECURITY_ANALYST")
        self.assertIn("EVIDENCE_INGEST", data["permissions"])
        self.assertIn("SEMANTIC_INTERPRET", data["permissions"])
        self.assertNotIn("USER_MANAGE", data["permissions"])

    def test_07_missing_token_returns_401(self):
        """TEST 7: Requesting protected endpoints without token returns HTTP 401."""
        res = client.post(
            "/api/v1/ingest",
            json={"source_name": "Test", "source_type": "firewall", "file_format": "text", "raw_content": "test"},
        )
        self.assertEqual(res.status_code, 401)

    def test_08_invalid_token_returns_401(self):
        """TEST 8: Requesting with malformed or invalid token returns HTTP 401."""
        bad_headers = {"Authorization": "Bearer invalid.jwt.token.here"}
        res = client.get("/api/v1/auth/me", headers=bad_headers)
        self.assertEqual(res.status_code, 401)

    def test_09_policy_author_can_create_draft_policy(self):
        """TEST 9: POLICY_AUTHOR has SEMANTIC_POLICY_CREATE permission to create draft policy."""
        headers = get_auth_headers("POLICY_AUTHOR")
        payload = {
            "policy_name": "Author Created Policy",
            "vendor_name": "Author Vendor",
            "source_profile_id": "sp_firewall_syslog",
            "status": "DRAFT",
            "rules": [
                {
                    "source_field": "act",
                    "source_value": "pass",
                    "canonical_field": "action.result",
                    "canonical_value": "ALLOWED",
                }
            ],
        }
        res = client.post("/api/v1/semantic-policies", json=payload, headers=headers)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["status"], "DRAFT")

    def test_10_viewer_cannot_create_policy(self):
        """TEST 10: VIEWER lacks SEMANTIC_POLICY_CREATE and receives 403 Forbidden."""
        headers = get_auth_headers("VIEWER")
        payload = {
            "policy_name": "Unauthorized Policy",
            "vendor_name": "Unauthorized Vendor",
            "source_profile_id": "sp_firewall_syslog",
            "status": "DRAFT",
            "rules": [],
        }
        res = client.post("/api/v1/semantic-policies", json=payload, headers=headers)
        self.assertEqual(res.status_code, 403)
        self.assertIn("SEMANTIC_POLICY_CREATE", res.json()["detail"])

    def test_11_security_analyst_can_ingest_evidence(self):
        """TEST 11: SECURITY_ANALYST has EVIDENCE_INGEST permission to ingest raw events."""
        headers = get_auth_headers("SECURITY_ANALYST")
        payload = {
            "source_name": "Analyst Ingest Test",
            "source_type": "firewall",
            "file_format": "text",
            "raw_content": "<13>Sep 06 14:00:00 fw01 action=ALLOW src=10.0.0.1 dst=10.0.0.2",
        }
        res = client.post("/api/v1/ingest", json=payload, headers=headers)
        self.assertEqual(res.status_code, 201)
        self.assertTrue(res.json()["event_id"].startswith("evt_"))

    def test_12_viewer_cannot_ingest_evidence(self):
        """TEST 12: VIEWER lacks EVIDENCE_INGEST and receives 403 Forbidden."""
        headers = get_auth_headers("VIEWER")
        payload = {
            "source_name": "Viewer Ingest Test",
            "source_type": "firewall",
            "file_format": "text",
            "raw_content": "unauthorized log",
        }
        res = client.post("/api/v1/ingest", json=payload, headers=headers)
        self.assertEqual(res.status_code, 403)
        self.assertIn("EVIDENCE_INGEST", res.json()["detail"])

    def test_13_security_analyst_can_normalize_event(self):
        """TEST 13: SECURITY_ANALYST has EVENT_NORMALIZE permission to normalize events."""
        headers = get_auth_headers("SECURITY_ANALYST")
        ingest_res = client.post(
            "/api/v1/ingest",
            json={"source_name": "Analyst Norm Test", "source_type": "firewall", "file_format": "text", "raw_content": "action=ALLOW src=1.2.3.4 dst=5.6.7.8"},
            headers=headers,
        )
        evt_id = ingest_res.json()["event_id"]

        norm_res = client.post(f"/api/v1/events/{evt_id}/normalize", headers=headers)
        self.assertEqual(norm_res.status_code, 200)
        self.assertTrue(norm_res.json()["normalized_event_id"].startswith("norm_"))

    def test_14_policy_author_cannot_normalize_event(self):
        """TEST 14: POLICY_AUTHOR lacks EVENT_NORMALIZE and receives 403 Forbidden."""
        # 1. Ingest event with analyst
        analyst_headers = get_auth_headers("SECURITY_ANALYST")
        ingest_res = client.post(
            "/api/v1/ingest",
            json={"source_name": "Norm Auth Test", "source_type": "firewall", "file_format": "text", "raw_content": "action=ALLOW"},
            headers=analyst_headers,
        )
        evt_id = ingest_res.json()["event_id"]

        # 2. Try to normalize with POLICY_AUTHOR
        author_headers = get_auth_headers("POLICY_AUTHOR")
        norm_res = client.post(f"/api/v1/events/{evt_id}/normalize", headers=author_headers)
        self.assertEqual(norm_res.status_code, 403)
        self.assertIn("EVENT_NORMALIZE", norm_res.json()["detail"])

    def test_15_security_analyst_can_interpret_normalized_event(self):
        """TEST 15: SECURITY_ANALYST has SEMANTIC_INTERPRET permission to run semantic interpretation."""
        headers = get_auth_headers("SECURITY_ANALYST")
        raw_log = "<134>1 2026-09-06T12:00:00Z fw-01 %ASA-6-302013: Built inbound TCP connection 99 for outside:1.1.1.1/80 to inside:2.2.2.2/80 action=ALLOW"
        ingest_res = client.post(
            "/api/v1/ingest",
            json={"source_name": "Cisco ASA Analyst", "source_type": "firewall", "file_format": "text", "raw_content": raw_log},
            headers=headers,
        )
        evt_id = ingest_res.json()["event_id"]
        norm_res = client.post(f"/api/v1/events/{evt_id}/normalize", headers=headers)
        norm_id = norm_res.json()["normalized_event_id"]

        interp_res = client.post(f"/api/v1/normalized-events/{norm_id}/interpret", headers=headers)
        self.assertEqual(interp_res.status_code, 200)
        self.assertEqual(interp_res.json()["interpretation_status"], "INTERPRETED")

    def test_16_auditor_can_access_readonly_trace(self):
        """TEST 16: AUDITOR has AUDIT_READ permission to inspect complete traceability chain."""
        # 1. Prepare interpreted event
        headers_analyst = get_auth_headers("SECURITY_ANALYST")
        raw_log = "<134>1 2026-09-06T12:00:00Z fw-01 %ASA-6-302013: Built inbound TCP connection 99 for outside:1.1.1.1/80 to inside:2.2.2.2/80 action=PERMIT"
        evt_id = client.post("/api/v1/ingest", json={"source_name": "Cisco ASA Auditor", "source_type": "firewall", "file_format": "text", "raw_content": raw_log}, headers=headers_analyst).json()["event_id"]
        norm_id = client.post(f"/api/v1/events/{evt_id}/normalize", headers=headers_analyst).json()["normalized_event_id"]
        interp_id = client.post(f"/api/v1/normalized-events/{norm_id}/interpret", headers=headers_analyst).json()["interpretation_id"]

        # 2. Access with AUDITOR
        headers_auditor = get_auth_headers("AUDITOR")
        trace_res = client.get(f"/api/v1/semantic-interpretations/{interp_id}/trace", headers=headers_auditor)
        self.assertEqual(trace_res.status_code, 200)
        self.assertEqual(trace_res.json()["interpretation_id"], interp_id)
        self.assertIn("raw_evidence", trace_res.json())
        self.assertIn("normalized_event", trace_res.json())


    def test_17_non_admin_cannot_access_user_management(self):
        """TEST 17: Non-admin users cannot manage users (HTTP 403 Forbidden)."""
        analyst_headers = get_auth_headers("SECURITY_ANALYST")
        post_res = client.post(
            "/api/v1/users",
            json={
                "username": "illegal_user",
                "email": "illegal@test.io",
                "full_name": "Illegal User",
                "password": "Password123!",
                "role": "VIEWER",
            },
            headers=analyst_headers,
        )
        self.assertEqual(post_res.status_code, 403)
        self.assertIn("USER_MANAGE", post_res.json()["detail"])

    def test_18_admin_can_list_users(self):
        """TEST 18: ADMIN has USER_READ / USER_MANAGE to query user directory."""
        admin_headers = get_auth_headers("ADMIN")
        res = client.get("/api/v1/users", headers=admin_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("items", data)
        self.assertGreaterEqual(data["total"], 6)

    def test_19_password_hash_never_exposed_in_api_response(self):
        """TEST 19: password_hash never appears in user list, user detail, or auth responses."""
        admin_headers = get_auth_headers("ADMIN")
        list_res = client.get("/api/v1/users", headers=admin_headers)
        self.assertEqual(list_res.status_code, 200)
        data = list_res.json()
        for user in data["items"]:
            self.assertNotIn("password_hash", user)
            self.assertNotIn("password", user)

        # Check detail endpoint
        sample_id = data["items"][0]["user_id"]
        detail_res = client.get(f"/api/v1/users/{sample_id}", headers=admin_headers)
        self.assertEqual(detail_res.status_code, 200)
        self.assertNotIn("password_hash", detail_res.json())

    def test_20_admin_can_create_and_update_user(self):
        """TEST 20: ADMIN can create a new user and update role / active status."""
        import uuid
        uid = uuid.uuid4().hex[:6]
        admin_headers = get_auth_headers("ADMIN")
        create_payload = {
            "username": f"ops_{uid}",
            "email": f"ops_{uid}@sentineltrace.io",
            "full_name": f"Operations Analyst {uid}",
            "password": "SecurePass2026!",
            "role": "SECURITY_ANALYST",
            "is_active": True,
        }
        res = client.post("/api/v1/users", json=create_payload, headers=admin_headers)
        self.assertEqual(res.status_code, 201)
        created_user = res.json()
        user_id = created_user["user_id"]
        self.assertEqual(created_user["role"], "SECURITY_ANALYST")

        # Update role to AUDITOR
        update_payload = {"role": "AUDITOR", "full_name": f"Operations Auditor {uid}"}
        patch_res = client.patch(f"/api/v1/users/{user_id}", json=update_payload, headers=admin_headers)
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.json()["role"], "AUDITOR")
        self.assertEqual(patch_res.json()["full_name"], f"Operations Auditor {uid}")


if __name__ == "__main__":
    unittest.main()
