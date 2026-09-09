"""
tests/auth_helper.py
--------------------
Authentication test fixtures and token generator for automated test suites.

Sprint 4A — Identity & Role-Based Access Control (RBAC).
Provides valid JWT tokens for standard test roles without bypassing production security.
"""

from app.core.security import create_access_token
from app.services.user_service import DEMO_USERS_SEEDS


def get_test_token_for_role(role_name: str) -> str:
    """
    Generates a valid signed JWT bearer token for the specified test role identity.
    """
    user_match = next((u for u in DEMO_USERS_SEEDS if u["role"] == role_name.upper()), None)
    if not user_match:
        user_id = f"usr_test_{role_name.lower()}"
        username = f"test_{role_name.lower()}"
        email = f"{role_name.lower()}@test.io"
    else:
        user_id = user_match["user_id"]
        username = user_match["username"]
        email = user_match["email"]

    token_claims = {
        "sub": user_id,
        "username": username,
        "role": role_name.upper(),
        "email": email,
    }
    return create_access_token(data=token_claims)


def get_auth_headers(role_name: str = "ADMIN") -> dict:
    """
    Returns HTTP Authorization header dictionary for TestClient requests.
    """
    token = get_test_token_for_role(role_name)
    return {"Authorization": f"Bearer {token}"}
