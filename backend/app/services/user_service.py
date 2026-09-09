"""
services/user_service.py
------------------------
Service layer for User Identity, Authentication, and RBAC Management.

Sprint 4A — Identity & Role-Based Access Control (RBAC).
"""

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.rbac import Role
from app.core.security import get_password_hash, verify_password
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate
from app.services.governance_ledger_service import GovernanceLedgerService

logger = logging.getLogger("sentinel.services.user")

# Development/demo password configuration (overridable via environment)
DEFAULT_DEMO_PASSWORD = os.getenv("DEMO_USER_PASSWORD", "SentinelDemo!2026")

DEMO_USERS_SEEDS = [
    {
        "user_id": "usr_admin_001",
        "username": "admin_demo",
        "email": "admin@sentineltrace.io",
        "full_name": "System Administrator",
        "role": Role.ADMIN.value,
        "password": os.getenv("DEMO_ADMIN_PASSWORD", DEFAULT_DEMO_PASSWORD),
        "is_active": True,
    },
    {
        "user_id": "usr_author_002",
        "username": "author_demo",
        "email": "author@sentineltrace.io",
        "full_name": "Dr. Elena Vance (Policy Author)",
        "role": Role.POLICY_AUTHOR.value,
        "password": os.getenv("DEMO_AUTHOR_PASSWORD", DEFAULT_DEMO_PASSWORD),
        "is_active": True,
    },
    {
        "user_id": "usr_reviewer_003",
        "username": "reviewer_demo",
        "email": "reviewer@sentineltrace.io",
        "full_name": "Marcus Holloway (Governance Reviewer)",
        "role": Role.POLICY_REVIEWER.value,
        "password": os.getenv("DEMO_REVIEWER_PASSWORD", DEFAULT_DEMO_PASSWORD),
        "is_active": True,
    },
    {
        "user_id": "usr_analyst_004",
        "username": "analyst_demo",
        "email": "analyst@sentineltrace.io",
        "full_name": "Abhilash (Security Analyst)",
        "role": Role.SECURITY_ANALYST.value,
        "password": os.getenv("DEMO_ANALYST_PASSWORD", DEFAULT_DEMO_PASSWORD),
        "is_active": True,
    },
    {
        "user_id": "usr_auditor_005",
        "username": "auditor_demo",
        "email": "auditor@sentineltrace.io",
        "full_name": "Sarah Connor (Compliance Auditor)",
        "role": Role.AUDITOR.value,
        "password": os.getenv("DEMO_AUDITOR_PASSWORD", DEFAULT_DEMO_PASSWORD),
        "is_active": True,
    },
    {
        "user_id": "usr_viewer_006",
        "username": "viewer_demo",
        "email": "viewer@sentineltrace.io",
        "full_name": "Guest Security Observer",
        "role": Role.VIEWER.value,
        "password": os.getenv("DEMO_VIEWER_PASSWORD", DEFAULT_DEMO_PASSWORD),
        "is_active": True,
    },
]


class UserService:
    """Service managing user authentication, identity records, and role governance."""

    @staticmethod
    def seed_demo_users(db: Session) -> int:
        """
        Idempotently seeds baseline development demo accounts.
        """
        seeded_count = 0
        for u_data in DEMO_USERS_SEEDS:
            existing = (
                db.query(User)
                .filter(
                    (User.username == u_data["username"])
                    | (User.email == u_data["email"])
                    | (User.user_id == u_data["user_id"])
                )
                .first()
            )
            if not existing:
                user = User(
                    user_id=u_data["user_id"],
                    username=u_data["username"],
                    email=u_data["email"],
                    full_name=u_data["full_name"],
                    password_hash=get_password_hash(u_data["password"]),
                    role=u_data["role"],
                    is_active=u_data["is_active"],
                )
                db.add(user)
                seeded_count += 1
            else:
                # Update role and active state if mismatched
                if existing.role != u_data["role"]:
                    existing.role = u_data["role"]
                if not existing.password_hash:
                    existing.password_hash = get_password_hash(u_data["password"])
        db.commit()
        if seeded_count > 0:
            logger.info(f"Seeded {seeded_count} demo identity accounts.")
        return seeded_count

    @staticmethod
    def authenticate_user(
        db: Session,
        username_or_email: str,
        password: str,
    ) -> Optional[User]:
        """
        Authenticates a user via username or email and password.
        Returns User entity if valid, None if credentials fail or account is inactive.
        Updates last_login_at on success.
        """
        clean_identifier = username_or_email.strip().lower()
        user = (
            db.query(User)
            .filter(
                (User.username.ilike(clean_identifier))
                | (User.email.ilike(clean_identifier))
            )
            .first()
        )

        if not user:
            return None

        # Check account active status
        if not user.is_active:
            logger.warning(f"Login rejected: user '{user.username}' is inactive.")
            return None

        # Check password
        if not verify_password(password, user.password_hash):
            return None

        # Update last login timestamp
        user.last_login_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
        """Fetch user by public user_id."""
        return db.query(User).filter(User.user_id == user_id).first()

    @staticmethod
    def get_user_by_username_or_email(db: Session, identifier: str) -> Optional[User]:
        """Fetch user by username or email."""
        clean = identifier.strip().lower()
        return (
            db.query(User)
            .filter((User.username.ilike(clean)) | (User.email.ilike(clean)))
            .first()
        )

    @staticmethod
    def list_users(db: Session, skip: int = 0, limit: int = 100) -> Tuple[List[User], int]:
        """List users with pagination."""
        total = db.query(User).count()
        users = db.query(User).order_by(User.id.asc()).offset(skip).limit(limit).all()
        return users, total

    @staticmethod
    def create_user(db: Session, user_in: UserCreate) -> User:
        """Create a new user with unique checks and password hashing."""
        # Check username collision
        if db.query(User).filter(User.username.ilike(user_in.username.strip())).first():
            raise ValueError(f"Username '{user_in.username}' is already registered.")

        # Check email collision
        if db.query(User).filter(User.email.ilike(user_in.email.strip())).first():
            raise ValueError(f"Email '{user_in.email}' is already registered.")

        # Validate role
        try:
            role_enum = Role(user_in.role.upper())
        except ValueError:
            raise ValueError(f"Invalid role '{user_in.role}'. Valid roles: {[r.value for r in Role]}")

        new_user = User(
            user_id=f"usr_{uuid.uuid4().hex[:12]}",
            username=user_in.username.strip().lower(),
            email=user_in.email.strip().lower(),
            full_name=user_in.full_name.strip(),
            password_hash=get_password_hash(user_in.password),
            role=role_enum.value,
            is_active=user_in.is_active,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="USER_CREATED",
                actor_id=new_user.user_id,
                actor_username=new_user.username,
                payload={
                    "user_id": new_user.user_id,
                    "username": new_user.username,
                    "email": new_user.email,
                    "role": new_user.role,
                    "is_active": new_user.is_active,
                },
            )
            db.commit()
        except Exception as e:
            logger.error(f"Failed to append USER_CREATED ledger event: {e}")

        return new_user

    @staticmethod
    def update_user(db: Session, user_id: str, user_update: UserUpdate) -> User:
        """Update user attributes (Admin only)."""
        user = UserService.get_user_by_id(db, user_id)
        if not user:
            raise ValueError(f"User '{user_id}' not found.")

        old_role = user.role
        old_active = user.is_active

        if user_update.full_name is not None:
            user.full_name = user_update.full_name.strip()

        if user_update.email is not None:
            existing = (
                db.query(User)
                .filter(User.email.ilike(user_update.email.strip()), User.user_id != user_id)
                .first()
            )
            if existing:
                raise ValueError(f"Email '{user_update.email}' is already in use.")
            user.email = user_update.email.strip().lower()

        if user_update.role is not None:
            try:
                role_enum = Role(user_update.role.upper())
                user.role = role_enum.value
            except ValueError:
                raise ValueError(f"Invalid role '{user_update.role}'.")

        if user_update.is_active is not None:
            user.is_active = user_update.is_active

        if user_update.password is not None and len(user_update.password) >= 8:
            user.password_hash = get_password_hash(user_update.password)

        db.commit()
        db.refresh(user)

        try:
            if user_update.role is not None and old_role != user.role:
                GovernanceLedgerService.append_entry(
                    db=db,
                    event_type="ROLE_CHANGED",
                    actor_id=user.user_id,
                    actor_username=user.username,
                    payload={
                        "user_id": user.user_id,
                        "username": user.username,
                        "previous_role": old_role,
                        "new_role": user.role,
                    },
                )
                db.commit()

            if user_update.is_active is not None and old_active != user.is_active and not user.is_active:
                GovernanceLedgerService.append_entry(
                    db=db,
                    event_type="USER_DEACTIVATED",
                    actor_id=user.user_id,
                    actor_username=user.username,
                    payload={
                        "user_id": user.user_id,
                        "username": user.username,
                        "is_active": user.is_active,
                    },
                )
                db.commit()
        except Exception as e:
            logger.error(f"Failed to append user update ledger event: {e}")

        return user
