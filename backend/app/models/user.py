"""
models/user.py
--------------
SQLAlchemy ORM model for User Identity and Role-Based Governance.

Sprint 4A — Identity & Role-Based Access Control (RBAC).
Establishes verifiable user identity, securely hashed credentials,
and role assignments for governance attribution.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String
from app.database import Base


class User(Base):
    """
    User identity entity governing authentication and RBAC permissions in SentinelTrace.
    """

    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_user_id", "user_id", unique=True),
        Index("ix_users_username", "username", unique=True),
        Index("ix_users_email", "email", unique=True),
        Index("ix_users_role", "role"),
        Index("ix_users_is_active", "is_active"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Surrogate integer primary key",
    )

    user_id = Column(
        String(64),
        unique=True,
        nullable=False,
        default=lambda: f"usr_{uuid.uuid4().hex[:12]}",
        comment="Unique public user identifier (e.g. 'usr_a1b2c3d4e5f6')",
    )

    username = Column(
        String(64),
        unique=True,
        nullable=False,
        comment="Unique login username",
    )

    email = Column(
        String(255),
        unique=True,
        nullable=False,
        comment="Unique user email address",
    )

    full_name = Column(
        String(255),
        nullable=False,
        comment="Display name of the user",
    )

    password_hash = Column(
        String(255),
        nullable=False,
        comment="Bcrypt-hashed password (never exposed via API)",
    )

    role = Column(
        String(32),
        nullable=False,
        default="VIEWER",
        comment="RBAC role: ADMIN, POLICY_AUTHOR, POLICY_REVIEWER, SECURITY_ANALYST, AUDITOR, VIEWER",
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
        comment="Account active state. Inactive accounts are blocked from login.",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC account creation timestamp",
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC last account update timestamp",
    )

    last_login_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp of most recent successful login",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert user to safe dictionary representation omitting password_hash."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }
