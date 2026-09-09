"""
models/source_profile.py
------------------------
SQLAlchemy ORM model for Source Profiles.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
A Source Profile structurally describes how known security log formats should be parsed.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

from app.database import Base


class SourceProfile(Base):
    """
    Source Profile definition for structural log parsing.

    Sprint 2: Structural parsing configuration only.
    (Semantic equivalence policies are intentionally deferred to Sprint 3).
    """

    __tablename__ = "source_profiles"
    __table_args__ = (
        Index("ix_source_profiles_source_profile_id", "source_profile_id", unique=True),
        Index("ix_source_profiles_source_type", "source_type"),
        {"schema": "sentinel"},
    )

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Surrogate primary key",
    )

    source_profile_id = Column(
        String(64),
        unique=True,
        nullable=False,
        comment="Unique identifier for source profile (e.g. 'sp_firewall_syslog')",
    )

    profile_name = Column(
        String(255),
        nullable=False,
        comment="Human-readable profile name (e.g. 'Generic Firewall Syslog')",
    )

    source_type = Column(
        String(100),
        nullable=False,
        comment="Origin category (e.g. 'firewall', 'authentication', 'system')",
    )

    supported_format = Column(
        String(50),
        nullable=False,
        comment="Payload format handled by profile ('text', 'json', 'csv', 'syslog')",
    )

    parser_type = Column(
        String(50),
        nullable=False,
        comment="Associated parser identifier ('syslog', 'json', 'csv')",
    )

    version = Column(
        String(32),
        nullable=False,
        default="v1.0.0",
        comment="Profile schema version",
    )

    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        comment="Whether the profile is active for automated selection",
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="UTC timestamp of profile creation",
    )

    configuration = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
        comment="Structural mapping settings (field hints, delimiters, timestamps format)",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert SourceProfile to a dictionary."""
        return {
            "id": self.id,
            "source_profile_id": self.source_profile_id,
            "profile_name": self.profile_name,
            "source_type": self.source_type,
            "supported_format": self.supported_format,
            "parser_type": self.parser_type,
            "version": self.version,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "configuration": self.configuration or {},
        }
