"""
schemas/source_profile.py
-------------------------
Pydantic schemas for Source Profiles.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class SourceProfileResponse(BaseModel):
    """Representation of a Source Profile for structural log interpretation."""

    id: int
    source_profile_id: str = Field(..., description="Unique profile identifier (e.g., 'sp_firewall_syslog')")
    profile_name: str = Field(..., description="Human-readable profile name")
    source_type: str = Field(..., description="Origin source category (firewall, authentication, system)")
    supported_format: str = Field(..., description="Payload format handled by profile")
    parser_type: str = Field(..., description="Associated parser identifier")
    version: str = Field(default="v1.0.0", description="Profile schema version")
    is_active: bool = Field(default=True, description="Whether profile is active")
    created_at: datetime
    configuration: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class SourceProfileListResponse(BaseModel):
    """Collection of source profiles."""

    items: List[SourceProfileResponse]
    total: int
