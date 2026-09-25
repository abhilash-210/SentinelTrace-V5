"""
schemas/source_profile.py
-------------------------
Pydantic schemas for Source Profiles.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
Sprint 6 — Source Profile Onboarding & Approvals.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class SourceProfileCreateRequest(BaseModel):
    profile_name: str = Field(..., description="Human-readable profile name")
    source_type: str = Field(..., description="Origin source category (firewall, authentication, system)")
    supported_format: str = Field(..., description="Payload format handled by profile (syslog, json, csv, cef)")
    parser_type: str = Field(..., description="Associated parser identifier")
    configuration: Dict[str, Any] = Field(default_factory=dict, description="Field mappings and configuration")


class SourceProfileUpdateRequest(BaseModel):
    profile_name: Optional[str] = None
    source_type: Optional[str] = None
    supported_format: Optional[str] = None
    parser_type: Optional[str] = None
    configuration: Optional[Dict[str, Any]] = None


class SourceProfileTestRequest(BaseModel):
    supported_format: str
    parser_type: str
    configuration: Dict[str, Any]
    sample_event: str = Field(..., description="Raw text sample of the event")


class SourceProfileTestResponse(BaseModel):
    success: bool
    mapped_fields: Dict[str, Any] = Field(default_factory=dict)
    unmapped_fields: Dict[str, Any] = Field(default_factory=dict)
    validation_result: Dict[str, Any] = Field(default_factory=dict)
    normalized_preview: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


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
    status: str = Field(default="DRAFT", description="Lifecycle status")
    created_by: Optional[str] = None
    approved_by: Optional[str] = None
    created_at: datetime
    configuration: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class SourceProfileListResponse(BaseModel):
    """Collection of source profiles."""
    items: List[SourceProfileResponse]
    total: int


class SourceProfileApprovalResponse(BaseModel):
    approval_id: str
    source_profile_id: str
    requested_by_user_id: str
    requested_at: datetime
    status: str
    reviewed_by_user_id: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_comment: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SourceProfileApprovalSubmitResponse(BaseModel):
    approval_id: str
    approval_status: str
    requested_at: datetime
