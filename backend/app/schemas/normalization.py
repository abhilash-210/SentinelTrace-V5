"""
schemas/normalization.py
------------------------
Pydantic schemas for OCSF-aligned canonical normalization and traceability.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class NormalizedEventResponse(BaseModel):
    """Complete OCSF-aligned canonical normalized event."""

    id: int
    normalized_event_id: str = Field(..., description="Unique normalized event identifier (e.g. 'norm_...')")
    original_event_id: str = Field(..., description="Traceability link to raw event in Evidence Vault")
    class_uid: int = Field(..., description="OCSF Class UID (e.g. 4001 Network, 3001 Auth, 1001 System)")
    class_name: str = Field(..., description="OCSF canonical class label")
    activity_id: int = Field(..., description="OCSF Activity UID")
    activity_name: str = Field(..., description="Canonical activity name")
    event_time: Optional[datetime] = Field(None, description="Parsed occurrence timestamp (UTC)")
    source_name: str = Field(..., description="Source system/device identifier")
    source_type: str = Field(..., description="Category of event source")
    action: Optional[str] = Field(None, description="Canonical action (e.g. 'ALLOW', 'DENY', 'SUCCESS', 'FAILURE')")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    src_port: Optional[int] = Field(None, description="Source port")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    dst_port: Optional[int] = Field(None, description="Destination port")
    protocol: Optional[str] = Field(None, description="Network protocol (e.g. 'TCP', 'UDP')")
    severity: Optional[str] = Field(None, description="Extracted severity")
    user_name: Optional[str] = Field(None, description="Extracted username")
    hostname: Optional[str] = Field(None, description="Extracted host identifier")
    process_name: Optional[str] = Field(None, description="Extracted process name")
    process_id: Optional[int] = Field(None, description="Extracted process ID")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Extracted key-value pairs")
    unmapped_data: Dict[str, Any] = Field(default_factory=dict, description="Vendor-specific unmapped fields")
    parser_name: str = Field(..., description="Parser module used")
    parser_version: str = Field(..., description="Parser release version")
    source_profile_id: Optional[str] = Field(None, description="Applied source profile")
    normalization_status: str = Field(..., description="'NORMALIZED', 'PARTIAL', 'FAILED'")
    normalization_confidence: float = Field(..., description="Deterministic confidence score (0.0 - 1.0)")
    confidence_reasons: List[str] = Field(default_factory=list, description="Explanatory confidence factors")
    normalized_at: datetime = Field(..., description="UTC timestamp of normalization")

    model_config = ConfigDict(from_attributes=True)


class NormalizedEventListResponse(BaseModel):
    """Paginated collection of normalized security events."""

    items: List[NormalizedEventResponse]
    total: int
    limit: int
    offset: int


class NormalizationTraceabilityResponse(BaseModel):
    """Traceability mapping between raw evidence and normalized event."""

    original_event_id: str
    raw_content_hash: str
    normalized_event_id: str
    parser_name: str
    parser_version: str
    source_profile_id: Optional[str]
    class_name: str
    activity_name: str
    normalization_status: str
    normalization_confidence: float
    confidence_reasons: List[str]
    normalized_at: datetime
