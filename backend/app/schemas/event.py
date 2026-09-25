"""
schemas/event.py
----------------
Pydantic validation schemas for raw event ingestion, listing, and integrity verification.

Sprint 1 — Raw Event Preservation & Traceable Ingestion.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EventIngestRequest(BaseModel):
    """Payload for submitting a raw event for immutable preservation."""

    source_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Source identifier or reporting system name",
        examples=["firewall-perimeter-01"],
    )
    source_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Type category of originating device",
        examples=["firewall"],
    )
    raw_content: Optional[str] = Field(
        default=None,
        description="Exact raw event payload to preserve",
        examples=["%ASA-6-302013: Built inbound TCP connection 12345 for outside:185.10.20.5/443 to inside:10.0.0.15/51515"],
    )
    raw_event: Optional[str] = Field(
        default=None,
        description="Alias for raw_content",
    )
    file_format: str = Field(
        default="text",
        max_length=50,
        description="Format of the raw payload ('text', 'json', 'csv', 'syslog')",
        examples=["text"],
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Optional provenance metadata",
        examples=[{"environment": "production", "collector_id": "collector-node-03"}],
    )

    @model_validator(mode="before")
    @classmethod
    def resolve_raw_content(cls, data: Any) -> Any:
        """Allow either raw_content or raw_event as payload key."""
        if isinstance(data, dict):
            if "raw_content" not in data and "raw_event" in data:
                data["raw_content"] = data["raw_event"]
            elif "raw_content" in data and not data.get("raw_content") and data.get("raw_event"):
                data["raw_content"] = data["raw_event"]
        return data

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source_name": "firewall-perimeter-01",
                "source_type": "firewall",
                "file_format": "text",
                "raw_content": "%ASA-6-302013: Built inbound TCP connection 12345 for outside:185.10.20.5/443 to inside:10.0.0.15/51515",
                "metadata": {"environment": "demo", "location": "datacenter-us-east"},
            }
        }
    )


class EventIngestResponse(BaseModel):
    """Response returned upon successful raw event preservation."""

    event_id: str = Field(
        ...,
        description="Unique identifier assigned to the preserved event record",
        examples=["evt_9a4f21b7c8e34a12"],
    )
    source_name: str = Field(..., description="Source device or system name")
    source_type: str = Field(..., description="Source type category")
    file_format: str = Field(..., description="Detected or specified file format")
    raw_content_hash: str = Field(
        ...,
        description="Deterministic SHA-256 integrity fingerprint",
        examples=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )
    hash_prefix: str = Field(
        ...,
        description="First 12 characters of the SHA-256 fingerprint for quick inspection",
        examples=["e3b0c44298fc"],
    )
    content_size: int = Field(..., description="Size of preserved payload in bytes")
    processing_status: str = Field(
        default="PRESERVED",
        description="Initial processing state",
        examples=["PRESERVED"],
    )
    ingested_at: datetime = Field(
        ...,
        description="UTC timestamp of preservation",
    )
    message: str = Field(
        default="Raw event preserved successfully with SHA-256 integrity fingerprint",
        description="Preservation summary message",
    )


class EventSummaryResponse(BaseModel):
    """Compact summary of an ingested event for table listings."""

    event_id: str
    source_name: str
    source_type: str
    file_format: str
    raw_content_hash: str
    hash_prefix: str
    content_size: int
    processing_status: str
    ingested_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EventDetailResponse(BaseModel):
    """Complete detail representation of an ingested event."""

    event_id: str
    source_name: str
    source_type: str
    file_format: str
    raw_content: str
    raw_content_hash: str
    hash_prefix: str
    content_size: int
    processing_status: str
    ingested_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class EventListResponse(BaseModel):
    """Paginated collection of ingested events."""

    items: List[EventSummaryResponse]
    total: int
    limit: int
    offset: int


class EventVerificationResponse(BaseModel):
    """Cryptographic integrity verification result."""

    event_id: str
    stored_hash: str = Field(..., description="SHA-256 hash registered in database at ingestion")
    calculated_hash: str = Field(..., description="Live SHA-256 recomputed over stored raw content")
    integrity_status: str = Field(
        ...,
        description="'VERIFIED' if hashes match exactly, 'MISMATCH' if content was modified",
        examples=["VERIFIED"],
    )
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the verification check",
    )

class RecentEventResponse(BaseModel):
    time: str
    source: str
    format: str
    status: str

class PipelineStatsResponse(BaseModel):
    received: int
    parsed: int
    normalized: int
    quarantined: int
    replayed: int
    forwarded: int
    recent_events: List[RecentEventResponse]

