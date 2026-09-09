"""
schemas/evidence.py
-------------------
Pydantic schemas for Evidence Vault ingestion, retrieval, and verification.

Sprint 1 — Evidence Vault & Secure Log Ingestion.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EvidenceIngestRequest(BaseModel):
    """Request payload for ingesting a raw security event."""

    source_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Name of the originating security device or system",
        examples=["Cisco ASA Firewall"],
    )
    source_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Category of the source log (e.g., firewall, authentication, endpoint)",
        examples=["firewall"],
    )
    raw_event: str = Field(
        ...,
        min_length=1,
        description="Exact raw security log text prior to parsing or normalization",
        examples=[
            "<13>Sep 06 12:34:56 firewall-01 %ASA-6-302013: Built inbound TCP connection 12345 for outside:185.10.20.5/443 to inside:10.0.0.15/51515"
        ],
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Optional contextual metadata (environment, collector, tags, etc.)",
        examples=[{"environment": "demo", "location": "perimeter"}],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "source_name": "Cisco ASA Firewall",
                "source_type": "firewall",
                "raw_event": "<13>Sep 06 12:34:56 firewall-01 %ASA-6-302013: Built inbound TCP connection 12345 for outside:185.10.20.5/443 to inside:10.0.0.15/51515",
                "metadata": {
                    "environment": "demo",
                    "location": "perimeter",
                },
            }
        }
    )


class EvidenceIngestResponse(BaseModel):
    """Response returned upon successful raw evidence preservation."""

    event_id: UUID = Field(
        ...,
        description="Unique UUIDv4 identifier assigned to the preserved evidence record",
    )
    status: str = Field(
        default="stored",
        description="Preservation status",
        examples=["stored"],
    )
    raw_event_hash: str = Field(
        ...,
        description="SHA-256 cryptographic digest of exact raw event content",
        examples=["5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"],
    )
    ingested_at: datetime = Field(
        ...,
        description="UTC timestamp when evidence was committed to the vault",
    )
    message: str = Field(
        default="Raw evidence securely preserved in Evidence Vault",
        description="Human-readable status message",
    )


class EvidenceEventResponse(BaseModel):
    """Complete representation of a preserved evidence event."""

    event_id: UUID
    source_name: str
    source_type: str
    raw_event: str
    raw_event_hash: str
    ingested_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)
    integrity_status: str

    model_config = ConfigDict(from_attributes=True)


class EvidenceListResponse(BaseModel):
    """Paginated collection of evidence events."""

    items: List[EvidenceEventResponse]
    total: int = Field(..., description="Total count of matching evidence records")
    limit: int = Field(..., description="Pagination limit")
    offset: int = Field(..., description="Pagination offset")


class EvidenceVerificationResponse(BaseModel):
    """Cryptographic integrity verification result."""

    event_id: UUID
    stored_hash: str = Field(
        ...,
        description="SHA-256 digest recorded in the database at ingestion time",
    )
    calculated_hash: str = Field(
        ...,
        description="SHA-256 digest computed live over the stored raw_event string",
    )
    integrity_valid: bool = Field(
        ...,
        description="True if calculated_hash == stored_hash, False if tampered",
    )
    status: str = Field(
        ...,
        description="'INTEGRITY_VERIFIED' or 'TAMPER_DETECTED'",
    )
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the verification check",
    )
