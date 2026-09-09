"""
schemas/semantic_interpretation.py
----------------------------------
Pydantic schemas for Semantic Interpretations, Drift Alerts, and End-to-End Traces.

Sprint 3B — Semantic Interpretation Engine & Semantic Drift Detection.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class SemanticDriftAlertResponse(BaseModel):
    """Response representation of a Semantic Drift Alert."""

    id: int
    alert_id: str = Field(..., description="Unique alert identifier")
    normalized_event_id: str = Field(..., description="Associated normalized event identifier")
    interpretation_id: Optional[str] = Field(default=None, description="Linked semantic interpretation ID")
    policy_id: Optional[str] = Field(default=None, description="Active policy ID during evaluation")
    drift_type: str = Field(
        ...,
        description="Type: 'UNMAPPED_VALUE', 'AMBIGUOUS_MAPPING', 'POLICY_CONFLICT', 'PROTECTED_FIELD_RISK', 'INCOMPATIBLE_MAPPING'",
    )
    severity: str = Field(..., description="Severity level: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")
    status: str = Field(default="OPEN", description="State: 'OPEN', 'ACKNOWLEDGED', 'RESOLVED'")
    description: str = Field(..., description="Explanatory text for the semantic drift/anomaly")
    expected_value: Optional[str] = Field(default=None, description="Expected semantic value")
    observed_value: Optional[str] = Field(default=None, description="Observed raw/mapped value")
    detected_at: datetime
    resolved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SemanticInterpretationResponse(BaseModel):
    """Response representation of a derived Semantic Interpretation."""

    id: int
    interpretation_id: str = Field(..., description="Unique semantic interpretation ID")
    normalized_event_id: str = Field(..., description="Linked normalized event ID")
    original_event_id: str = Field(..., description="Direct link back to raw evidence in Evidence Vault")
    policy_id: Optional[str] = Field(default=None, description="Matched vendor policy ID")
    policy_version: Optional[int] = Field(default=None, description="Version of the evaluated policy")
    vendor_name: str = Field(..., description="Vendor context")
    source_profile_id: str = Field(..., description="Source profile identifier")
    source_field: str = Field(..., description="Evaluated source field name")
    source_value: str = Field(..., description="Raw value from source")
    canonical_field: str = Field(..., description="Target canonical field name")
    interpreted_value: Optional[str] = Field(default=None, description="Interpreted canonical value")
    equivalence_classification: Optional[str] = Field(
        default=None,
        description="Equivalence level: 'EQUIVALENT', 'COMPATIBLE', 'AMBIGUOUS', 'INCOMPATIBLE'",
    )
    risk_level: str = Field(default="LOW", description="Evaluated risk: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'")
    interpretation_status: str = Field(
        default="INTERPRETED",
        description="Status: 'INTERPRETED', 'UNMAPPED', 'AMBIGUOUS', 'CONFLICT', 'FAILED'",
    )
    confidence_score: float = Field(default=1.0, description="Deterministic semantic confidence (0.0 to 1.0)")
    confidence_reasons: List[str] = Field(default_factory=list, description="Deduction and calculation reasons")
    explanation: str = Field(..., description="Explainable audit explanation of semantic derivation")
    created_at: datetime
    drift_alerts: List[SemanticDriftAlertResponse] = Field(
        default_factory=list,
        description="Drift alerts spawned by this interpretation",
    )

    model_config = ConfigDict(from_attributes=True)


class SemanticInterpretationListResponse(BaseModel):
    """Paginated collection of semantic interpretations."""

    items: List[SemanticInterpretationResponse]
    total: int
    limit: int
    offset: int


class SemanticDriftAlertListResponse(BaseModel):
    """Paginated collection of semantic drift alerts."""

    items: List[SemanticDriftAlertResponse]
    total: int
    limit: int
    offset: int


class SemanticTraceResponse(BaseModel):
    """End-to-end explainable audit trace from raw evidence through semantic decision."""

    interpretation_id: str
    raw_evidence: Dict[str, Any] = Field(..., description="Raw Evidence Vault preservation metadata")
    normalized_event: Dict[str, Any] = Field(..., description="OCSF canonical normalized event snapshot")
    source_profile: Dict[str, Any] = Field(..., description="Source Profile metadata")
    vendor: str = Field(..., description="Vendor context")
    semantic_policy: Optional[Dict[str, Any]] = Field(default=None, description="Matched vendor Semantic Policy")
    matched_rule: Optional[Dict[str, Any]] = Field(default=None, description="Specific policy rule applied")
    semantic_decision: Dict[str, Any] = Field(..., description="Semantic outcome, classification, and score")
    drift_alerts: List[SemanticDriftAlertResponse] = Field(default_factory=list, description="Associated drift alerts")
