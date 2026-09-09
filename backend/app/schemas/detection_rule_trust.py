"""
schemas/detection_rule_trust.py
-------------------------------
Pydantic schemas for Detection Rule Trust Evaluation, Detection Trust Alerts,
and End-to-End Trust Trace Provenance.

Sprint 6B — Detection Rule Trust Evaluation & Semantic Drift Binding.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class TrustScoreDeduction(BaseModel):
    """Single deduction item in trust score calculation."""
    component: str = Field(..., description="Name of the deduction component")
    deduction: float = Field(..., description="Deduction amount (positive number subtracted from base)")
    reason: str = Field(..., description="Explanation for why this deduction was applied")


class TrustEvaluationCreateRequest(BaseModel):
    """Request to manually trigger a detection rule trust evaluation."""
    rule_id: str = Field(..., description="Rule ID to evaluate")
    normalized_event_id: Optional[str] = Field(None, description="Optional event ID for event-specific trust evaluation")
    interpretation_id: Optional[str] = Field(None, description="Optional interpretation ID")
    canonical_field: Optional[str] = Field(None, description="Specific canonical field or evaluate all dependencies")


class DriftAlertImpactEvaluationRequest(BaseModel):
    """Request to evaluate rule impact from a semantic drift alert."""
    alert_id: str = Field(..., description="Semantic drift alert ID")


class DetectionRuleTrustEvaluationResponse(BaseModel):
    """Response model for a single trust evaluation record."""
    id: int
    evaluation_id: str
    rule_id: str
    rule_name: Optional[str] = None
    rule_severity: Optional[str] = None
    vendor_name: Optional[str] = None
    normalized_event_id: Optional[str] = None
    interpretation_id: Optional[str] = None
    drift_alert_id: Optional[str] = None
    canonical_field: str
    trust_status: str
    trust_score: float
    risk_level: str
    evaluation_reasons: List[str]
    explanation: str
    evaluation_version: int
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class DetectionTrustAlertResponse(BaseModel):
    """Response model for a detection trust alert."""
    id: int
    alert_id: str
    rule_id: str
    rule_name: Optional[str] = None
    evaluation_id: str
    drift_alert_id: Optional[str] = None
    alert_type: str
    severity: str
    status: str
    description: str
    affected_field: str
    trust_status: str
    trust_score: float
    created_at: Optional[str] = None
    resolved_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class DetectionTrustAlertStatusUpdate(BaseModel):
    """Request model for updating alert status."""
    status: str = Field(..., description="New status: 'OPEN', 'ACKNOWLEDGED', 'RESOLVED'")


class DependencyTrustItem(BaseModel):
    """Single dependency status within a multi-dependency rule inspection."""
    canonical_field: str
    dependency_type: str
    is_protected: bool
    drift_status: str
    trust_status: str
    trust_score: float
    deduction_applied: float
    explanation: str


class RuleTrustInspectionResponse(BaseModel):
    """Comprehensive inspection of a rule's trust state and dependencies."""
    rule_id: str
    rule_name: str
    vendor_name: str
    rule_status: str
    rule_severity: str
    overall_trust_status: str
    overall_trust_score: float
    overall_risk_level: str
    worst_dependency_field: Optional[str] = None
    evaluation_id: Optional[str] = None
    created_at: Optional[str] = None
    explanation: str
    evaluation_reasons: List[str]
    dependencies: List[DependencyTrustItem]


class TrustTraceProvenanceStep(BaseModel):
    """Single step in the end-to-end trust trace provenance chain."""
    step_number: int
    stage_name: str
    entity_id: str
    entity_type: str
    summary: str
    details: Dict[str, Any]
    timestamp: Optional[str] = None


class EndToEndTrustTraceResponse(BaseModel):
    """Complete provenance chain from Raw Evidence to Detection Trust Alert."""
    evaluation_id: str
    rule_id: str
    rule_name: str
    trust_status: str
    trust_score: float
    provenance_chain: List[TrustTraceProvenanceStep]


class TrustKPISummaryResponse(BaseModel):
    """Aggregated KPI metrics for detection rule trust."""
    total_evaluations: int
    trusted_rules_count: int
    degraded_rules_count: int
    at_risk_rules_count: int
    invalid_rules_count: int
    unknown_rules_count: int
    open_alerts_count: int
    critical_alerts_count: int
