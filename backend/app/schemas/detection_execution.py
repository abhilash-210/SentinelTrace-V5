"""
schemas/detection_execution.py
-------------------------------
Pydantic response and request models for Detection Execution Engine.

Sprint 7A — Real-Time Detection Rule Execution Engine.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConditionEvaluationDetail(BaseModel):
    """Detailed result for an individual atomic condition evaluation."""
    condition_index: int
    canonical_field: str
    comparison_operator: str
    expected_value: Optional[Any] = None
    observed_value: Optional[Any] = None
    field_resolved: bool
    condition_result: str  # TRUE, FALSE, MISSING, ERROR
    explanation: Optional[str] = None


class DetectionExecutionResponse(BaseModel):
    """Execution record for a detection rule evaluated against a normalized event."""
    execution_id: str
    rule_id: str
    rule_name: Optional[str] = None
    rule_version_id: str
    rule_version_number: int
    normalized_event_id: str
    original_event_id: str
    execution_status: str  # MATCH, NO_MATCH, PARTIAL, ERROR
    matched: bool
    conditions_total: int
    conditions_matched: int
    conditions_missing: int
    execution_fingerprint: str
    execution_details: Dict[str, Any] = Field(default_factory=dict)
    execution_explanation: Optional[str] = None
    executed_at: Optional[str] = None
    execution_engine_version: str
    condition_results: List[ConditionEvaluationDetail] = Field(default_factory=list)


class DetectionExecutionListResponse(BaseModel):
    """Paginated list of detection execution records."""
    total: int
    offset: int
    limit: int
    executions: List[DetectionExecutionResponse]


class RunDetectionsForEventResponse(BaseModel):
    """Summary of batch executing all ACTIVE rules against a normalized event."""
    normalized_event_id: str
    original_event_id: str
    rules_evaluated: int
    matches: int
    no_matches: int
    partial: int
    errors: int
    executions: List[DetectionExecutionResponse] = Field(default_factory=list)


class ExecutionProvenanceTraceResponse(BaseModel):
    """
    10-stage end-to-end cryptographic and governance provenance trace
    for a detection execution.
    """
    execution_id: str
    execution_status: str
    matched: bool
    executed_at: Optional[str] = None
    execution_engine_version: str
    stages: List[Dict[str, Any]] = Field(default_factory=list)
