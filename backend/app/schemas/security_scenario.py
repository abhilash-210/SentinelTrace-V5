"""
schemas/security_scenario.py
----------------------------
Pydantic v2 schemas for Sprint 10B End-to-End Security Scenario Orchestration,
Demonstration Validation, Cross-Domain Evidence Replay, and Scenario Verification.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class ScenarioCategory(str, Enum):
    IDENTITY_COMPROMISE = "IDENTITY_COMPROMISE"
    ENDPOINT_MALWARE = "ENDPOINT_MALWARE"
    TRUST_DEGRADATION = "TRUST_DEGRADATION"
    CRYPTO_VERIFICATION = "CRYPTO_VERIFICATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    NETWORK_INTRUSION = "NETWORK_INTRUSION"


class ScenarioSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScenarioStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


class ScenarioVersionStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"


class ScenarioExecutionMode(str, Enum):
    LIVE_PIPELINE = "LIVE_PIPELINE"
    CONTROLLED_DEMO = "CONTROLLED_DEMO"
    HISTORICAL_REPLAY = "HISTORICAL_REPLAY"
    EVIDENCE_REPLAY = "EVIDENCE_REPLAY"
    CONTROLLED_REEXECUTION = "CONTROLLED_REEXECUTION"


class ScenarioExecutionStatus(str, Enum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScenarioStageStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


class ScenarioVerificationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


class ScenarioImpactClassification(str, Enum):
    CRITICAL_NEGATIVE = "CRITICAL_NEGATIVE"
    HIGH_NEGATIVE = "HIGH_NEGATIVE"
    MODERATE_NEGATIVE = "MODERATE_NEGATIVE"
    LOW_NEGATIVE = "LOW_NEGATIVE"
    NEUTRAL = "NEUTRAL"
    POSITIVE_RECOVERY = "POSITIVE_RECOVERY"


# ── Request Models ────────────────────────────────────────────────────────────

class SecurityScenarioCreate(BaseModel):
    scenario_key: str = Field(..., description="Unique scenario key e.g. SCN_CREDENTIAL_COMPROMISE")
    scenario_name: str = Field(..., description="Human-readable title")
    description: str = Field(..., description="Detailed narrative description")
    category: ScenarioCategory = Field(default=ScenarioCategory.IDENTITY_COMPROMISE)
    severity: ScenarioSeverity = Field(default=ScenarioSeverity.HIGH)
    status: ScenarioStatus = Field(default=ScenarioStatus.ACTIVE)


class SecurityScenarioVersionCreate(BaseModel):
    scenario_definition_json: Dict[str, Any] = Field(..., description="Canonical scenario event definitions")
    expected_stage_sequence_json: List[Dict[str, Any]] = Field(default_factory=list, description="Expected 20-stage sequence")
    expected_outcomes_json: Dict[str, Any] = Field(default_factory=dict, description="Expected detection and posture outcomes")
    deterministic_seed: str = Field(default="SENTINELTRACE_SCENARIO_SEED_V1", description="Deterministic execution seed")
    status: ScenarioVersionStatus = Field(default=ScenarioVersionStatus.ACTIVE)


class ScenarioExecutionCreateRequest(BaseModel):
    version_id: Optional[str] = Field(default=None, description="Specific scenario version ID, defaults to current active version")
    execution_mode: ScenarioExecutionMode = Field(default=ScenarioExecutionMode.CONTROLLED_DEMO)
    deterministic_seed_override: Optional[str] = Field(default=None)
    notes: Optional[str] = Field(default="")


class ScenarioReplayRequest(BaseModel):
    execution_mode: ScenarioExecutionMode = Field(default=ScenarioExecutionMode.HISTORICAL_REPLAY)
    verify_against_original: bool = Field(default=True)
    notes: Optional[str] = Field(default="Replay verification")


class ScenarioVerifyRequest(BaseModel):
    check_ledger: bool = Field(default=True)
    check_merkle: bool = Field(default=True)
    notes: Optional[str] = Field(default="")


# ── Response Models ───────────────────────────────────────────────────────────

class SecurityScenarioResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scenario_key: str
    scenario_name: str
    description: str
    category: str
    severity: str
    status: str
    current_version_id: Optional[str] = None
    created_by_user_id: str
    created_at: datetime
    updated_at: datetime


class SecurityScenarioVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scenario_id: str
    version_number: int
    scenario_definition_json: Dict[str, Any]
    expected_stage_sequence_json: List[Any]
    expected_outcomes_json: Dict[str, Any]
    deterministic_seed: str
    definition_hash: str
    status: str
    created_by_user_id: str
    created_at: datetime


class ScenarioStageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scenario_execution_id: str
    stage_number: int
    stage_key: str
    stage_name: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    input_reference_json: Dict[str, Any]
    output_reference_json: Dict[str, Any]
    verification_result: str
    error_code: Optional[str] = None
    execution_hash: str


class ScenarioArtifactBindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scenario_execution_id: str
    stage_execution_id: str
    artifact_domain: str
    artifact_type: str
    artifact_id: str
    artifact_hash: str
    artifact_reference_json: Dict[str, Any]
    binding_hash: str
    created_at: datetime


class ScenarioVerificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scenario_execution_id: str
    total_stages: int
    verified_stages: int
    degraded_stages: int
    failed_stages: int
    missing_stages: int
    provenance_integrity: str
    ledger_integrity: str
    merkle_integrity: str
    overall_verification_status: str
    verification_summary_json: Dict[str, Any]
    verification_hash: str
    verified_at: datetime
    verified_by_user_id: str


class ScenarioExecutiveImpactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scenario_execution_id: str
    pre_executive_posture_id: Optional[str] = None
    post_executive_posture_id: Optional[str] = None
    pre_score: float
    post_score: float
    score_delta: float
    pre_status: str
    post_status: str
    impacted_domains_json: List[Any]
    top_risk_driver_delta_json: List[Any]
    impact_classification: str
    created_at: datetime


class ScenarioExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    execution_number: str
    scenario_id: str
    scenario_version_id: str
    execution_mode: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    initiated_by_user_id: str
    deterministic_execution_seed: str
    execution_hash: str
    verification_status: str
    stages: Optional[List[ScenarioStageResponse]] = None
    artifact_bindings: Optional[List[ScenarioArtifactBindingResponse]] = None
    verification_result: Optional[ScenarioVerificationResponse] = None
    executive_impact: Optional[ScenarioExecutiveImpactResponse] = None


class ScenarioReplayResponse(BaseModel):
    original_execution_id: str
    replay_execution_id: Optional[str] = None
    replay_mode: str
    comparison_status: str  # IDENTICAL, FUNCTIONALLY_EQUIVALENT, DIFFERENT, INCONCLUSIVE
    divergent_stages: List[Dict[str, Any]] = Field(default_factory=list)
    reconstructed_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    integrity_verified: bool
    summary: str


class ScenarioProvenanceNode(BaseModel):
    stage_number: int
    stage_key: str
    stage_name: str
    domain: str
    artifact_type: str
    artifact_id: Optional[str] = None
    artifact_hash: Optional[str] = None
    verification_status: str
    upstream_reference: Optional[str] = None
    downstream_reference: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class ScenarioDashboardSummary(BaseModel):
    total_scenarios: int
    active_scenarios: int
    total_executions: int
    completed_executions: int
    verified_executions: int
    degraded_executions: int
    failed_executions: int
    pipeline_integrity_rate: float
    recent_executions: List[Dict[str, Any]] = Field(default_factory=list)
