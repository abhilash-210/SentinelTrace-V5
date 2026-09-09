"""
schemas/risk_correlation.py
---------------------------
Pydantic v2 schemas for Risk Correlations, Concentration Clusters, and Graph DAGs.

Sprint 7B — Security Posture Risk Correlation, Prioritized Remediation & Executive Risk Intelligence.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class CorrelationTypeEnum(str, Enum):
    SINGLE_SIGNAL = "SINGLE_SIGNAL"
    MULTI_SIGNAL = "MULTI_SIGNAL"
    DEPENDENCY_CHAIN = "DEPENDENCY_CHAIN"
    PROTECTED_FIELD_CHAIN = "PROTECTED_FIELD_CHAIN"
    TRUST_DEGRADATION_CHAIN = "TRUST_DEGRADATION_CHAIN"
    CRITICAL_RISK_CLUSTER = "CRITICAL_RISK_CLUSTER"


class CorrelationSeverityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CorrelationStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    INVESTIGATING = "INVESTIGATING"
    MITIGATED = "MITIGATED"
    CLOSED = "CLOSED"


class MemberTypeEnum(str, Enum):
    SEMANTIC_DRIFT_ALERT = "SEMANTIC_DRIFT_ALERT"
    DETECTION_TRUST_ALERT = "DETECTION_TRUST_ALERT"
    TRUST_EVALUATION = "TRUST_EVALUATION"
    DETECTION_RULE = "DETECTION_RULE"
    CANONICAL_FIELD = "CANONICAL_FIELD"
    PROTECTED_FIELD = "PROTECTED_FIELD"
    GOVERNANCE_VIOLATION = "GOVERNANCE_VIOLATION"
    DETECTION_EXECUTION = "DETECTION_EXECUTION"
    RAW_EVIDENCE = "RAW_EVIDENCE"
    NORMALIZED_EVENT = "NORMALIZED_EVENT"


class RelationshipTypeEnum(str, Enum):
    CONTRIBUTING_FACTOR = "CONTRIBUTING_FACTOR"
    DIRECT_DEPENDENCY = "DIRECT_DEPENDENCY"
    DOWNSTREAM_IMPACT = "DOWNSTREAM_IMPACT"
    ROOT_CAUSE_CANDIDATE = "ROOT_CAUSE_CANDIDATE"
    GOVERNANCE_ANCHOR = "GOVERNANCE_ANCHOR"
    CAUSES = "CAUSES"
    DEGRADES = "DEGRADES"
    AFFECTS = "AFFECTS"
    TRIGGERS = "TRIGGERS"
    MITIGATES = "MITIGATES"


class RiskCorrelationMemberResponse(BaseModel):
    id: int
    correlation_id: str
    member_type: str
    member_id: str
    relationship_type: str
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class RiskCorrelationResponse(BaseModel):
    id: int
    correlation_id: str
    correlation_type: str
    severity: str
    status: str
    risk_cluster_key: Optional[str] = None
    affected_signal_count: int
    affected_rule_count: int
    affected_field_count: int
    risk_score: float
    root_cause_candidates: List[Any] = Field(default_factory=list)
    explanation: str
    created_at: Optional[str] = None
    member_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class RiskCorrelationDetailResponse(BaseModel):
    id: int
    correlation_id: str
    correlation_type: str
    severity: str
    status: str
    risk_cluster_key: Optional[str] = None
    affected_signal_count: int
    affected_rule_count: int
    affected_field_count: int
    risk_score: float
    root_cause_candidates: List[Any] = Field(default_factory=list)
    explanation: str
    created_at: Optional[str] = None
    members: List[RiskCorrelationMemberResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class RiskClusterResponse(BaseModel):
    cluster_key: str
    cluster_center: str
    severity: str
    concentration_score: float
    is_protected_field: bool
    affected_rule_count: int
    affected_signal_count: int
    affected_correlations: List[str] = Field(default_factory=list)
    connected_signals: List[Dict[str, Any]] = Field(default_factory=list)
    explanation: str


class GraphNode(BaseModel):
    id: str
    label: str
    node_type: str
    severity: Optional[str] = None
    status: Optional[str] = None
    data: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    label: Optional[str] = None


class RiskCorrelationGraphResponse(BaseModel):
    correlation_id: str
    correlation_type: str
    severity: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    root_cause_candidates: List[str] = Field(default_factory=list)


class RiskAnalysisRequest(BaseModel):
    force_reanalyze: bool = False
    context_note: Optional[str] = None


class RiskAnalysisSummaryResponse(BaseModel):
    correlations_identified: int
    clusters_detected: int
    critical_risk_chains: int
    affected_rules_total: int
    analysis_timestamp: str
    correlations: List[RiskCorrelationResponse] = Field(default_factory=list)
