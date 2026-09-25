"""
schemas/security_analytics.py
-----------------------------
Pydantic validation schemas for Security Analytics, Reporting & Evidence Intelligence.

Sprint 12B — Security Analytics, Reporting & Evidence Intelligence.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import ConfigDict, BaseModel, Field


# ── Metric Schemas ───────────────────────────────────────────────────────────

class SecurityMetricDefinitionResponse(BaseModel):
    id: str
    metric_code: str
    metric_name: str
    description: str
    domain: str
    unit: str
    direction: str
    calculation_method: str
    criticality: str
    requires_complete_telemetry: bool
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityMetricEvaluationResponse(BaseModel):
    id: str
    snapshot_id: str
    metric_definition_id: str
    metric_value: float
    metric_status: str
    confidence_score: float
    sample_count: int
    telemetry_state: str
    calculation_details_json: Dict[str, Any]
    source_references_json: List[Any]
    evaluation_hash: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Snapshot Schemas ─────────────────────────────────────────────────────────

class SecurityAnalyticsSnapshotCreateRequest(BaseModel):
    period_type: Optional[str] = Field("24H", description="24H, 7D, 30D, 90D, CUSTOM")
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    force_crypto_failure: Optional[bool] = False


class SecurityAnalyticsSnapshotResponse(BaseModel):
    id: str
    snapshot_number: str
    period_type: str
    period_start: datetime
    period_end: datetime
    overall_security_score: float
    overall_confidence: float
    telemetry_completeness: float
    domains_evaluated: int
    domains_unknown: int
    critical_findings: int
    high_findings: int
    snapshot_hash: str
    created_at: datetime
    created_by: str

    model_config = ConfigDict(from_attributes=True)


# ── Trend Schemas ────────────────────────────────────────────────────────────

class SecurityTrendResponse(BaseModel):
    id: str
    metric_definition_id: str
    current_snapshot_id: str
    previous_snapshot_id: Optional[str]
    current_value: float
    previous_value: Optional[float]
    delta_value: Optional[float]
    delta_percentage: Optional[float]
    trend_classification: str
    confidence: float
    reasoning_json: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Insight Schemas ──────────────────────────────────────────────────────────

class SecurityAnalyticsInsightResponse(BaseModel):
    id: str
    snapshot_id: str
    insight_code: str
    insight_type: str
    severity: str
    title: str
    description: str
    rule_triggered: str
    supporting_metrics_json: List[Any]
    source_references_json: List[Any]
    confidence_score: float
    limitations_json: List[Any]
    insight_hash: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Report Schemas ───────────────────────────────────────────────────────────

class SecurityReportCreateRequest(BaseModel):
    report_type: str = Field(
        "EXECUTIVE_SECURITY_REPORT",
        description="EXECUTIVE_SECURITY_REPORT, SOC_OPERATIONAL_REPORT, COMPLIANCE_ASSURANCE_REPORT, THREAT_INTELLIGENCE_REPORT, INVESTIGATION_REPORT, ASSURANCE_RECOVERY_REPORT, CUSTOM_SECURITY_REPORT",
    )
    title: Optional[str] = None
    description: Optional[str] = None
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    scope: Optional[str] = "PLATFORM_FULL"


class SecurityReportSectionResponse(BaseModel):
    id: str
    report_id: str
    section_order: int
    section_type: str
    title: str
    summary: str
    content_json: Dict[str, Any]
    source_references_json: List[Any]
    section_hash: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityReportResponse(BaseModel):
    id: str
    report_number: str
    report_type: str
    title: str
    description: str
    period_start: datetime
    period_end: datetime
    status: str
    generated_by_user_id: str
    generated_at: datetime
    canonical_manifest_json: Dict[str, Any]
    report_hash: str
    integrity_status: str
    ledger_reference: Optional[str]
    merkle_reference: Optional[str]
    sections: Optional[List[SecurityReportSectionResponse]] = None

    model_config = ConfigDict(from_attributes=True)


# ── Evidence Package Schemas ─────────────────────────────────────────────────

class SecurityEvidencePackageCreateRequest(BaseModel):
    package_type: Optional[str] = Field(
        "COMPREHENSIVE_AUDIT",
        description="COMPREHENSIVE_AUDIT, INCIDENT_DOSSIER, COMPLIANCE_ATTESTATION, EXECUTIVE_BRIEF, CUSTOM_PACKAGE",
    )
    scope: Optional[str] = "PLATFORM_FULL"
    description: Optional[str] = None


class EvidencePackageArtifactResponse(BaseModel):
    id: str
    package_id: str
    artifact_domain: str
    artifact_type: str
    artifact_id: str
    artifact_hash: str
    source_reference: str
    binding_hash: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityEvidencePackageResponse(BaseModel):
    id: str
    package_number: str
    package_type: str
    scope: str
    description: str
    artifact_count: int
    manifest_json: Dict[str, Any]
    manifest_hash: str
    integrity_status: str
    ledger_reference: Optional[str]
    merkle_reference: Optional[str]
    created_by_user_id: str
    created_at: datetime
    artifacts: Optional[List[EvidencePackageArtifactResponse]] = None

    model_config = ConfigDict(from_attributes=True)


# ── Verification & Provenance Schemas ────────────────────────────────────────

class SecurityReportVerificationResponse(BaseModel):
    report_id: str
    report_number: str
    verified: bool
    status: str
    report_hash_valid: bool
    sections_count: int
    tampered_sections: List[int]
    stored_report_hash: str
    computed_report_hash: str
    ledger_reference: Optional[str]
    merkle_reference: Optional[str]


class SecurityEvidencePackageVerificationResponse(BaseModel):
    package_id: str
    package_number: str
    verified: bool
    status: str
    manifest_hash_valid: bool
    artifact_count: int
    tampered_bindings: List[str]
    stored_manifest_hash: str
    computed_manifest_hash: str
    ledger_reference: Optional[str]
    merkle_reference: Optional[str]


class SecurityAnalyticsProvenanceRecordResponse(BaseModel):
    id: str
    snapshot_id: str
    stage_number: int
    stage_name: str
    artifact_type: str
    artifact_id: str
    artifact_hash: str
    previous_hash: str
    current_hash: str
    verification_status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityAnalyticsProvenanceChainResponse(BaseModel):
    snapshot_id: str
    total_stages: int
    lineage_verified: bool
    provenance_chain: List[SecurityAnalyticsProvenanceRecordResponse]


# ── Dashboard Summary Schema ─────────────────────────────────────────────────

class SecurityAnalyticsDashboardResponse(BaseModel):
    latest_snapshot_id: Optional[str]
    latest_snapshot_number: str
    overall_security_score: float
    overall_confidence: float
    telemetry_completeness: float
    domains_evaluated: int
    critical_findings: int
    high_findings: int
    total_snapshots: int
    total_metric_definitions: int
    snapshot_hash: Optional[str]
    created_at: Optional[str]
