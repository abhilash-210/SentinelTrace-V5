"""
models package
--------------
SQLAlchemy models for SENTINEL-TRACE.

Sprint 0: Project Foundation Base
Sprint 1: IngestedEvent for raw event preservation and integrity
Sprint 2: SourceProfile and NormalizedEvent for OCSF-aligned canonical normalization
Sprint 6A: DetectionRule and DetectionRuleDependency for detection rule registry
"""

from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.semantic_interpretation import (
    SemanticDriftAlert,
    SemanticInterpretation,
)
from app.models.semantic_policy import (
    ProtectedSemanticField,
    SemanticPolicy,
    SemanticPolicyRule,
)
from app.models.governance import GovernanceAuditLog, PolicyApprovalRequest
from app.models.ledger import GovernanceLedgerEntry
from app.models.merkle import MerkleBatch, MerkleProof
from app.models.detection_rule import DetectionRule, DetectionRuleDependency
from app.models.detection_rule_trust import (
    DetectionRuleTrustEvaluation,
    DetectionTrustAlert,
)
from app.models.detection_rule_governance import (
    DetectionRuleApprovalRequest,
    DetectionRuleGovernanceEvent,
    DetectionRuleVersion,
    DetectionRuleVersionDependency,
    DetectionRuleVersionImpact,
)
from app.models.detection_execution import (
    DetectionExecution,
    DetectionConditionResult,
)
from app.models.risk_correlation import (
    RiskCorrelation,
    RiskCorrelationMember,
)
from app.models.remediation import (
    RemediationCandidate,
    RemediationAction,
)
from app.models.security_incident import (
    SecurityIncident,
    IncidentSignal,
    IncidentEvidenceLink,
    IncidentFinding,
    IncidentTimelineEvent,
)
from app.models.incident_response import (
    IncidentResponsePlaybook,
    IncidentPlaybookAction,
    IncidentResponseRecommendation,
    IncidentContainmentRequest,
    IncidentResponseApproval,
    IncidentResponseExecution,
    IncidentResponseVerification,
)
from app.models.security_assurance import (
    AssuranceDomainEvaluation,
    PlatformAssuranceEvaluation,
    AssuranceAlert,
    AssuranceMetricDefinition,
    AssuranceTrendSnapshot,
)
from app.models.assurance_remediation import (
    AssuranceRemediationCase,
    AssuranceRootCauseAnalysis,
    AssuranceRemediationRecommendation,
    AssuranceRemediationPlan,
    AssuranceRemediationApproval,
    AssuranceRemediationExecution,
    AssuranceRecoveryVerification,
    AssuranceRecoveryRecord,
)
from app.models.executive_security_intelligence import (
    ExecutiveSecurityPostureEvaluation,
    ExecutivePostureDomainScore,
    ExecutiveRiskDriver,
    ExecutivePostureTrendSnapshot,
    ExecutiveSecurityInsight,
)
from app.models.source_profile import SourceProfile
from app.models.user import User
from app.models.security_scenario import (
    SecurityScenario,
    SecurityScenarioVersion,
    ScenarioExecution,
    ScenarioStageExecution,
    ScenarioArtifactBinding,
    ScenarioVerificationResult,
    ScenarioExecutiveImpact,
)
from app.models.compliance_intelligence import (
    ComplianceFramework,
    ComplianceRequirement,
    SecurityControl,
    FrameworkControlMapping,
    ControlEvidenceBinding,
    ControlEffectivenessEvaluation,
    ComplianceGap,
    ComplianceFinding,
    CompliancePostureEvaluation,
    ComplianceReview,
    ComplianceProvenanceRecord,
)
from app.models.threat_intelligence import (
    ThreatIntelligenceSource,
    ThreatIntelligenceArtifact,
    ThreatIndicator,
    ThreatActor,
    ThreatCampaign,
    ThreatActorCampaignMapping,
    ThreatMitreMapping,
    ThreatIntelligenceCorrelation,
    ThreatIntelligenceTrustEvaluation,
    ThreatIntelligenceInsight,
    ThreatIntelligenceProvenanceRecord,
)
from app.models.security_investigation import (
    SecurityInvestigationCase,
    InvestigationArtifactBinding,
    InvestigationHypothesis,
    InvestigationFinding,
    InvestigationTimelineEvent,
    InvestigationImpactAssessment,
    InvestigationReview,
    InvestigationCaseResolution,
    InvestigationProvenanceRecord,
)
from app.models.security_analytics import (
    SecurityAnalyticsSnapshot,
    SecurityMetricDefinition,
    SecurityMetricEvaluation,
    SecurityTrendSnapshot,
    SecurityAnalyticsInsight,
    SecurityReport,
    SecurityReportSection,
    SecurityEvidencePackage,
    EvidencePackageArtifact,
    SecurityAnalyticsProvenanceRecord,
)

__all__ = [
    "IngestedEvent",
    "NormalizedEvent",
    "SemanticInterpretation",
    "SemanticDriftAlert",
    "SemanticPolicy",
    "SemanticPolicyRule",
    "ProtectedSemanticField",
    "PolicyApprovalRequest",
    "GovernanceAuditLog",
    "GovernanceLedgerEntry",
    "MerkleBatch",
    "MerkleProof",
    "SourceProfile",
    "User",
    "DetectionRule",
    "DetectionRuleDependency",
    "DetectionRuleTrustEvaluation",
    "DetectionTrustAlert",
    "DetectionRuleVersion",
    "DetectionRuleVersionDependency",
    "DetectionRuleApprovalRequest",
    "DetectionRuleVersionImpact",
    "DetectionRuleGovernanceEvent",
    "DetectionExecution",
    "DetectionConditionResult",
    "RiskCorrelation",
    "RiskCorrelationMember",
    "RemediationCandidate",
    "RemediationAction",
    "SecurityIncident",
    "IncidentSignal",
    "IncidentEvidenceLink",
    "IncidentFinding",
    "IncidentTimelineEvent",
    "IncidentResponsePlaybook",
    "IncidentPlaybookAction",
    "IncidentResponseRecommendation",
    "IncidentContainmentRequest",
    "IncidentResponseApproval",
    "IncidentResponseExecution",
    "IncidentResponseVerification",
    "AssuranceDomainEvaluation",
    "PlatformAssuranceEvaluation",
    "AssuranceAlert",
    "AssuranceMetricDefinition",
    "AssuranceTrendSnapshot",
    "AssuranceRemediationCase",
    "AssuranceRootCauseAnalysis",
    "AssuranceRemediationRecommendation",
    "AssuranceRemediationPlan",
    "AssuranceRemediationApproval",
    "AssuranceRemediationExecution",
    "AssuranceRecoveryVerification",
    "AssuranceRecoveryRecord",
    "ExecutiveSecurityPostureEvaluation",
    "ExecutivePostureDomainScore",
    "ExecutiveRiskDriver",
    "ExecutivePostureTrendSnapshot",
    "ExecutiveSecurityInsight",
    "SecurityScenario",
    "SecurityScenarioVersion",
    "ScenarioExecution",
    "ScenarioStageExecution",
    "ScenarioArtifactBinding",
    "ScenarioVerificationResult",
    "ScenarioExecutiveImpact",
    "ComplianceFramework",
    "ComplianceRequirement",
    "SecurityControl",
    "FrameworkControlMapping",
    "ControlEvidenceBinding",
    "ControlEffectivenessEvaluation",
    "ComplianceGap",
    "ComplianceFinding",
    "CompliancePostureEvaluation",
    "ComplianceReview",
    "ComplianceProvenanceRecord",
    "ThreatIntelligenceSource",
    "ThreatIntelligenceArtifact",
    "ThreatIndicator",
    "ThreatActor",
    "ThreatCampaign",
    "ThreatActorCampaignMapping",
    "ThreatMitreMapping",
    "ThreatIntelligenceCorrelation",
    "ThreatIntelligenceTrustEvaluation",
    "ThreatIntelligenceInsight",
    "ThreatIntelligenceProvenanceRecord",
    "SecurityInvestigationCase",
    "InvestigationArtifactBinding",
    "InvestigationHypothesis",
    "InvestigationFinding",
    "InvestigationTimelineEvent",
    "InvestigationImpactAssessment",
    "InvestigationReview",
    "InvestigationCaseResolution",
    "InvestigationProvenanceRecord",
    "SecurityAnalyticsSnapshot",
    "SecurityMetricDefinition",
    "SecurityMetricEvaluation",
    "SecurityTrendSnapshot",
    "SecurityAnalyticsInsight",
    "SecurityReport",
    "SecurityReportSection",
    "SecurityEvidencePackage",
    "EvidencePackageArtifact",
    "SecurityAnalyticsProvenanceRecord",
]
