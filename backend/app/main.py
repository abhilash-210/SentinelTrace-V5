"""
main.py
-------
FastAPI application entrypoint for SENTINEL-TRACE.

Sprint 2 — Source Parsing & OCSF-Aligned Normalization.
"""

import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.config import settings
from app.database import Base, SessionLocal, engine, verify_database_connection
from app.models import (  # noqa: F401
    IngestedEvent,
    NormalizedEvent,
    ProtectedSemanticField,
    SemanticDriftAlert,
    SemanticInterpretation,
    SemanticPolicy,
    SemanticPolicyRule,
    SourceProfile,
    DetectionRule,
    DetectionRuleDependency,
    DetectionRuleTrustEvaluation,
    DetectionTrustAlert,
    DetectionRuleVersion,
    DetectionRuleVersionDependency,
    DetectionRuleApprovalRequest,
    DetectionRuleVersionImpact,
    DetectionRuleGovernanceEvent,
    DetectionExecution,
    DetectionConditionResult,
    RiskCorrelation,
    RiskCorrelationMember,
    RemediationCandidate,
    RemediationAction,
    SecurityIncident,
    IncidentSignal,
    IncidentEvidenceLink,
    IncidentFinding,
    IncidentTimelineEvent,
    IncidentResponsePlaybook,
    IncidentPlaybookAction,
    IncidentResponseRecommendation,
    IncidentContainmentRequest,
    IncidentResponseApproval,
    IncidentResponseExecution,
    IncidentResponseVerification,
)
from app.routers import auth as auth_router
from app.routers import detection_rules as detection_rules_router
from app.routers import detection_rule_trust as detection_rule_trust_router
from app.routers import detection_rule_governance as detection_rule_governance_router
from app.routers import detection_execution as detection_execution_router
from app.routers import risk_correlations as risk_correlations_router
from app.routers import remediation as remediation_router
from app.routers import security_incidents as security_incidents_router
from app.routers import incident_response as incident_response_router
from app.routers import security_assurance as security_assurance_router
from app.routers import assurance_remediation as assurance_remediation_router
from app.routers import executive_security_intelligence as executive_security_intelligence_router
from app.routers import security_scenarios as security_scenarios_router
from app.routers import compliance_intelligence as compliance_intelligence_router
from app.routers import threat_intelligence as threat_intelligence_router
from app.routers import security_investigations as security_investigations_router
from app.routers import security_analytics as security_analytics_router
from app.routers import events as events_router
from app.routers import governance_ledger as governance_ledger_router
from app.routers import health as health_router
from app.routers import ingest as ingest_router
from app.routers import merkle as merkle_router
from app.routers import normalization as normalization_router
from app.routers import policy_governance as policy_governance_router
from app.routers import semantic_interpretation as semantic_interpretation_router
from app.routers import semantic_policy as semantic_policy_router
from app.routers import user as user_router
from app.services.detection_rule_service import DetectionRuleService
from app.services.detection_rule_trust_service import DetectionRuleTrustService
from app.services.detection_rule_governance_service import DetectionRuleGovernanceService
from app.services.detection_execution_service import DetectionExecutionService
from app.services.risk_correlation_service import RiskCorrelationService
from app.services.remediation_service import RemediationService
from app.services.incident_service import IncidentService
from app.services.incident_response_service import IncidentResponseService
from app.services.security_assurance_service import SecurityAssuranceService
from app.services.compliance_posture_service import CompliancePostureService
from app.services.threat_actor_campaign_service import ThreatActorCampaignService
from app.services.investigation_artifact_service import InvestigationArtifactService
from app.services.normalization_service import NormalizationService
from app.services.semantic_policy_service import SemanticPolicyService
from app.services.user_service import UserService

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


# ── Lifespan (startup / shutdown) ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manage application startup and shutdown events.
    """
    # ── Startup ────────────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("  SENTINEL-TRACE Backend  |  %s", settings.APP_VERSION)
    logger.info("  Sprint      : Sprint 11B (Threat Intelligence & Adversary Context)")
    logger.info("  Environment : %s", settings.APP_ENV)
    logger.info("  Database    : %s:%s/%s", settings.POSTGRES_HOST, settings.POSTGRES_PORT, settings.POSTGRES_DB)
    logger.info("=" * 60)

    try:
        verify_database_connection()
        logger.info("PostgreSQL connection verified.")

        # Ensure sentinel schema and tables are created
        if engine.dialect.name == "postgresql":
            with engine.begin() as conn:
                conn.execute(text("CREATE SCHEMA IF NOT EXISTS sentinel;"))
        Base.metadata.create_all(bind=engine)

        # Seed default Source Profiles, Semantic Policies, Demo Users, Rules, Remediation, Incidents, Playbooks, Assurance Metrics, Compliance Baseline & Threat Intelligence
        with SessionLocal() as db:
            NormalizationService.ensure_default_source_profiles(db)
            SemanticPolicyService.seed_defaults(db)
            UserService.seed_demo_users(db)
            DetectionRuleService.seed_defaults(db)
            DetectionRuleTrustService.seed_demo_trust_scenarios(db)
            DetectionRuleGovernanceService.seed_default_governed_versions(db)
            DetectionExecutionService.seed_demo_execution_scenarios(db)
            RemediationService.seed_demo_scenarios(db)
            IncidentService.seed_demo_scenarios(db)
            IncidentResponseService.seed_defaults(db)
            SecurityAssuranceService.seed_default_metric_definitions(db)
            CompliancePostureService.seed_default_frameworks_and_controls(db)
            ThreatActorCampaignService.seed_default_threat_intelligence(db)
            InvestigationArtifactService.seed_default_investigations(db)
        logger.info("Database schema, tables, Source Profiles, Semantic Policies, Detection Rules, Governed Versions, Execution, Remediation, Incident Scenarios, Response Playbooks, Assurance Metrics, Compliance Baseline, Threat Intelligence, and SOC Investigations verified.")
    except Exception as exc:
        logger.error("Database initialization error: %s", exc)
        logger.warning("    Backend will start but database operations may fail until reachable.")

    yield

    # ── Shutdown ───────────────────────────────────────────────────────────────
    logger.info("SENTINEL-TRACE Backend shutting down.")


# ── Application ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SENTINEL-TRACE API",
    description=(
        "**SENTINEL-TRACE** — Verifiable Security Log Normalization "
        "& Semantic Trust Governance Platform\n\n"
        "### Sprint 12A: Unified SOC Investigation & Security Case Management\n"
        "- **Unified SOC Case Orchestration**: Connects detections, threat intel, incidents, risk, and compliance into governed cases.\n"
        "- **Automatic Artifact Discovery**: Cross-domain reference bindings without data duplication.\n"
        "- **Deterministic Prioritization**: Explainable scores (0-100) with cryptographic hard failure dominance.\n"
        "- **Hypothesis Management**: Rule-based formulation with explainable confidence deductions (Zero ML/LLM).\n"
        "- **Cross-Domain Timeline**: Chronological event reconstruction preserving source timestamps.\n"
        "- **Maker-Checker Governance**: Independent reviewer sign-off with self-approval prohibition (HTTP 409).\n"
        "- **18-Stage Cryptographic Lineage**: Traceable from analyst question back to raw evidence.\n"
    ),
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ── CORS ───────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ────────────────────────────────────────────────────────────────────
app.include_router(health_router.router)
app.include_router(auth_router.router)
app.include_router(user_router.router)
app.include_router(ingest_router.router)
app.include_router(events_router.router)
app.include_router(normalization_router.router)
app.include_router(semantic_policy_router.router)
app.include_router(semantic_interpretation_router.router)
app.include_router(policy_governance_router.router)
app.include_router(governance_ledger_router.router)
app.include_router(merkle_router.router)
app.include_router(detection_rules_router.router)
app.include_router(detection_rule_trust_router.router)
app.include_router(detection_rule_governance_router.router)
app.include_router(detection_execution_router.router)
app.include_router(risk_correlations_router.router)
app.include_router(remediation_router.router)
app.include_router(security_incidents_router.router)
app.include_router(incident_response_router.router)
app.include_router(security_assurance_router.router)
app.include_router(assurance_remediation_router.router)
app.include_router(executive_security_intelligence_router.router)
app.include_router(security_scenarios_router.router)
app.include_router(compliance_intelligence_router.router)
app.include_router(threat_intelligence_router.router)
app.include_router(security_investigations_router.router)
app.include_router(security_analytics_router.router)




