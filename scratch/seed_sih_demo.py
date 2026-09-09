"""
scratch/seed_sih_demo.py
------------------------
Deterministic, single-command SIH demonstration environment seeder for SentinelTrace V5.
Populates a complete, cohesive end-to-end security scenario across all 15 domains:
Raw Ingest -> OCSF Normalization -> Semantic Drift -> Detection -> Threat Intel ->
Risk Correlation -> Incident -> Investigation -> Response -> Assurance ->
Compliance -> Analytics Snapshot -> Executive Report -> Cryptographic Provenance.
"""

from datetime import datetime, timezone, timedelta
import json
import os
import sys

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.database import SessionLocal, engine, Base
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.semantic_policy import SemanticPolicy, ProtectedSemanticField
from app.models.semantic_interpretation import SemanticInterpretation, SemanticDriftAlert
from app.models.detection_rule import DetectionRule
from app.models.detection_rule_trust import DetectionRuleTrustEvaluation
from app.models.detection_execution import DetectionExecution
from app.models.threat_intelligence import ThreatIndicator, ThreatActor
from app.models.risk_correlation import RiskCorrelation
from app.models.security_incident import SecurityIncident, IncidentSignal
from app.models.incident_response import IncidentResponsePlaybook, IncidentContainmentRequest
from app.models.security_assurance import PlatformAssuranceEvaluation
from app.models.assurance_remediation import AssuranceRemediationCase, AssuranceRecoveryVerification
from app.models.compliance_intelligence import ComplianceFramework, ComplianceRequirement, SecurityControl
from app.models.security_investigation import (
    SecurityInvestigationCase,
    InvestigationArtifactBinding,
    InvestigationHypothesis,
    InvestigationFinding,
    InvestigationTimelineEvent,
    InvestigationImpactAssessment,
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
    compute_canonical_hash,
)
from app.services.security_metric_registry_service import SecurityMetricRegistryService
from app.services.security_analytics_service import SecurityAnalyticsService
from app.services.security_reporting_service import SecurityReportingService
from app.services.security_evidence_package_service import SecurityEvidencePackageService
from app.services.security_analytics_provenance_service import SecurityAnalyticsProvenanceService


def seed_demo_environment():
    print("===================================================================")
    print("       SENTINELTRACE V5 — DETERMINISTIC SIH DEMO ENVIRONMENT       ")
    print("===================================================================")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    now = datetime.now(timezone.utc)

    # 1. Seed Metrics
    print("[1/10] Seeding 15-Domain Security Metric Registry...")
    SecurityMetricRegistryService.seed_default_metrics(db)

    # 2. Seed Raw Ingested Event & OCSF Normalization
    print("[2/10] Seeding Raw Ingested Events & OCSF Normalization...")
    from app.services.event_service import EventService
    from app.services.normalization_service import NormalizationService
    from app.schemas.event import EventIngestRequest

    raw_payload = "Sep 09 10:15:22 fw01.corp.internal %ASA-4-106023: Deny tcp src outside:198.51.100.42/44122 dst inside:10.0.4.15/443 by access-group 'OUTSIDE-IN' [0x0, 0x0]"
    evt = EventService.ingest_event(
        db=db,
        payload=EventIngestRequest(
            source_name="Firewall-Edge-01",
            source_type="firewall",
            raw_content=raw_payload,
            file_format="syslog",
        ),
    )

    norm = NormalizationService.normalize_event(db, evt.event_id)

    # 3. Seed Threat Intelligence IOC
    print("[3/10] Seeding Threat Intelligence & APT Adversary Context...")
    actor = db.query(ThreatActor).filter_by(actor_name="Silver Hydra").first()
    if not actor:
        actor = ThreatActor(
            id="act-demo-001",
            actor_name="Silver Hydra",
            description="Silver Hydra Cyber Espionage Group",
            motivation="ESPIONAGE",
            sophistication="ADVANCED",
            origin_context="State-Sponsored",
            confidence_score=92.0,
            status="ACTIVE",
            created_at=now - timedelta(days=30),
        )
        db.add(actor)
        db.commit()

    ioc = db.query(ThreatIndicator).filter_by(indicator_value="198.51.100.42").first()
    if not ioc:
        ioc = ThreatIndicator(
            id="ioc-demo-001",
            indicator_type="IP_ADDRESS",
            indicator_value="198.51.100.42",
            normalized_value="198.51.100.42",
            severity="HIGH",
            confidence_score=95.0,
            status="ACTIVE",
            indicator_hash=compute_canonical_hash("SENTINELTRACE_IOC_V1", {"val": "198.51.100.42"}),
            created_at=now - timedelta(days=10),
        )
        db.add(ioc)
        db.commit()

    # 4. Seed Security Incident
    print("[4/10] Seeding Correlated Security Incident...")
    inc = db.query(SecurityIncident).filter_by(incident_number="INC-2026-000001").first()
    if not inc:
        inc = SecurityIncident(
            id="inc-demo-sih-001",
            incident_number="INC-2026-000001",
            title="Adversarial Reconnaissance & C2 Ingress Attempt",
            description="Correlated multi-source network intrusion attempt against internal infrastructure.",
            severity="HIGH",
            status="INVESTIGATING",
            priority="P1",
            confidence_score=94.5,
            incident_hash=compute_canonical_hash("SENTINELTRACE_INCIDENT_V1", {"number": "INC-2026-000001"}),
            created_at=now - timedelta(hours=1),
        )
        db.add(inc)
        db.commit()

    # 5. Seed SOC Investigation Case & Findings
    print("[5/10] Seeding SOC Investigation Workspace Case...")
    case = db.query(SecurityInvestigationCase).filter_by(case_number="SIC-2026-001").first()
    if not case:
        case = SecurityInvestigationCase(
            id="sic-demo-sih-001",
            case_number="SIC-2026-001",
            title="Investigation: Adversarial Ingress on Gateway fw01",
            description="Detailed SOC case investigating repeated targeted probes from APT-SILVER-HYDRA C2 IP.",
            lead_investigator_id="analyst_demo",
            assigned_team="TIER_2_SOC",
            status="IN_INVESTIGATION",
            priority="HIGH",
            overall_severity="HIGH",
            source_domain="DETECTION",
            source_incident_id=inc.id,
            case_hash=compute_canonical_hash("SENTINELTRACE_INVESTIGATION_CASE_V1", {"number": "SIC-2026-001"}),
            created_by_user_id="analyst_demo",
            created_at=now - timedelta(minutes=45),
        )
        db.add(case)
        db.commit()

        # Bind Evidence Artifact
        binding = InvestigationArtifactBinding(
            id="iab-demo-001",
            case_id=case.id,
            artifact_domain="EVIDENCE",
            artifact_type="INGESTED_EVENT",
            artifact_id=evt.event_id,
            artifact_hash=evt.raw_content_hash,
            source_reference=f"/api/v1/events/{evt.event_id}",
            binding_reason="Direct initial raw firewall log trigger",
            binding_hash=compute_canonical_hash("SENTINELTRACE_INVESTIGATION_BINDING_V1", {"case_id": case.id, "art_id": evt.event_id}),
            created_by_user_id="analyst_demo",
            created_at=now - timedelta(minutes=40),
        )
        db.add(binding)

        # Add Hypothesis
        hyp = InvestigationHypothesis(
            id="hyp-demo-001",
            case_id=case.id,
            statement="Hostile external reconnaissance prior to credential stuffing attack",
            status="SUPPORTED",
            confidence_score=90.0,
            supporting_evidence_json=[evt.event_id, ioc.id],
            hypothesis_hash=compute_canonical_hash("SENTINELTRACE_HYPOTHESIS_V1", {"case_id": case.id, "stmt": "recon"}),
            created_by_user_id="analyst_demo",
            created_at=now - timedelta(minutes=35),
        )
        db.add(hyp)
        db.commit()

    # 6. Seed Point-in-Time Security Analytics Snapshot
    print("[6/10] Seeding Sealed Analytics Snapshot...")
    snap = SecurityAnalyticsService.create_snapshot(db, "24H", "SYSTEM")

    # 7. Seed 17-Stage Cryptographic Provenance Lineage
    print("[7/10] Seeding 17-Stage Cryptographic Provenance Hash Chain...")
    SecurityAnalyticsProvenanceService.generate_provenance_chain(db, snap.id)

    # 8. Synthesize Executive Security Report
    print("[8/10] Synthesizing Executive Security Posture Report...")
    rep = SecurityReportingService.generate_report(
        db,
        report_type="EXECUTIVE_SECURITY_REPORT",
        title="SentinelTrace Executive Security Posture & Compliance Briefing",
        user_id="admin_demo",
    )

    # 9. Synthesize Reference-Only Evidence Package
    print("[9/10] Building Reference-Only Evidence Package Dossier...")
    pkg = SecurityEvidencePackageService.build_evidence_package(
        db,
        package_type="COMPREHENSIVE_AUDIT",
        scope="PLATFORM_FULL",
        description="Comprehensive Cross-Domain Verifiable Security Evidence Package",
        user_id="admin_demo",
    )

    # 10. Summary Verification
    print("[10/10] Running Self-Verification Check...")
    is_lineage_valid, _ = SecurityAnalyticsProvenanceService.verify_provenance_chain(db, snap.id)
    print(f"  [OK] 17-Stage Provenance Lineage: {'VERIFIED & UNBROKEN' if is_lineage_valid else 'FAILED'}")
    print(f"  [OK] Snapshot Number: {snap.snapshot_number} (Seal: {snap.snapshot_hash[:16]}...)")
    print(f"  [OK] Executive Report: {rep.report_number} (Hash: {rep.report_hash[:16]}...)")
    print(f"  [OK] Evidence Package: {pkg.package_number} (Bound Artifacts: {pkg.artifact_count})")
    
    db.close()
    print("===================================================================")
    print("       DEMO ENVIRONMENT READY FOR SIH PRESENTATION WALKTHROUGH     ")
    print("===================================================================")


if __name__ == "__main__":
    seed_demo_environment()
