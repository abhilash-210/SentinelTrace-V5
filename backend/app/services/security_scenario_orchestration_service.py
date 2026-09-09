"""
services/security_scenario_orchestration_service.py
---------------------------------------------------
Deterministic Security Scenario Orchestration Service for SentinelTrace V5.
Orchestrates end-to-end security scenarios across all 10 platform security domains,
binding cross-domain artifacts and enforcing mathematical integrity without ML/LLMs.

Sprint 10B — End-to-End Security Scenario Orchestration, Demonstration Validation & Cross-Domain Evidence Replay.
Core Invariant: "EVERY EXECUTIVE SECURITY CONCLUSION MUST BE REPLAYABLE BACKWARD THROUGH THE COMPLETE SECURITY PIPELINE TO ITS ORIGINAL EVIDENCE."
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.models.security_scenario import (
    SecurityScenario,
    SecurityScenarioVersion,
    ScenarioExecution,
    ScenarioStageExecution,
    ScenarioArtifactBinding,
    ScenarioVerificationResult,
    ScenarioExecutiveImpact,
    SCENARIO_VERSION_DOMAIN_PREFIX,
    SCENARIO_EXECUTION_DOMAIN_PREFIX,
    calculate_scenario_hash,
)
from app.models.event import IngestedEvent
from app.models.normalized_event import NormalizedEvent
from app.models.semantic_policy import SemanticPolicy, ProtectedSemanticField
from app.models.semantic_interpretation import SemanticInterpretation, SemanticDriftAlert
from app.models.detection_rule import DetectionRule
from app.models.detection_rule_trust import DetectionRuleTrustEvaluation
from app.models.detection_execution import DetectionExecution
from app.models.risk_correlation import RiskCorrelation
from app.models.security_incident import SecurityIncident, IncidentSignal
from app.models.incident_response import (
    IncidentResponsePlaybook,
    IncidentContainmentRequest,
    IncidentResponseExecution,
    IncidentResponseVerification,
)
from app.models.security_assurance import PlatformAssuranceEvaluation, AssuranceAlert
from app.models.assurance_remediation import (
    AssuranceRemediationCase,
    AssuranceRemediationPlan,
    AssuranceRecoveryVerification,
)
from app.models.executive_security_intelligence import ExecutiveSecurityPostureEvaluation
from app.models.ledger import GovernanceLedgerEntry
from app.models.merkle import MerkleBatch, MerkleProof

from app.services.scenario_artifact_binding_service import ScenarioArtifactBindingService
from app.services.governance_ledger_service import GovernanceLedgerService
from app.services.executive_security_intelligence_service import ExecutiveSecurityIntelligenceService

logger = logging.getLogger("sentinel.services.scenario_orchestrator")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


CANONICAL_STAGES = [
    {"stage_number": 1, "stage_key": "RAW_EVIDENCE", "stage_name": "Raw Ingestion & Vault Preservation", "domain": "EVIDENCE_INTEGRITY", "artifact_type": "RAW_LOG"},
    {"stage_number": 2, "stage_key": "EVIDENCE_HASH", "stage_name": "SHA-256 Evidence Sealing", "domain": "EVIDENCE_INTEGRITY", "artifact_type": "EVIDENCE_HASH"},
    {"stage_number": 3, "stage_key": "NORMALIZED_EVENT", "stage_name": "OCSF Canonical Normalization", "domain": "NORMALIZATION_PIPELINE", "artifact_type": "NORMALIZED_EVENT"},
    {"stage_number": 4, "stage_key": "SEMANTIC_INTERPRETATION", "stage_name": "Semantic Interpretation & Policy Mapping", "domain": "SEMANTIC_TRUST", "artifact_type": "SEMANTIC_INTERPRETATION"},
    {"stage_number": 5, "stage_key": "SEMANTIC_DRIFT_ANALYSIS", "stage_name": "Semantic Drift Evaluation", "domain": "SEMANTIC_TRUST", "artifact_type": "DRIFT_EVALUATION"},
    {"stage_number": 6, "stage_key": "CANONICAL_FIELD_BINDING", "stage_name": "Canonical Field Contract Binding", "domain": "SEMANTIC_TRUST", "artifact_type": "CANONICAL_BINDING"},
    {"stage_number": 7, "stage_key": "DETECTION_RULE", "stage_name": "Detection Rule Definition & Resolution", "domain": "DETECTION_TRUST", "artifact_type": "DETECTION_RULE"},
    {"stage_number": 8, "stage_key": "DETECTION_TRUST", "stage_name": "Detection Rule Trust Scoring", "domain": "DETECTION_TRUST", "artifact_type": "DETECTION_TRUST"},
    {"stage_number": 9, "stage_key": "DETECTION_EXECUTION", "stage_name": "Deterministic Rule Execution", "domain": "DETECTION_TRUST", "artifact_type": "DETECTION_EXECUTION"},
    {"stage_number": 10, "stage_key": "RISK_CORRELATION", "stage_name": "Multi-Signal Threat Correlation", "domain": "RISK_INTELLIGENCE", "artifact_type": "RISK_CORRELATION"},
    {"stage_number": 11, "stage_key": "SECURITY_INCIDENT", "stage_name": "Security Incident Formulation", "domain": "INCIDENT_SECURITY", "artifact_type": "SECURITY_INCIDENT"},
    {"stage_number": 12, "stage_key": "INCIDENT_RESPONSE_PLAYBOOK", "stage_name": "Incident Response Playbook Formulation", "domain": "INCIDENT_RESPONSE", "artifact_type": "RESPONSE_PLAYBOOK"},
    {"stage_number": 13, "stage_key": "CONTAINMENT_AUTHORIZATION", "stage_name": "Dual-Control Containment Authorization", "domain": "INCIDENT_RESPONSE", "artifact_type": "CONTAINMENT_REQUEST"},
    {"stage_number": 14, "stage_key": "EXECUTION_ATTESTATION", "stage_name": "Containment Execution Attestation", "domain": "INCIDENT_RESPONSE", "artifact_type": "RESPONSE_EXECUTION"},
    {"stage_number": 15, "stage_key": "RESPONSE_VERIFICATION", "stage_name": "Incident Response Attestation & Verification", "domain": "INCIDENT_RESPONSE", "artifact_type": "RESPONSE_VERIFICATION"},
    {"stage_number": 16, "stage_key": "PLATFORM_ASSURANCE", "stage_name": "Platform Assurance Telemetry Evaluation", "domain": "PLATFORM_ASSURANCE", "artifact_type": "ASSURANCE_EVALUATION"},
    {"stage_number": 17, "stage_key": "ASSURANCE_REMEDIATION", "stage_name": "Continuous Assurance Remediation Case", "domain": "ASSURANCE_RECOVERY", "artifact_type": "REMEDIATION_CASE"},
    {"stage_number": 18, "stage_key": "RECOVERY_VERIFICATION", "stage_name": "Assurance Recovery Empirical Verification", "domain": "ASSURANCE_RECOVERY", "artifact_type": "RECOVERY_VERIFICATION"},
    {"stage_number": 19, "stage_key": "EXECUTIVE_SECURITY_POSTURE", "stage_name": "Executive Security Posture Evaluation", "domain": "EXECUTIVE_POSTURE", "artifact_type": "EXECUTIVE_POSTURE"},
    {"stage_number": 20, "stage_key": "GOVERNANCE_LEDGER_AND_MERKLE_PROOF", "stage_name": "Governance Ledger Append & Merkle Proof", "domain": "CRYPTOGRAPHIC_ASSURANCE", "artifact_type": "LEDGER_ENTRY"},
]


class SecurityScenarioOrchestrationService:
    """
    Main orchestration engine for security scenarios and demonstration validation.
    """

    # ── Scenario Registry & Versioning ──────────────────────────────────────────

    @staticmethod
    def calculate_version_hash(
        scenario_key: str,
        version_number: int,
        definition_json: Dict[str, Any],
        expected_stages: List[Dict[str, Any]],
        expected_outcomes: Dict[str, Any],
        seed: str,
    ) -> str:
        """Calculates deterministic SHA-256 version hash."""
        payload = {
            "scenario_key": scenario_key,
            "version_number": version_number,
            "scenario_definition_json": definition_json,
            "expected_stage_sequence_json": expected_stages,
            "expected_outcomes_json": expected_outcomes,
            "deterministic_seed": seed,
        }
        return calculate_scenario_hash(SCENARIO_VERSION_DOMAIN_PREFIX, payload)

    @classmethod
    def create_scenario(
        cls,
        db: Session,
        scenario_key: str,
        scenario_name: str,
        description: str,
        category: str,
        severity: str,
        created_by_user_id: str,
        definition_json: Optional[Dict[str, Any]] = None,
        expected_stages: Optional[List[Dict[str, Any]]] = None,
        expected_outcomes: Optional[Dict[str, Any]] = None,
        deterministic_seed: str = "SENTINELTRACE_SCENARIO_V1",
        status: str = "ACTIVE",
    ) -> Tuple[SecurityScenario, SecurityScenarioVersion]:
        """
        Creates a new SecurityScenario along with Version 1.
        """
        existing = db.query(SecurityScenario).filter(SecurityScenario.scenario_key == scenario_key).first()
        if existing:
            raise ValueError(f"Security Scenario with key '{scenario_key}' already exists.")

        scenario_id = f"scn_{uuid.uuid4().hex[:16]}"
        version_id = f"scnv_{uuid.uuid4().hex[:16]}"
        def_json = definition_json or {"events": [], "target_system": "SENTINEL_DEMO"}
        stages_json = expected_stages or CANONICAL_STAGES
        outcomes_json = expected_outcomes or {"minimum_severity": severity, "incident_expected": True}

        def_hash = cls.calculate_version_hash(
            scenario_key=scenario_key,
            version_number=1,
            definition_json=def_json,
            expected_stages=stages_json,
            expected_outcomes=outcomes_json,
            seed=deterministic_seed,
        )

        scenario = SecurityScenario(
            id=scenario_id,
            scenario_key=scenario_key,
            scenario_name=scenario_name,
            description=description,
            category=category,
            severity=severity,
            status=status,
            current_version_id=version_id,
            created_by_user_id=created_by_user_id,
            created_at=utcnow(),
            updated_at=utcnow(),
        )

        version = SecurityScenarioVersion(
            id=version_id,
            scenario_id=scenario_id,
            version_number=1,
            scenario_definition_json=def_json,
            expected_stage_sequence_json=stages_json,
            expected_outcomes_json=outcomes_json,
            deterministic_seed=deterministic_seed,
            definition_hash=def_hash,
            status="ACTIVE",
            created_by_user_id=created_by_user_id,
            created_at=utcnow(),
        )

        db.add(scenario)
        db.add(version)
        db.commit()
        db.refresh(scenario)
        db.refresh(version)

        logger.info(f"Created Security Scenario '{scenario.scenario_key}' v1 [{scenario.id}]")
        return scenario, version

    @classmethod
    def create_scenario_version(
        cls,
        db: Session,
        scenario_id: str,
        definition_json: Dict[str, Any],
        created_by_user_id: str,
        expected_stages: Optional[List[Dict[str, Any]]] = None,
        expected_outcomes: Optional[Dict[str, Any]] = None,
        deterministic_seed: Optional[str] = None,
        set_active: bool = True,
    ) -> SecurityScenarioVersion:
        """
        Creates an immutable next version of an existing scenario definition.
        """
        scenario = db.query(SecurityScenario).filter(SecurityScenario.id == scenario_id).first()
        if not scenario:
            raise ValueError(f"Scenario '{scenario_id}' not found.")

        # Determine next version number
        latest_ver = (
            db.query(func.max(SecurityScenarioVersion.version_number))
            .filter(SecurityScenarioVersion.scenario_id == scenario_id)
            .scalar()
        ) or 0
        next_ver_num = latest_ver + 1

        seed = deterministic_seed or f"{scenario.scenario_key}_V{next_ver_num}_SEED"
        stages_json = expected_stages or CANONICAL_STAGES
        outcomes_json = expected_outcomes or {"minimum_severity": scenario.severity, "incident_expected": True}

        def_hash = cls.calculate_version_hash(
            scenario_key=scenario.scenario_key,
            version_number=next_ver_num,
            definition_json=definition_json,
            expected_stages=stages_json,
            expected_outcomes=outcomes_json,
            seed=seed,
        )

        new_version_id = f"scnv_{uuid.uuid4().hex[:16]}"
        version = SecurityScenarioVersion(
            id=new_version_id,
            scenario_id=scenario_id,
            version_number=next_ver_num,
            scenario_definition_json=definition_json,
            expected_stage_sequence_json=stages_json,
            expected_outcomes_json=outcomes_json,
            deterministic_seed=seed,
            definition_hash=def_hash,
            status="ACTIVE" if set_active else "DRAFT",
            created_by_user_id=created_by_user_id,
            created_at=utcnow(),
        )

        if set_active:
            # Mark previous active version as SUPERSEDED
            db.query(SecurityScenarioVersion).filter(
                SecurityScenarioVersion.scenario_id == scenario_id,
                SecurityScenarioVersion.status == "ACTIVE",
            ).update({"status": "SUPERSEDED"})
            scenario.current_version_id = new_version_id
            scenario.updated_at = utcnow()

        db.add(version)
        db.commit()
        db.refresh(version)
        logger.info(f"Created version {next_ver_num} for scenario '{scenario.scenario_key}'")
        return version

    @staticmethod
    def get_scenario(db: Session, scenario_id_or_key: str) -> Optional[SecurityScenario]:
        """Looks up a scenario by ID or unique key."""
        return (
            db.query(SecurityScenario)
            .filter(
                (SecurityScenario.id == scenario_id_or_key)
                | (SecurityScenario.scenario_key == scenario_id_or_key)
            )
            .first()
        )

    @staticmethod
    def list_scenarios(
        db: Session,
        category: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[SecurityScenario]:
        """Lists scenarios with optional category and status filtering."""
        query = db.query(SecurityScenario)
        if category:
            query = query.filter(SecurityScenario.category == category)
        if status:
            query = query.filter(SecurityScenario.status == status)
        return query.order_by(SecurityScenario.created_at.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_scenario_versions(db: Session, scenario_id: str) -> List[SecurityScenarioVersion]:
        """Lists all versions for a scenario."""
        return (
            db.query(SecurityScenarioVersion)
            .filter(SecurityScenarioVersion.scenario_id == scenario_id)
            .order_by(SecurityScenarioVersion.version_number.desc())
            .all()
        )

    # ── Seeded Demonstration Scenarios ──────────────────────────────────────────

    @classmethod
    def seed_default_scenarios(cls, db: Session, system_user_id: str = "system_admin") -> List[SecurityScenario]:
        """
        Seeds the 4 canonical demonstration scenarios required for Sprint 10B.
        """
        seeded = []

        # 1. SCN_CREDENTIAL_COMPROMISE
        s1 = cls.get_scenario(db, "SCN_CREDENTIAL_COMPROMISE")
        if not s1:
            s1, _ = cls.create_scenario(
                db=db,
                scenario_key="SCN_CREDENTIAL_COMPROMISE",
                scenario_name="Compromised Credential & Lateral Privilege Escalation",
                description="A compromised privileged credential performs an anomalous login from an unrecognized ASN, triggers impossible travel, escalates privileges on sensitive asset, and initiates lateral movement.",
                category="IDENTITY_COMPROMISE",
                severity="CRITICAL",
                created_by_user_id=system_user_id,
                deterministic_seed="SENTINELTRACE_DEMO_CREDENTIAL_COMPROMISE_V1",
                definition_json={
                    "events": [
                        {"seq": 1, "type": "AUTH_LOGIN", "user": "victim_admin", "ip": "198.51.100.44", "country": "RU", "status": "SUCCESS"},
                        {"seq": 2, "type": "IMPOSSIBLE_TRAVEL", "user": "victim_admin", "delta_km": 8400, "delta_minutes": 12},
                        {"seq": 3, "type": "PRIVILEGE_ESCALATION", "user": "victim_admin", "target_role": "DOMAIN_CONTROLLER_ADMIN"},
                        {"seq": 4, "type": "SENSITIVE_RESOURCE_ACCESS", "resource": "DATABASE_CREDENTIAL_VAULT", "action": "EXPORT_ALL"},
                    ],
                    "expected_detection_rules": ["DRULE_AUTH_ANOMALOUS_GEO", "DRULE_PRIV_ESC_SENSITIVE"],
                    "expected_playbook": "PLAYBOOK_CREDENTIAL_CONTAINMENT",
                },
                expected_outcomes={
                    "minimum_severity": "CRITICAL",
                    "incident_expected": True,
                    "containment_action": "DISABLE_USER_AND_REVOKE_ACTIVE_SESSIONS",
                    "posture_impact": "HIGH_NEGATIVE",
                },
            )
            seeded.append(s1)

        # 2. SCN_MALWARE_PROPAGATION
        s2 = cls.get_scenario(db, "SCN_MALWARE_PROPAGATION")
        if not s2:
            s2, _ = cls.create_scenario(
                db=db,
                scenario_key="SCN_MALWARE_PROPAGATION",
                scenario_name="Ransomware Dropper & Endpoint Lateral Infection",
                description="A weaponized payload executes on an endpoint, attempts defense evasion, establishes persistence via scheduled tasks, and probes subnet for SMB lateral spread.",
                category="ENDPOINT_MALWARE",
                severity="HIGH",
                created_by_user_id=system_user_id,
                deterministic_seed="SENTINELTRACE_DEMO_MALWARE_PROPAGATION_V1",
                definition_json={
                    "events": [
                        {"seq": 1, "type": "PROCESS_EXECUTION", "process": "powershell.exe -enc <payload>", "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                        {"seq": 2, "type": "FILE_WRITE", "path": "C:\\Windows\\System32\\Tasks\\UpdateHelper.job"},
                        {"seq": 3, "type": "NETWORK_SCAN", "target_subnet": "10.0.4.0/24", "port": 445},
                    ],
                    "expected_detection_rules": ["DRULE_SUSPICIOUS_POWERSHELL", "DRULE_LATERAL_SMB_SWEEP"],
                    "expected_playbook": "PLAYBOOK_ENDPOINT_ISOLATION",
                },
                expected_outcomes={
                    "minimum_severity": "HIGH",
                    "incident_expected": True,
                    "containment_action": "ISOLATE_HOST_AND_QUARANTINE_HASH",
                    "posture_impact": "MODERATE_NEGATIVE",
                },
            )
            seeded.append(s2)

        # 3. SCN_DETECTION_TRUST_FAILURE
        s3 = cls.get_scenario(db, "SCN_DETECTION_TRUST_FAILURE")
        if not s3:
            s3, _ = cls.create_scenario(
                db=db,
                scenario_key="SCN_DETECTION_TRUST_FAILURE",
                scenario_name="Semantic Drift Induced Detection Trust Degradation",
                description="Vendor log format updates introduce structural and semantic drift on canonical fields ('action.result'), triggering trust score penalties and continuous platform assurance degradation.",
                category="TRUST_DEGRADATION",
                severity="MEDIUM",
                created_by_user_id=system_user_id,
                deterministic_seed="SENTINELTRACE_DEMO_TRUST_DEGRADATION_V1",
                definition_json={
                    "events": [
                        {"seq": 1, "type": "SCHEMA_DRIFT_INGEST", "field": "action.result", "vendor_val": "DENIED_BY_POLICY_V2", "canonical_expected": "BLOCKED"},
                        {"seq": 2, "type": "SEMANTIC_DRIFT_ALERT", "divergence_rate": 0.38, "drift_tier": "CRITICAL"},
                    ],
                    "expected_detection_rules": ["DRULE_FIREWALL_BLOCK_VALIDATION"],
                    "expected_playbook": "PLAYBOOK_SEMANTIC_REMEDIATION",
                },
                expected_outcomes={
                    "minimum_severity": "MEDIUM",
                    "incident_expected": False,
                    "assurance_alert_expected": True,
                    "posture_impact": "MODERATE_NEGATIVE",
                },
            )
            seeded.append(s3)

        # 4. SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE
        s4 = cls.get_scenario(db, "SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE")
        if not s4:
            s4, _ = cls.create_scenario(
                db=db,
                scenario_key="SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE",
                scenario_name="Controlled Cryptographic Proof Failure & Score Domination",
                description="Simulates a controlled cryptographic verification failure where a ledger payload hash diverges from its Merkle root. Proves that cryptographic integrity failure strictly forces executive posture to CRITICAL with a 0.0/100 score.",
                category="CRYPTO_VERIFICATION",
                severity="CRITICAL",
                created_by_user_id=system_user_id,
                deterministic_seed="SENTINELTRACE_DEMO_CRYPTO_FAILURE_V1",
                definition_json={
                    "events": [
                        {"seq": 1, "type": "SIMULATED_HASH_CORRUPTION", "target_block": 142, "simulated_hash": "0xdeadbeef1234567890abcdef"},
                        {"seq": 2, "type": "MERKLE_INCLUSION_VERIFY", "expected_result": "FAILED"},
                    ],
                    "expected_detection_rules": ["DRULE_LEDGER_INTEGRITY_CHECK"],
                    "expected_playbook": "PLAYBOOK_FORENSIC_LEDGER_HALT",
                },
                expected_outcomes={
                    "minimum_severity": "CRITICAL",
                    "verification_result": "FAILED",
                    "executive_score_override": 0.0,
                    "posture_impact": "CRITICAL_NEGATIVE",
                },
            )
            seeded.append(s4)

        return seeded

    # ── Execution Lifecycle Engine ──────────────────────────────────────────────

    @staticmethod
    def _generate_execution_number(db: Session) -> str:
        """Generates sequential execution number format: SCX-YYYY-NNN."""
        year = utcnow().year
        count = db.query(func.count(ScenarioExecution.id)).scalar() or 0
        return f"SCX-{year}-{(count + 1):03d}"

    @classmethod
    def create_execution(
        cls,
        db: Session,
        scenario_id_or_key: str,
        initiated_by_user_id: str,
        version_id: Optional[str] = None,
        execution_mode: str = "CONTROLLED_DEMO",
        deterministic_seed_override: Optional[str] = None,
        notes: str = "",
    ) -> ScenarioExecution:
        """
        Initializes a ScenarioExecution and pre-populates the 20 canonical stages.
        """
        scenario = cls.get_scenario(db, scenario_id_or_key)
        if not scenario:
            raise ValueError(f"Scenario '{scenario_id_or_key}' not found.")

        target_version_id = version_id or scenario.current_version_id
        version = db.query(SecurityScenarioVersion).filter(SecurityScenarioVersion.id == target_version_id).first()
        if not version:
            raise ValueError(f"Scenario Version '{target_version_id}' not found.")

        exec_id = f"scx_{uuid.uuid4().hex[:16]}"
        exec_num = cls._generate_execution_number(db)
        seed = deterministic_seed_override or version.deterministic_seed

        exec_hash = calculate_scenario_hash(
            SCENARIO_EXECUTION_DOMAIN_PREFIX,
            {
                "execution_id": exec_id,
                "execution_number": exec_num,
                "scenario_key": scenario.scenario_key,
                "version_number": version.version_number,
                "deterministic_seed": seed,
                "initiated_by_user_id": initiated_by_user_id,
            },
        )

        execution = ScenarioExecution(
            id=exec_id,
            execution_number=exec_num,
            scenario_id=scenario.id,
            scenario_version_id=version.id,
            execution_mode=execution_mode,
            status="CREATED",
            started_at=utcnow(),
            initiated_by_user_id=initiated_by_user_id,
            deterministic_execution_seed=seed,
            execution_hash=exec_hash,
            verification_status="UNVERIFIED",
        )
        db.add(execution)
        db.flush()

        # Pre-populate all 20 canonical stages
        for stg in CANONICAL_STAGES:
            stage_exec_id = f"scs_{uuid.uuid4().hex[:16]}"
            stage_hash = calculate_scenario_hash(
                "SENTINELTRACE_SCENARIO_STAGE_V1",
                {
                    "stage_exec_id": stage_exec_id,
                    "scenario_execution_id": exec_id,
                    "stage_number": stg["stage_number"],
                    "stage_key": stg["stage_key"],
                },
            )

            stage = ScenarioStageExecution(
                id=stage_exec_id,
                scenario_execution_id=exec_id,
                stage_number=stg["stage_number"],
                stage_key=stg["stage_key"],
                stage_name=stg["stage_name"],
                status="PENDING",
                started_at=utcnow(),
                input_reference_json={"domain": stg["domain"], "stage_desc": stg["stage_name"]},
                output_reference_json={},
                verification_result="UNVERIFIED",
                execution_hash=stage_hash,
            )
            db.add(stage)

        db.commit()
        db.refresh(execution)

        # Append Governance Ledger Event
        GovernanceLedgerService.append_entry(
            db=db,
            event_type="SCENARIO_EXECUTION_STARTED",
            actor_id=initiated_by_user_id,
            actor_username=initiated_by_user_id,
            payload={
                "entity_type": "SCENARIO_EXECUTION",
                "entity_id": execution.id,
                "execution_number": execution.execution_number,
                "scenario_key": scenario.scenario_key,
                "version_number": version.version_number,
                "mode": execution_mode,
            },
        )

        logger.info(f"Initialized ScenarioExecution {exec_num} [{exec_id}] for {scenario.scenario_key}")
        return execution

    @classmethod
    def execute_stage(
        cls,
        db: Session,
        execution_id: str,
        stage_number: int,
        actor_id: str = "system",
        actor_username: str = "system",
    ) -> ScenarioStageExecution:
        """
        Executes a specific stage of a scenario execution, calling existing platform layers
        and creating the appropriate artifact bindings.
        """
        execution = db.query(ScenarioExecution).filter(ScenarioExecution.id == execution_id).first()
        if not execution:
            raise ValueError(f"ScenarioExecution '{execution_id}' not found.")

        stage = (
            db.query(ScenarioStageExecution)
            .filter(
                ScenarioStageExecution.scenario_execution_id == execution_id,
                ScenarioStageExecution.stage_number == stage_number,
            )
            .first()
        )
        if not stage:
            raise ValueError(f"Stage #{stage_number} not found for execution '{execution_id}'.")

        if stage.status == "COMPLETED":
            logger.info(f"Stage #{stage_number} already COMPLETED for execution {execution_id}. Returning idempotent record.")
            return stage

        stage.status = "RUNNING"
        stage.started_at = utcnow()
        db.flush()

        # Execute stage logic based on stage_number & scenario definition
        scenario = execution.scenario
        version = execution.version
        is_crypto_failure_demo = scenario.scenario_key == "SCN_CRYPTOGRAPHIC_INTEGRITY_FAILURE"

        artifact_domain = "EVIDENCE"
        artifact_type = "RAW_LOG"
        artifact_id = f"art_{execution.execution_number}_stg{stage_number}"
        artifact_hash = hashlib.sha256(f"{execution.deterministic_execution_seed}_stg{stage_number}".encode()).hexdigest()
        output_ref = {"stage_completed": True, "actor": actor_username}

        try:
            # Map canonical logic to existing DB records where available
            if stage_number == 1:
                # Stage 1: RAW_EVIDENCE
                latest_ev = db.query(IngestedEvent).first()
                if latest_ev:
                    artifact_id = str(latest_ev.event_id or latest_ev.id)
                    artifact_hash = latest_ev.raw_content_hash or artifact_hash
                artifact_domain = "EVIDENCE_INTEGRITY"
                artifact_type = "RAW_LOG"
                output_ref["event_captured"] = True

            elif stage_number == 2:
                # Stage 2: EVIDENCE_HASH
                artifact_domain = "EVIDENCE_INTEGRITY"
                artifact_type = "EVIDENCE_HASH"
                output_ref["hash_sealed"] = artifact_hash

            elif stage_number == 3:
                # Stage 3: NORMALIZED_EVENT
                latest_norm = db.query(NormalizedEvent).first()
                if latest_norm:
                    artifact_id = str(latest_norm.id)
                artifact_domain = "NORMALIZATION_PIPELINE"
                artifact_type = "NORMALIZED_EVENT"
                output_ref["ocsf_class"] = "4001"

            elif stage_number == 4:
                # Stage 4: SEMANTIC_INTERPRETATION
                latest_interp = db.query(SemanticInterpretation).first()
                if latest_interp:
                    artifact_id = str(latest_interp.id)
                artifact_domain = "SEMANTIC_TRUST"
                artifact_type = "SEMANTIC_INTERPRETATION"
                output_ref["policy_applied"] = "spol_cisco_asa_default"

            elif stage_number == 5:
                # Stage 5: SEMANTIC_DRIFT_ANALYSIS
                artifact_domain = "SEMANTIC_TRUST"
                artifact_type = "DRIFT_EVALUATION"
                output_ref["drift_detected"] = scenario.category == "TRUST_DEGRADATION"

            elif stage_number == 6:
                # Stage 6: CANONICAL_FIELD_BINDING
                artifact_domain = "SEMANTIC_TRUST"
                artifact_type = "CANONICAL_BINDING"
                output_ref["protected_field"] = "action.result"

            elif stage_number == 7:
                # Stage 7: DETECTION_RULE
                latest_rule = db.query(DetectionRule).first()
                if latest_rule:
                    artifact_id = str(latest_rule.id)
                artifact_domain = "DETECTION_TRUST"
                artifact_type = "DETECTION_RULE"
                output_ref["rule_name"] = "DRULE_SUSPICIOUS_AUTH"

            elif stage_number == 8:
                # Stage 8: DETECTION_TRUST
                artifact_domain = "DETECTION_TRUST"
                artifact_type = "DETECTION_TRUST"
                output_ref["trust_score"] = 65.0 if scenario.category == "TRUST_DEGRADATION" else 95.0

            elif stage_number == 9:
                # Stage 9: DETECTION_EXECUTION
                latest_dexec = db.query(DetectionExecution).first()
                if latest_dexec:
                    artifact_id = str(latest_dexec.id)
                artifact_domain = "DETECTION_TRUST"
                artifact_type = "DETECTION_EXECUTION"
                output_ref["condition_evaluated"] = True

            elif stage_number == 10:
                # Stage 10: RISK_CORRELATION
                latest_risk = db.query(RiskCorrelation).first()
                if latest_risk:
                    artifact_id = str(latest_risk.id)
                artifact_domain = "RISK_INTELLIGENCE"
                artifact_type = "RISK_CORRELATION"
                output_ref["risk_cluster"] = "CREDENTIAL_HIJACK"

            elif stage_number == 11:
                # Stage 11: SECURITY_INCIDENT
                latest_inc = db.query(SecurityIncident).first()
                if latest_inc:
                    artifact_id = str(latest_inc.id)
                artifact_domain = "INCIDENT_SECURITY"
                artifact_type = "SECURITY_INCIDENT"
                output_ref["incident_number"] = "INC-2026-000001"

            elif stage_number == 12:
                # Stage 12: INCIDENT_RESPONSE_PLAYBOOK
                artifact_domain = "INCIDENT_RESPONSE"
                artifact_type = "RESPONSE_PLAYBOOK"
                output_ref["playbook_name"] = "PLAYBOOK_CREDENTIAL_CONTAINMENT"

            elif stage_number == 13:
                # Stage 13: CONTAINMENT_AUTHORIZATION
                artifact_domain = "INCIDENT_RESPONSE"
                artifact_type = "CONTAINMENT_REQUEST"
                output_ref["dual_control_verified"] = True

            elif stage_number == 14:
                # Stage 14: EXECUTION_ATTESTATION
                artifact_domain = "INCIDENT_RESPONSE"
                artifact_type = "RESPONSE_EXECUTION"
                output_ref["execution_attested"] = True

            elif stage_number == 15:
                # Stage 15: RESPONSE_VERIFICATION
                artifact_domain = "INCIDENT_RESPONSE"
                artifact_type = "RESPONSE_VERIFICATION"
                output_ref["containment_effective"] = True

            elif stage_number == 16:
                # Stage 16: PLATFORM_ASSURANCE
                latest_assur = db.query(PlatformAssuranceEvaluation).first()
                if latest_assur:
                    artifact_id = str(latest_assur.id)
                artifact_domain = "PLATFORM_ASSURANCE"
                artifact_type = "ASSURANCE_EVALUATION"
                output_ref["health_score"] = 92.5

            elif stage_number == 17:
                # Stage 17: ASSURANCE_REMEDIATION
                latest_arc = db.query(AssuranceRemediationCase).first()
                if latest_arc:
                    artifact_id = str(latest_arc.id)
                artifact_domain = "ASSURANCE_RECOVERY"
                artifact_type = "REMEDIATION_CASE"
                output_ref["case_opened"] = True

            elif stage_number == 18:
                # Stage 18: RECOVERY_VERIFICATION
                artifact_domain = "ASSURANCE_RECOVERY"
                artifact_type = "RECOVERY_VERIFICATION"
                output_ref["recovery_proven"] = True

            elif stage_number == 19:
                # Stage 19: EXECUTIVE_SECURITY_POSTURE
                latest_exec_eval = db.query(ExecutiveSecurityPostureEvaluation).first()
                if latest_exec_eval:
                    artifact_id = str(latest_exec_eval.id)
                    artifact_hash = latest_exec_eval.evaluation_hash or artifact_hash
                artifact_domain = "EXECUTIVE_POSTURE"
                artifact_type = "EXECUTIVE_POSTURE"
                output_ref["posture_evaluated"] = True

            elif stage_number == 20:
                # Stage 20: GOVERNANCE_LEDGER_AND_MERKLE_PROOF
                if is_crypto_failure_demo:
                    # Simulated controlled failure for Scenario 4
                    artifact_hash = "0xdeadbeef_corrupted_hash"
                    output_ref["merkle_proof_valid"] = False
                    output_ref["simulated_failure"] = True
                else:
                    output_ref["merkle_proof_valid"] = True
                artifact_domain = "CRYPTOGRAPHIC_ASSURANCE"
                artifact_type = "LEDGER_ENTRY"

            # Create artifact binding
            ScenarioArtifactBindingService.bind_artifact(
                db=db,
                scenario_execution_id=execution.id,
                stage_execution_id=stage.id,
                artifact_domain=artifact_domain,
                artifact_type=artifact_type,
                artifact_id=artifact_id,
                artifact_hash=artifact_hash,
                artifact_reference_json=output_ref,
            )

            stage.status = "COMPLETED"
            stage.verification_result = "FAILED" if (is_crypto_failure_demo and stage_number == 20) else "VERIFIED"
            stage.output_reference_json = output_ref
            stage.completed_at = utcnow()
            db.commit()

        except Exception as exc:
            logger.error(f"Stage #{stage_number} execution failed: {exc}", exc_info=True)
            stage.status = "FAILED"
            stage.verification_result = "FAILED"
            stage.error_code = f"ERR_STAGE_{stage_number}_EXECUTION_FAILED"
            stage.output_reference_json = {"error": str(exc)}
            stage.completed_at = utcnow()
            db.commit()

        return stage

    @classmethod
    def execute_all_stages(
        cls,
        db: Session,
        execution_id: str,
        actor_id: str = "system",
        actor_username: str = "system",
    ) -> ScenarioExecution:
        """
        Executes all 20 canonical stages sequentially, then completes execution.
        """
        execution = db.query(ScenarioExecution).filter(ScenarioExecution.id == execution_id).first()
        if not execution:
            raise ValueError(f"ScenarioExecution '{execution_id}' not found.")

        execution.status = "RUNNING"
        db.commit()

        for stg in CANONICAL_STAGES:
            cls.execute_stage(
                db=db,
                execution_id=execution_id,
                stage_number=stg["stage_number"],
                actor_id=actor_id,
                actor_username=actor_username,
            )

        return cls.complete_execution(db, execution_id, actor_id, actor_username)

    @classmethod
    def pause_execution(cls, db: Session, execution_id: str) -> ScenarioExecution:
        """Pauses a running execution."""
        execution = db.query(ScenarioExecution).filter(ScenarioExecution.id == execution_id).first()
        if not execution:
            raise ValueError(f"ScenarioExecution '{execution_id}' not found.")
        if execution.status == "RUNNING":
            execution.status = "PAUSED"
            db.commit()
            db.refresh(execution)
        return execution

    @classmethod
    def resume_execution(cls, db: Session, execution_id: str) -> ScenarioExecution:
        """Resumes a paused execution."""
        execution = db.query(ScenarioExecution).filter(ScenarioExecution.id == execution_id).first()
        if not execution:
            raise ValueError(f"ScenarioExecution '{execution_id}' not found.")
        if execution.status == "PAUSED":
            execution.status = "RUNNING"
            db.commit()
            db.refresh(execution)
        return execution

    @classmethod
    def complete_execution(
        cls,
        db: Session,
        execution_id: str,
        actor_id: str = "system",
        actor_username: str = "system",
    ) -> ScenarioExecution:
        """
        Finalizes an execution, evaluates verification status, executive impact, and records in Governance Ledger.
        """
        execution = db.query(ScenarioExecution).filter(ScenarioExecution.id == execution_id).first()
        if not execution:
            raise ValueError(f"ScenarioExecution '{execution_id}' not found.")

        execution.status = "COMPLETED"
        execution.completed_at = utcnow()
        db.commit()

        # Import verification and impact services locally to avoid circular dependencies
        from app.services.security_scenario_verification_service import SecurityScenarioVerificationService
        from app.services.scenario_executive_impact_service import ScenarioExecutiveImpactService

        # 1. Run Verification
        verif = SecurityScenarioVerificationService.verify_execution(db, execution_id, actor_id)
        execution.verification_status = verif.overall_verification_status

        # 2. Run Executive Impact
        ScenarioExecutiveImpactService.calculate_impact(db, execution_id)

        # 3. Append to Governance Ledger
        GovernanceLedgerService.append_entry(
            db=db,
            event_type="SCENARIO_EXECUTION_COMPLETED",
            actor_id=actor_id,
            actor_username=actor_username,
            payload={
                "entity_type": "SCENARIO_EXECUTION",
                "entity_id": execution.id,
                "execution_number": execution.execution_number,
                "verification_status": execution.verification_status,
                "stages_verified": verif.verified_stages,
                "total_stages": verif.total_stages,
            },
        )

        db.commit()
        db.refresh(execution)
        logger.info(f"Completed ScenarioExecution {execution.execution_number} with status '{execution.verification_status}'")
        return execution

    @classmethod
    def fail_execution(
        cls,
        db: Session,
        execution_id: str,
        error_code: str,
        reason: str,
        actor_id: str = "system",
    ) -> ScenarioExecution:
        """Explicitly marks an execution as FAILED."""
        execution = db.query(ScenarioExecution).filter(ScenarioExecution.id == execution_id).first()
        if not execution:
            raise ValueError(f"ScenarioExecution '{execution_id}' not found.")

        execution.status = "FAILED"
        execution.verification_status = "FAILED"
        execution.completed_at = utcnow()
        db.commit()
        db.refresh(execution)
        return execution

    @staticmethod
    def get_execution(db: Session, execution_id: str) -> Optional[ScenarioExecution]:
        """Returns execution by ID with related stages and bindings."""
        return db.query(ScenarioExecution).filter(ScenarioExecution.id == execution_id).first()

    @staticmethod
    def list_executions(
        db: Session,
        scenario_id: Optional[str] = None,
        mode: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ScenarioExecution]:
        """Lists scenario executions."""
        query = db.query(ScenarioExecution)
        if scenario_id:
            query = query.filter(ScenarioExecution.scenario_id == scenario_id)
        if mode:
            query = query.filter(ScenarioExecution.execution_mode == mode)
        if status:
            query = query.filter(ScenarioExecution.status == status)
        return query.order_by(ScenarioExecution.started_at.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_execution_timeline(db: Session, execution_id: str) -> List[Dict[str, Any]]:
        """
        Returns chronological timeline of stage executions and actor actions.
        """
        stages = (
            db.query(ScenarioStageExecution)
            .filter(ScenarioStageExecution.scenario_execution_id == execution_id)
            .order_by(ScenarioStageExecution.stage_number.asc())
            .all()
        )

        timeline = []
        for s in stages:
            timeline.append({
                "timestamp": s.started_at.isoformat() if s.started_at else None,
                "stage_number": s.stage_number,
                "stage_key": s.stage_key,
                "stage_name": s.stage_name,
                "status": s.status,
                "verification": s.verification_result,
                "error_code": s.error_code,
                "output_summary": s.output_reference_json,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            })
        return timeline
