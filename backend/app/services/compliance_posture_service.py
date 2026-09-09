"""
services/compliance_posture_service.py
--------------------------------------
Compliance Posture Evaluation, Framework Seeding & Command Center Aggregation.

Sprint 11A — Compliance Intelligence, Security Control Governance & Evidence-Backed Compliance Assurance.

Core Invariant: "COMPLIANCE MUST BE EVIDENCE-BACKED, EXPLAINABLE, HUMAN-GOVERNED, AND CRYPTOGRAPHICALLY VERIFIABLE."
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.compliance_intelligence import (
    ComplianceFramework,
    ComplianceRequirement,
    SecurityControl,
    FrameworkControlMapping,
    ControlEffectivenessEvaluation,
    ComplianceGap,
    ComplianceFinding,
    CompliancePostureEvaluation,
    ComplianceReview,
    ComplianceProvenanceRecord,
    COMPLIANCE_POSTURE_DOMAIN_PREFIX,
    calculate_compliance_hash,
    utcnow,
)
from app.services.control_effectiveness_service import ControlEffectivenessService
from app.services.compliance_gap_service import ComplianceGapService
from app.services.governance_ledger_service import GovernanceLedgerService

logger = logging.getLogger("sentinel.services.compliance_posture")


class CompliancePostureService:
    """Service for overall framework posture evaluation, default baseline seeding, and KPI metrics."""

    @classmethod
    def seed_default_frameworks_and_controls(cls, db: Session) -> Dict[str, int]:
        """
        Seeds default 3 Compliance Frameworks, 30+ Requirements, and 12 Core Security Controls.
        """
        created_counts = {"frameworks": 0, "requirements": 0, "controls": 0, "mappings": 0}

        # 1. Frameworks
        frameworks_data = [
            {
                "code": "FW-SENTINEL-TRACE-V5",
                "name": "SentinelTrace Security Baseline v5",
                "version": "5.0",
                "category": "SECURITY_BASELINE",
                "publisher": "SentinelTrace Architecture Board",
                "description": "Comprehensive Zero Trust cryptographic security baseline across all 11 lifecycle stages.",
            },
            {
                "code": "FW-NIST-CSF-2.0",
                "name": "NIST Cybersecurity Framework 2.0 Profile",
                "version": "2.0",
                "category": "INDUSTRY_STANDARD",
                "publisher": "National Institute of Standards and Technology (NIST)",
                "description": "NIST CSF 2.0 Core Functions: Govern, Identify, Protect, Detect, Respond, and Recover.",
            },
            {
                "code": "FW-ISO-27001-2022",
                "name": "ISO/IEC 27001:2022 ISMS Profile",
                "version": "2022",
                "category": "REGULATORY",
                "publisher": "International Organization for Standardization (ISO)",
                "description": "Information Security, Cybersecurity and Privacy Protection — Information Security Management Systems.",
            },
        ]

        framework_map: Dict[str, ComplianceFramework] = {}
        for fw_dict in frameworks_data:
            existing_fw = db.query(ComplianceFramework).filter(ComplianceFramework.framework_code == fw_dict["code"]).first()
            if not existing_fw:
                new_fw = ComplianceFramework(
                    framework_code=fw_dict["code"],
                    framework_name=fw_dict["name"],
                    framework_version=fw_dict["version"],
                    description=fw_dict["description"],
                    framework_category=fw_dict["category"],
                    status="ACTIVE",
                    publisher=fw_dict["publisher"],
                    created_by_user_id="SYSTEM",
                    metadata_json={"seeded": True},
                )
                db.add(new_fw)
                db.flush()
                framework_map[fw_dict["code"]] = new_fw
                created_counts["frameworks"] += 1
            else:
                framework_map[fw_dict["code"]] = existing_fw

        # 2. Controls (12 core controls)
        controls_data = [
            ("SC-AUTH-01", "Cryptographic Token Authentication & Signature Verification", "IDENTITY_ACCESS", "AUTHENTICATION", "CRITICAL", "PREVENTIVE"),
            ("SC-INGEST-01", "Deterministic Event Ingestion & Normalization", "DATA_INTEGRITY", "LOGGING", "HIGH", "DETECTIVE"),
            ("SC-SEM-01", "Semantic Interpretation & Multi-Source Reconciliation", "THREAT_ANALYSIS", "SEMANTICS", "MEDIUM", "DETECTIVE"),
            ("SC-POL-01", "Policy Governance & Dual-Approval Enforcement", "POLICY_MANAGEMENT", "GOVERNANCE", "HIGH", "GOVERNANCE"),
            ("SC-LEDGER-01", "Immutable SHA-256 Chained Governance Ledger", "CRYPTOGRAPHIC_ASSURANCE", "AUDIT", "CRITICAL", "ASSURANCE"),
            ("SC-MERKLE-01", "Merkle Tree Batch Cryptographic Notarization", "CRYPTOGRAPHIC_ASSURANCE", "CRYPTOGRAPHY", "CRITICAL", "ASSURANCE"),
            ("SC-DET-01", "Deterministic Detection Rule Execution & State Tracking", "DETECTION_ENGINEERING", "DETECTION", "HIGH", "DETECTIVE"),
            ("SC-TRUST-01", "Detection Rule Trust & Anomaly Governance", "DETECTION_ENGINEERING", "TRUST", "MEDIUM", "GOVERNANCE"),
            ("SC-INC-01", "Incident Escalation & Response State Automation", "INCIDENT_RESPONSE", "INCIDENT", "HIGH", "CORRECTIVE"),
            ("SC-ASSUR-01", "Automated Security Assurance & Remediation Verification", "SECURITY_ASSURANCE", "ASSURANCE", "HIGH", "ASSURANCE"),
            ("SC-SCEN-01", "End-to-End Cross-Domain Security Scenario Orchestration", "RESILIENCE_VALIDATION", "SCENARIO", "MEDIUM", "ASSURANCE"),
            ("SC-COMP-01", "Continuous Compliance Intelligence & Control Verification", "COMPLIANCE_INTELLIGENCE", "COMPLIANCE", "CRITICAL", "GOVERNANCE"),
        ]

        control_map: Dict[str, SecurityControl] = {}
        for c_code, c_name, domain, c_owner, crit, c_type in controls_data:
            existing_ctrl = db.query(SecurityControl).filter(SecurityControl.control_code == c_code).first()
            if not existing_ctrl:
                new_ctrl = SecurityControl(
                    control_code=c_code,
                    control_name=c_name,
                    description=f"Operational control for {c_name}.",
                    control_domain=domain,
                    control_owner=c_owner,
                    control_type=c_type,
                    criticality=crit,
                    expected_state="OPERATIONAL",
                    verification_frequency="CONTINUOUS",
                    status="ACTIVE",
                )
                db.add(new_ctrl)
                db.flush()
                control_map[c_code] = new_ctrl
                created_counts["controls"] += 1
            else:
                control_map[c_code] = existing_ctrl

        # 3. Requirements (10 per framework = 30 total)
        requirements_data = [
            # FW-SENTINEL-TRACE-V5 Requirements
            ("FW-SENTINEL-TRACE-V5", "ST-REQ-01", "Verifiable Identity & Access", "All API actions must have verifiable cryptographic identity.", "IDENTITY", 1.0, ["SC-AUTH-01"]),
            ("FW-SENTINEL-TRACE-V5", "ST-REQ-02", "Deterministic Log Ingestion", "Security telemetry must be ingested deterministically.", "INGESTION", 1.0, ["SC-INGEST-01"]),
            ("FW-SENTINEL-TRACE-V5", "ST-REQ-03", "Semantic Attack Alignment", "Events must be semantically classified and mapped to MITRE ATT&CK.", "SEMANTICS", 0.8, ["SC-SEM-01"]),
            ("FW-SENTINEL-TRACE-V5", "ST-REQ-04", "Dual-Control Policy Governance", "Security policy changes must require two-person authorization.", "GOVERNANCE", 1.2, ["SC-POL-01"]),
            ("FW-SENTINEL-TRACE-V5", "ST-REQ-05", "Cryptographic Governance Ledger", "Every state change must be sequentially hash-chained in the ledger.", "AUDIT", 1.5, ["SC-LEDGER-01"]),
            ("FW-SENTINEL-TRACE-V5", "ST-REQ-06", "Merkle Batch Cryptographic Sealing", "Batches must be notarized via Merkle tree roots.", "CRYPTOGRAPHY", 1.5, ["SC-MERKLE-01"]),
            ("FW-SENTINEL-TRACE-V5", "ST-REQ-07", "Deterministic Detection Execution", "Detection rules must execute deterministically against normalized logs.", "DETECTION", 1.0, ["SC-DET-01"]),
            ("FW-SENTINEL-TRACE-V5", "ST-REQ-08", "Detection Rule Anomaly Governance", "Anomalous or degraded rules must trigger governance review.", "TRUST", 0.8, ["SC-TRUST-01"]),
            ("FW-SENTINEL-TRACE-V5", "ST-REQ-09", "Automated Incident Containment", "High-severity detections must trigger automated containment playbooks.", "INCIDENT", 1.2, ["SC-INC-01"]),
            ("FW-SENTINEL-TRACE-V5", "ST-REQ-10", "Evidence-Backed Assurance", "Remediations must be verified before assurance restoration.", "ASSURANCE", 1.0, ["SC-ASSUR-01", "SC-COMP-01"]),

            # FW-NIST-CSF-2.0 Requirements
            ("FW-NIST-CSF-2.0", "NIST-GV.OC-01", "Organizational Context Governance", "The organization's mission and risk strategy are understood.", "GOVERN", 1.0, ["SC-POL-01"]),
            ("FW-NIST-CSF-2.0", "NIST-ID.AM-01", "Asset & Identity Management", "Inventories of hardware, software, and identity credentials are maintained.", "IDENTIFY", 1.0, ["SC-AUTH-01", "SC-INGEST-01"]),
            ("FW-NIST-CSF-2.0", "NIST-PR.DS-01", "Data Security & Integrity", "Data is managed consistent with risk strategy to protect integrity.", "PROTECT", 1.5, ["SC-LEDGER-01", "SC-MERKLE-01"]),
            ("FW-NIST-CSF-2.0", "NIST-PR.AC-01", "Access Control & Identity Assurance", "Access to assets is limited to authorized users and processes.", "PROTECT", 1.2, ["SC-AUTH-01"]),
            ("FW-NIST-CSF-2.0", "NIST-DE.CM-01", "Continuous Security Monitoring", "The network and environment are monitored to identify potential events.", "DETECT", 1.2, ["SC-INGEST-01", "SC-DET-01"]),
            ("FW-NIST-CSF-2.0", "NIST-DE.AE-01", "Adverse Event Analysis", "Anomalous activities and events are analyzed to detect cyber attacks.", "DETECT", 1.0, ["SC-SEM-01", "SC-TRUST-01"]),
            ("FW-NIST-CSF-2.0", "NIST-RS.MA-01", "Incident Management & Containment", "Incident response processes are executed to contain attacks.", "RESPOND", 1.2, ["SC-INC-01"]),
            ("FW-NIST-CSF-2.0", "NIST-RS.AN-01", "Incident Forensics & Investigation", "Analysis is conducted to support forensics.", "RESPOND", 1.0, ["SC-SCEN-01", "SC-ASSUR-01"]),
            ("FW-NIST-CSF-2.0", "NIST-RC.RP-01", "Recovery Planning & Execution", "Recovery processes are executed to restore affected systems.", "RECOVER", 1.0, ["SC-ASSUR-01"]),
            ("FW-NIST-CSF-2.0", "NIST-RC.IM-01", "Continuous Improvement & Verification", "Post-incident reviews inform updates to cybersecurity plans.", "RECOVER", 0.9, ["SC-COMP-01"]),

            # FW-ISO-27001-2022 Requirements
            ("FW-ISO-27001-2022", "ISO-A.5.1", "Policies for Information Security", "Information security policy and topic-specific policies are defined.", "ORGANIZATIONAL", 1.0, ["SC-POL-01"]),
            ("FW-ISO-27001-2022", "ISO-A.5.15", "Access Control Management", "Rules to control access to information are implemented.", "ORGANIZATIONAL", 1.2, ["SC-AUTH-01"]),
            ("FW-ISO-27001-2022", "ISO-A.8.15", "Logging and Monitoring", "Logs that record activities and security events are produced.", "TECHNOLOGICAL", 1.5, ["SC-INGEST-01", "SC-LEDGER-01"]),
            ("FW-ISO-27001-2022", "ISO-A.8.16", "Monitoring Activities", "Networks, systems and applications are monitored for anomalous behavior.", "TECHNOLOGICAL", 1.0, ["SC-DET-01", "SC-SEM-01"]),
            ("FW-ISO-27001-2022", "ISO-A.8.24", "Use of Cryptography", "Rules for the effective use of cryptography are implemented.", "TECHNOLOGICAL", 1.5, ["SC-MERKLE-01", "SC-LEDGER-01"]),
            ("FW-ISO-27001-2022", "ISO-A.5.24", "Information Security Incident Management Planning", "The organization plans and prepares for managing incidents.", "ORGANIZATIONAL", 1.2, ["SC-INC-01"]),
            ("FW-ISO-27001-2022", "ISO-A.5.28", "Collection of Evidence", "Procedures for identification and preservation of evidence.", "ORGANIZATIONAL", 1.5, ["SC-LEDGER-01", "SC-COMP-01"]),
            ("FW-ISO-27001-2022", "ISO-A.8.7", "Protection Against Malware", "Protection against malware is implemented.", "TECHNOLOGICAL", 0.8, ["SC-DET-01"]),
            ("FW-ISO-27001-2022", "ISO-A.8.8", "Management of Technical Vulnerabilities", "Information about technical vulnerabilities is obtained.", "TECHNOLOGICAL", 1.0, ["SC-ASSUR-01", "SC-SCEN-01"]),
            ("FW-ISO-27001-2022", "ISO-A.5.35", "Independent Review of Information Security", "The approach to managing information security is reviewed.", "ORGANIZATIONAL", 1.0, ["SC-COMP-01"]),
        ]

        for fw_code, req_code, title, desc_text, domain_sec, weight, mapped_ctrl_codes in requirements_data:
            fw = framework_map.get(fw_code)
            if not fw:
                continue

            existing_req = (
                db.query(ComplianceRequirement)
                .filter(
                    ComplianceRequirement.framework_id == fw.id,
                    ComplianceRequirement.requirement_code == req_code,
                )
                .first()
            )

            if not existing_req:
                new_req = ComplianceRequirement(
                    framework_id=fw.id,
                    requirement_code=req_code,
                    title=title,
                    description=desc_text,
                    requirement_category="TECHNICAL",
                    importance_weight=weight,
                    verification_required=True,
                    evidence_freshness_days=30,
                    status="ACTIVE",
                )
                db.add(new_req)
                db.flush()
                req_obj = new_req
                created_counts["requirements"] += 1
            else:
                req_obj = existing_req

            for c_code in mapped_ctrl_codes:
                ctrl = control_map.get(c_code)
                if not ctrl:
                    continue

                existing_map = (
                    db.query(FrameworkControlMapping)
                    .filter(
                        FrameworkControlMapping.framework_requirement_id == req_obj.id,
                        FrameworkControlMapping.security_control_id == ctrl.id,
                    )
                    .first()
                )
                if not existing_map:
                    new_map = FrameworkControlMapping(
                        framework_requirement_id=req_obj.id,
                        security_control_id=ctrl.id,
                        mapping_strength="PRIMARY",
                        mapping_rationale=f"Control {ctrl.control_code} provides core assurance for {req_obj.requirement_code}.",
                        mandatory=True,
                    )
                    db.add(new_map)
                    db.flush()
                    created_counts["mappings"] += 1

        logger.info(f"Seeded compliance baseline: {created_counts}")
        return created_counts

    @classmethod
    def evaluate_framework_posture(
        cls,
        db: Session,
        framework_id: str,
        evaluator_username: str = "SYSTEM",
    ) -> CompliancePostureEvaluation:
        """
        Calculates the comprehensive compliance posture score for a given Framework.
        """
        framework = (
            db.query(ComplianceFramework)
            .filter((ComplianceFramework.id == framework_id) | (ComplianceFramework.framework_code == framework_id))
            .first()
        )
        if not framework:
            raise ValueError(f"Compliance Framework {framework_id} not found.")

        requirements = (
            db.query(ComplianceRequirement)
            .filter(
                ComplianceRequirement.framework_id == framework.id,
                ComplianceRequirement.status == "ACTIVE",
            )
            .all()
        )

        total_reqs = len(requirements)
        if total_reqs == 0:
            raise ValueError(f"Framework {framework.framework_code} has no active requirements.")

        total_weighted_score = 0.0
        total_weight = 0.0
        reqs_effective = 0
        reqs_partial = 0
        reqs_failed = 0
        reqs_unknown = 0
        crypto_failure_detected = False
        deductions = []

        for req in requirements:
            weight = float(req.importance_weight or 1.0)
            total_weight += weight

            mappings = (
                db.query(FrameworkControlMapping)
                .filter(FrameworkControlMapping.framework_requirement_id == req.id)
                .all()
            )

            if not mappings:
                reqs_unknown += 1
                continue

            ctrl_scores = []
            for m in mappings:
                ctrl = m.control
                if not ctrl:
                    continue

                latest_eval = (
                    db.query(ControlEffectivenessEvaluation)
                    .filter(ControlEffectivenessEvaluation.security_control_id == ctrl.id)
                    .order_by(desc(ControlEffectivenessEvaluation.evaluated_at))
                    .first()
                )

                if not latest_eval:
                    latest_eval = ControlEffectivenessService.evaluate_control(
                        db=db,
                        control_id=ctrl.id,
                        evaluator_username=evaluator_username,
                    )

                if latest_eval.integrity_score == 0.0:
                    crypto_failure_detected = True

                ctrl_scores.append(float(latest_eval.effectiveness_score or 0.0))

            avg_score = sum(ctrl_scores) / len(ctrl_scores) if ctrl_scores else 0.0
            total_weighted_score += avg_score * weight

            if avg_score >= 80.0:
                reqs_effective += 1
            elif avg_score >= 50.0:
                reqs_partial += 1
            else:
                reqs_failed += 1

        calc_score = total_weighted_score / total_weight if total_weight > 0 else 0.0

        # Gaps count
        active_gaps = (
            db.query(ComplianceGap)
            .join(ComplianceRequirement)
            .filter(
                ComplianceRequirement.framework_id == framework.id,
                ComplianceGap.gap_status.in_(["OPEN", "ACKNOWLEDGED", "UNDER_REVIEW"]),
            )
            .all()
        )
        critical_gaps = len([g for g in active_gaps if g.severity == "CRITICAL"])
        high_gaps = len([g for g in active_gaps if g.severity == "HIGH"])

        # Hard failure override
        if crypto_failure_detected:
            final_score = 0.0
            posture_status = "CRITICAL_NON_COMPLIANT"
            hard_override = True
            override_reason = "CRITICAL OVERRIDE: Cryptographic verification failure detected across mapped controls."
            deductions.append({
                "rule": "CRYPTOGRAPHIC_INTEGRITY_DOMINANCE",
                "deduction": 100.0,
                "reason": override_reason,
            })
        else:
            final_score = max(0.0, min(100.0, calc_score))
            hard_override = False
            override_reason = None
            if final_score >= 90.0:
                posture_status = "COMPLIANT"
            elif final_score >= 75.0:
                posture_status = "SUBSTANTIALLY_COMPLIANT"
            elif final_score >= 50.0:
                posture_status = "PARTIALLY_COMPLIANT"
            else:
                posture_status = "NON_COMPLIANT"

        now = utcnow()
        eval_number = f"CPE-{now.strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"

        reasoning = {
            "requirements_evaluated": total_reqs,
            "requirements_effective": reqs_effective,
            "requirements_partial": reqs_partial,
            "requirements_failed": reqs_failed,
            "requirements_unknown": reqs_unknown,
            "critical_gaps": critical_gaps,
            "high_gaps": high_gaps,
            "hard_failure_override": hard_override,
            "override_reason": override_reason,
            "crypto_failure_detected": crypto_failure_detected,
        }

        eval_payload = {
            "evaluation_number": eval_number,
            "framework_id": framework.id,
            "framework_code": framework.framework_code,
            "overall_score": final_score,
            "posture_status": posture_status,
            "evaluated_at": now.isoformat(),
        }
        posture_hash = calculate_compliance_hash(COMPLIANCE_POSTURE_DOMAIN_PREFIX, eval_payload)

        evaluation = CompliancePostureEvaluation(
            evaluation_number=eval_number,
            framework_id=framework.id,
            overall_score=final_score,
            posture_status=posture_status,
            requirements_total=total_reqs,
            requirements_effective=reqs_effective,
            requirements_partial=reqs_partial,
            requirements_failed=reqs_failed,
            requirements_unknown=reqs_unknown,
            critical_gaps=critical_gaps,
            high_gaps=high_gaps,
            hard_failure_override=hard_override,
            override_reason=override_reason,
            evaluation_reasoning_json=reasoning,
            evaluation_hash=posture_hash,
            created_by_user_id=evaluator_username,
            created_at=now,
        )
        db.add(evaluation)
        db.flush()

        try:
            GovernanceLedgerService.append_entry(
                db=db,
                event_type="COMPLIANCE_POSTURE_EVALUATED",
                actor_id=None,
                actor_username=evaluator_username,
                payload={
                    "entity_type": "COMPLIANCE_FRAMEWORK",
                    "entity_id": framework.id,
                    "framework_code": framework.framework_code,
                    "overall_score": final_score,
                    "posture_status": posture_status,
                    "posture_hash": posture_hash,
                },
            )
        except Exception as e:
            logger.warning(f"Ledger append failed: {e}")

        logger.info(f"Evaluated framework {framework.framework_code}: Score={final_score:.1f}, Status={posture_status}")
        return evaluation

    @classmethod
    def get_command_center_metrics(cls, db: Session) -> Dict[str, Any]:
        """
        Aggregates comprehensive KPIs for the Cyber SOC Compliance Command Center.
        """
        cls.seed_default_frameworks_and_controls(db)

        frameworks = db.query(ComplianceFramework).filter(ComplianceFramework.status == "ACTIVE").all()
        controls = db.query(SecurityControl).filter(SecurityControl.status == "ACTIVE").all()
        gaps = db.query(ComplianceGap).filter(ComplianceGap.gap_status.in_(["OPEN", "ACKNOWLEDGED", "UNDER_REVIEW"])).all()
        findings = db.query(ComplianceFinding).filter(ComplianceFinding.status.in_(["DRAFT", "PENDING_REVIEW"])).all()
        reviews = db.query(ComplianceReview).all()

        total_controls = len(controls)
        effective_controls = 0
        partial_controls = 0
        ineffective_controls = 0

        for ctrl in controls:
            latest_eval = (
                db.query(ControlEffectivenessEvaluation)
                .filter(ControlEffectivenessEvaluation.security_control_id == ctrl.id)
                .order_by(desc(ControlEffectivenessEvaluation.evaluated_at))
                .first()
            )
            if latest_eval:
                if latest_eval.evaluation_status == "EFFECTIVE":
                    effective_controls += 1
                elif latest_eval.evaluation_status == "PARTIALLY_EFFECTIVE":
                    partial_controls += 1
                else:
                    ineffective_controls += 1

        framework_summaries = []
        overall_scores = []
        for fw in frameworks:
            latest_posture = (
                db.query(CompliancePostureEvaluation)
                .filter(CompliancePostureEvaluation.framework_id == fw.id)
                .order_by(desc(CompliancePostureEvaluation.created_at))
                .first()
            )
            if latest_posture:
                score = float(latest_posture.overall_score or 0.0)
                status = latest_posture.posture_status
                overall_scores.append(score)
            else:
                score = 0.0
                status = "PENDING_EVALUATION"

            framework_summaries.append({
                "framework_id": fw.id,
                "framework_code": fw.framework_code,
                "framework_name": fw.framework_name,
                "score": score,
                "status": status,
            })

        global_idx = sum(overall_scores) / len(overall_scores) if overall_scores else 0.0

        return {
            "global_compliance_index": round(global_idx, 2),
            "total_frameworks": len(frameworks),
            "total_controls": total_controls,
            "effective_controls": effective_controls,
            "partially_effective_controls": partial_controls,
            "ineffective_controls": ineffective_controls,
            "active_gaps_count": len(gaps),
            "critical_gaps_count": len([g for g in gaps if g.severity == "CRITICAL"]),
            "high_gaps_count": len([g for g in gaps if g.severity == "HIGH"]),
            "open_findings_count": len(findings),
            "pending_reviews_count": len(reviews),
            "framework_summaries": framework_summaries,
            "timestamp": utcnow().isoformat(),
        }
