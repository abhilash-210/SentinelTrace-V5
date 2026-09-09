# FINAL_ARCHITECTURE.md
# SentinelTrace V5 — Authoritative Architecture Specification

**Platform**: SENTINELTRACE V5  
**Baseline**: Sprint 13 Final Integration & Hardening  
**Core Invariant**: *"VERIFIABLE LOG NORMALIZATION, SEMANTIC TRUST GOVERNANCE & EXPLAINABLE SECURITY INTELLIGENCE WITHOUT STATISTICAL GUESSWORK OR GENERATIVE LLM HALLUCINATIONS."*  
**Operating Mode**: Offline-first, air-gapped, zero-trust cryptographic auditability.  

---

## 1. High-Level Architectural Blueprint

SentinelTrace V5 is a modular, deterministic, end-to-end cybersecurity platform designed for verifiable security log normalization, semantic drift detection, rule execution, risk correlation, SOC investigations, compliance assurance, security analytics, and executive intelligence.

```
+---------------------------------------------------------------------------------------------------------+
|                                      SENTINELTRACE V5 CORE ARCHITECTURE                                 |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|  [Tier 1: Ingestion & Evidence Vault]                                                                  |
|   -> Raw Ingestion API (Syslog, JSON, CEF, CSV, Windows Event XML)                                       |
|   -> Exact Raw Payload Preservation (Byte-for-byte SHA-256 Fingerprinting)                              |
|   -> IngestedEvent Table (sentinel.events)                                                              |
|                                     |                                                                   |
|                                     v                                                                   |
|  [Tier 2: Normalization & Semantic Governance]                                                          |
|   -> Format Detectors & Parsers (SyslogParser, JSONParser, CSVParser)                                  |
|   -> OCSF Canonical Event Normalization (Classes 4001 Network, 3001 Auth, 1001 System)                  |
|   -> Vendor-Scoped Semantic Policies & Protected Fields (sentinel.semantic_policies)                    |
|   -> Semantic Interpretation & Drift Detection Engine (Score Penalties, Drift Alerts)                   |
|                                     |                                                                   |
|                                     v                                                                   |
|  [Tier 3: Detection Trust & Rule Execution Engine]                                                      |
|   -> Declarative Detection Rule Registry & DAG Dependency Mapping                                       |
|   -> Detection Rule Trust Scoring (Dynamic Trust Deductions on Semantic Drift)                          |
|   -> Dual-Control Maker-Checker Approval (Draft -> Pending Review -> Active)                           |
|   -> Real-Time Declarative DSL Rule Execution Engine (Deterministic Matches)                           |
|                                     |                                                                   |
|                                     v                                                                   |
|  [Tier 4: Threat Intelligence & Risk Correlation]                                                       |
|   -> Structured Threat Feeds & IOC Normalization (IP, Hash, Domain, CVE)                                |
|   -> Multi-Signal Risk Correlation & Concentration Analysis                                             |
|   -> Prioritized Remediation Strategy Engine & Simulation Sandbox                                       |
|                                     |                                                                   |
|                                     v                                                                   |
|  [Tier 5: Incident Security & SOC Investigations]                                                       |
|   -> Deterministic Security Incident Correlation & Deduplication                                        |
|   -> Incident Response Containment Decision Engine & Playbooks                                          |
|   -> SOC Investigation Case Management & Cross-Domain Evidence Dossiers                                 |
|   -> 5-Dimension Impact Matrix (Financial, Operational, Regulatory, Reputation, Technical)             |
|                                     |                                                                   |
|                                     v                                                                   |
|  [Tier 6: Continuous Assurance & Compliance Intelligence]                                               |
|   -> 7-Domain Mathematical Platform Assurance (Health Scoring & Anomaly Detection)                      |
|   -> Assurance Remediation Lifecycle & Empirical Recovery Verification                                 |
|   -> Framework Crosswalk (NIST CSF, ISO 27001, SOC 2, SentinelTrace Baseline)                          |
|   -> Security Control Effectiveness & Evidence Binding Governance                                       |
|                                     |                                                                   |
|                                     v                                                                   |
|  [Tier 7: Security Analytics, Reporting & Cryptographic Provenance]                                     |
|   -> 15-Domain Cross-Domain Security Metric Registry & Dynamic Evaluations                              |
|   -> Point-in-Time Analytics Snapshots (SAS-YYYY-NNN) & SHA-256 Snapshot Seal                           |
|   -> Multi-Template Security Reporting Engine (7 Report Types, 11 Section Checksums)                    |
|   -> Reference-Only Evidence Packaging (SEP-YYYY-NNN) & Canonical Manifest Hashes                       |
|   -> 17-Stage Sequential Cryptographic Provenance Hash Lineage Chain                                    |
|   -> Governance Ledger (Hash-Chained Audit Trail) & Merkle Proof Anchoring                              |
+---------------------------------------------------------------------------------------------------------+
```

---

## 2. Subsystem Specifications

### 2.1 Evidence Vault & Ingestion Pipeline
- **Purpose**: Preserves raw security logs with zero modification and immediate SHA-256 cryptographic fingerprinting.
- **Key Tables**: `sentinel.events` (`IngestedEvent`).
- **Core Invariant**: $\text{raw\_payload\_hash} = \text{SHA256}(\text{raw\_payload})$. Raw payload is never mutated, cleaned, or truncated in place.
- **Tamper Detection**: Live cryptographic verification recalculates SHA-256 and compares against stored hash.

### 2.2 Normalization & Semantic Trust
- **Purpose**: Aligns heterogeneous log formats to OCSF canonical schemas while enforcing vendor-scoped semantic mapping policies.
- **Key Tables**: `sentinel.normalized_events`, `sentinel.semantic_policies`, `sentinel.protected_semantic_fields`, `sentinel.semantic_interpretations`, `sentinel.semantic_drift_alerts`.
- **Core Invariant**: Unmapped or drifted fields incur deterministic confidence deductions ($0.0 \le \text{confidence} \le 1.0$) and never default to "healthy".

### 2.3 Detection Rule Governance & Trust Scoring
- **Purpose**: Treats detection rules as governed security assets with versioning, blast-radius analysis, and semantic drift sensitivity.
- **Key Tables**: `sentinel.detection_rules`, `sentinel.detection_rule_versions`, `sentinel.detection_rule_trust_evaluations`, `sentinel.detection_executions`.
- **Core Invariant**: Detection rules bound to drifted semantic fields suffer automatic trust degradation. Rule activation strictly requires dual-control review.

### 2.4 Threat Intelligence & Adversary Context
- **Purpose**: Offline ingestion and normalization of indicators of compromise (IOCs) with actor attribution and event correlation.
- **Key Tables**: `sentinel.threat_feeds`, `sentinel.threat_indicators`, `sentinel.threat_actors`, `sentinel.threat_matches`, `sentinel.threat_trust_evaluations`.
- **Core Invariant**: `IOC MATCH != CONFIRMED INCIDENT`. Matches generate structured context and confidence scores without fabricating conclusions.

### 2.5 Risk Correlation & Prioritized Remediation
- **Purpose**: Evaluates cross-event risk concentration, multi-stage attacks, and computes cost-effective remediation strategies.
- **Key Tables**: `sentinel.risk_correlations`, `sentinel.remediation_plans`, `sentinel.remediation_simulations`.
- **Core Invariant**: Prioritized remediations are calculated via deterministic impact-to-effort ratios.

### 2.6 Incident Security & SOC Investigations
- **Purpose**: End-to-end incident lifecycle and structured case investigation workspace with multi-hypothesis evaluation and empirical findings.
- **Key Tables**: `sentinel.security_incidents`, `sentinel.incident_signals`, `sentinel.security_investigation_cases`, `sentinel.investigation_artifact_bindings`, `sentinel.investigation_hypotheses`, `sentinel.investigation_findings`, `sentinel.investigation_timeline_events`, `sentinel.investigation_impact_assessments`, `sentinel.investigation_reviews`, `sentinel.investigation_resolutions`.
- **Core Invariant**: Case closure and containment require dual-control separation of duties. Self-approval is mathematically rejected.

### 2.7 Continuous Assurance & Compliance Intelligence
- **Purpose**: Continuous empirical auditing of platform health and automated crosswalk against major compliance frameworks (NIST, ISO, SOC2).
- **Key Tables**: `sentinel.assurance_evaluations`, `sentinel.assurance_remediation_cases`, `sentinel.assurance_recovery_verifications`, `sentinel.compliance_frameworks`, `sentinel.compliance_requirements`, `sentinel.security_controls`, `sentinel.control_evidence_bindings`, `sentinel.control_effectiveness_evaluations`, `sentinel.compliance_gaps`, `sentinel.compliance_posture_evaluations`.
- **Core Invariant**: `CONTROL EXISTS != CONTROL EFFECTIVE`. Control effectiveness requires unexpired, verified evidence bindings.

### 2.8 Security Analytics, Reporting & Evidence Packaging
- **Purpose**: Aggregates 15 cross-domain metrics into sealed point-in-time snapshots, synthesizes 7 report types across 11 section checksums, and produces reference-only evidence packages.
- **Key Tables**: `sentinel.security_analytics_snapshots`, `sentinel.security_metric_definitions`, `sentinel.security_metric_evaluations`, `sentinel.security_trend_snapshots`, `sentinel.security_analytics_insights`, `sentinel.security_reports`, `sentinel.security_report_sections`, `sentinel.security_evidence_packages`, `sentinel.evidence_package_artifacts`, `sentinel.security_analytics_provenance_records`.
- **Core Invariant**: `CRYPTOGRAPHIC FAILURE > NUMERICAL REPORT SCORE`. Tampering or cryptographic failure overrides confidence to 0.0 and forces report status to `UNTRUSTED`.

### 2.9 Cryptographic Ledger & Merkle Audit
- **Purpose**: Append-only immutable audit trail and Merkle tree inclusion proofs for third-party auditing.
- **Key Tables**: `sentinel.governance_ledger`, `sentinel.merkle_batches`, `sentinel.merkle_proofs`.
- **Core Invariant**: Sequential block hash $H_n = \text{SHA256}(H_{n-1} \parallel \text{block\_data})$. Any block alteration invalidates the entire subsequent chain.

---

## 3. Cryptographic Provenance Lineage (17 Stages)

Every executive report and point-in-time analytics snapshot is bound to an immutable 17-stage cryptographic lineage chain:

```
Stage 01: RAW_EVIDENCE                   (Raw log preservation & SHA-256 seal)
   |
Stage 02: EVIDENCE_HASH                  (Cryptographic hash seal verification)
   |
Stage 03: NORMALIZED_EVENT               (OCSF canonical alignment & field mapping)
   |
Stage 04: SEMANTIC_INTERPRETATION        (Vendor policy interpretation & baseline comparison)
   |
Stage 05: DETECTION                      (Declarative detection rule matching)
   |
Stage 06: DETECTION_TRUST                (Dynamic trust scoring & drift penalties)
   |
Stage 07: THREAT_INTELLIGENCE            (IOC feed normalization & adversary correlation)
   |
Stage 08: RISK_CORRELATION               (Multi-signal threat & concentration correlation)
   |
Stage 09: SECURITY_INCIDENT              (Incident formulation & signal clustering)
   |
Stage 10: INVESTIGATION                  (SOC case investigation & hypothesis scoring)
   |
Stage 11: RESPONSE                       (Containment authorization & response playbooks)
   |
Stage 12: ASSURANCE                      (Platform assurance & continuous health auditing)
   |
Stage 13: COMPLIANCE                     (Security control effectiveness & framework crosswalk)
   |
Stage 14: SECURITY_ANALYTICS             (15-domain metric evaluation & snapshot sealing)
   |
Stage 15: ANALYTICS_INSIGHT              (Deterministic rule-triggered platform insights)
   |
Stage 16: SECURITY_REPORT                (Deterministic report synthesis & section checksums)
   |
Stage 17: GOVERNANCE_LEDGER_AND_MERKLE   (Sequential hash chain append & Merkle proof anchor)
```

**Sequential Mathematical Linkage**:
$$H_i = \text{SHA256}(\text{DOMAIN\_PREFIX} \parallel \text{stage\_number} \parallel \text{stage\_name} \parallel \text{artifact\_type} \parallel H_{i-1})$$
where $H_0 = 0^{64}$.

---

## 4. Role-Based Access Control (RBAC) Matrix

| Role | Core Responsibilities | Key Permissions | Maker-Checker Rights |
|---|---|---|---|
| `ADMIN` | System administrator | All permissions across all subsystems | Can authorize/review submissions made by others |
| `SECURITY_ANALYST` | SOC analyst & investigator | Read, Ingest, Normalize, Execute Detections, Investigate Cases, Draft Reports | Maker (submits policies, plans, containment requests) |
| `POLICY_AUTHOR` | Policy & detection rule author | Create/edit policies, detection rules, remediation plans | Maker |
| `POLICY_REVIEWER` | Governance reviewer | Review, Approve, Reject policies and plans | Checker (cannot approve own submissions) |
| `AUDITOR` | Independent compliance auditor | Read all modules, Verify Merkle proofs, Verify reports, Audit ledger | Verifier (read & verify only) |
| `VIEWER` | Executive & read-only viewer | Read dashboards, executive posture, reports | Read-only |

---

## 5. Technology Stack

- **Backend**: Python 3.11+ / FastAPI / SQLAlchemy 2.0 / Pydantic v2 / PostgreSQL 15 / SQLite (in-memory & tests) / PyJWT / Cryptography
- **Frontend**: React 18 / Vite 8 / Tailwind CSS / Vanilla Lucide-style SVG Icons
- **Security & Integrity**: Pure SHA-256 canonical JSON hashing / Merkle Trees / Dual-Control State Machines
- **Testing**: Python `unittest` with 867+ automated unit, integration, and security tests
