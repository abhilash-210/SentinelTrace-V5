# SENTINEL-TRACE V5: COMPLETE MASTER PROJECT REPORT & EXPLANATION

**Prepared Specially for Abhilash**  
**Project Name**: SentinelTrace V5  
**Original SIH Problem Theme**: Unified Log Parsing & Normalization Framework  
**Project Status**: COMPLETE, VERIFIED & FROZEN (Sprint 13 Security Hardened)  
**Hardening Test Suite**: **68 / 68 Tests Verified** (66 OK, 2 Skipped, 0 Failures, 0 Errors)  
**Full Platform Regression Suite**: **935 / 935 Tests Passing** (933 OK, 2 Skipped, 0 Failures, 0 Errors, 74.64s execution time)  
**Repository**: [github.com/abhilash-210/SentinelTrace-V5](https://github.com/abhilash-210/SentinelTrace-V5.git)  

---

## TABLE OF CONTENTS
1. [Executive Summary & Purpose](#1-executive-summary--purpose)
2. [The Heterogeneous Log Challenge](#2-the-heterogeneous-log-challenge)
3. [Original SIH Problem vs SentinelTrace V5 Prototype](#3-original-sih-problem-vs-sentineltrace-v5-prototype)
4. [Proposed Solution & End-to-End Conceptual Flow](#4-proposed-solution--end-to-end-conceptual-flow)
5. [System Architecture & Layered Breakdown](#5-system-architecture--layered-breakdown)
6. [The 17-Stage Cryptographic Lineage Chain](#6-the-17-stage-cryptographic-lineage-chain)
7. [Security Governance & RBAC Model](#7-security-governance--rbac-model)
8. [Threat Intelligence & Risk Correlation](#8-threat-intelligence--risk-correlation)
9. [Security Incidents & Forensic Case Investigation](#9-security-incidents--forensic-case-investigation)
10. [Assurance & Remediation Recovery](#10-assurance--remediation-recovery)
11. [Compliance Intelligence Engine](#11-compliance-intelligence-engine)
12. [15-Domain Security Analytics & Reporting Engine](#12-15-domain-security-analytics--reporting-engine)
13. [Scenario Execution & Replay Engine](#13-scenario-execution--replay-engine)
14. [Database Architecture & ORM Model Reference](#14-database-architecture--orm-model-reference)
15. [Backend FastAPI Implementation Reference](#15-backend-fastapi-implementation-reference)
16. [Frontend React Command Centers Reference](#16-frontend-react-command-centers-reference)
17. [Testing Strategy & Automated Verification Results](#17-testing-strategy--automated-verification-results)
18. [Installation & Local Execution Guide](#18-installation--local-execution-guide)
19. [SIH Judge Demonstration Script & Visual Guide](#19-sih-judge-demonstration-script--visual-guide)
20. [SIH Judge Technical Defense Q&A](#20-sih-judge-technical-defense-qa)
21. [Complete Codebase File Map](#21-complete-codebase-file-map)
22. [Limitations & Production Roadmap](#22-limitations--production-roadmap)
23. [Technical Glossary](#23-technical-glossary)

---

## 1. Executive Summary & Purpose

**SentinelTrace V5** is an enterprise-grade, zero-trust security intelligence platform engineered to eliminate log format chaos and provide verifiable mathematical confidence to security operations.

In modern cybersecurity operations, Security Operations Centers (SOCs) ingest millions of events daily across firewalls, endpoints, identity providers, and cloud services. These raw logs arrive in wildly divergent formats (JSON, Syslog, CSV, CEF, XML) with inconsistent field naming, missing attributes, and zero proof of authenticity. 

SentinelTrace V5 solves this foundational challenge by uniting an **OCSF v1.1.0 Multi-Format Ingestion & Normalization Engine** with a **17-Stage Cryptographic Lineage Chain**. Every event ingested into SentinelTrace is immediately hashed (SHA-256), mapped into standard Open Cybersecurity Schema Framework (OCSF) classes, evaluated for detection trust, correlated against threat intelligence baselines, and sealed into verifiable point-in-time analytics snapshots.

---

## 2. The Heterogeneous Log Challenge

### 2.1 Why Heterogeneous Security Logs Break Traditional SOCs
1. **Schema Fragmentation**: The source IP address appears as `src_ip` in Cisco ASA logs, `source_ip` in AWS CloudTrail, `src_address` in Palo Alto firewalls, and `client_ip` in Okta logs. SOC analysts must write separate query logic for every vendor format.
2. **Format Chaos**: Parsing JSON, Syslog Key-Value, CSV, CEF, XML, and Windows Event Logs requires distinct parsing scripts, resulting in fragile pipelines that fail when vendors update log formats.
3. **Lack of Evidence Integrity**: Standard Syslog transmission uses unencrypted, unauthenticated UDP/TCP streams without cryptographic digests. Adversaries who breach log servers can modify timestamps or delete intrusion evidence without detection.
4. **False Clean Posture**: Traditional SIEM platforms treat missing or dropped log streams as "0 alerts", generating false clean reports during telemetry outages.

---

## 3. Original SIH Problem vs SentinelTrace V5 Prototype

| SIH Problem Challenge Requirement | Core SentinelTrace Implementation | Extended Platform Capability |
|---|---|---|
| Ingest multi-vendor raw logs | Format-Agnostic Ingestion Engine (`IngestedEvent`) | Raw Evidence Vault with SHA-256 evidence hashing |
| Multi-format log parsing | Multi-Format Parser (`parsers/`) for JSON, Syslog, CSV, CEF | Automated pattern discovery & field extraction |
| Unified schema mapping | OCSF v1.1.0 & ECS Schema Mapping (`NormalizedEvent`) | Semantic Interpretation & Policy Registry |
| Log correlation & search | Incident & Case Management (`SecurityIncident`) | Threat Intel, Risk Correlation, & ATT&CK Mapping |
| Auditability | Governance Ledger (`GovernanceLedger`) | 17-Stage Cryptographic Provenance Chain (`SAS-YYYY-NNN`) |

---

## 4. Proposed Solution & End-to-End Conceptual Flow

SentinelTrace V5 implements a zero-trust, verifiable security pipeline:

```
[Raw Security Telemetry] ──> (SHA-256 Evidence Seal)
          │
          ▼
[Multi-Format Ingestion Vault] ──> [OCSF v1.1.0 Normalization Engine]
          │
          ▼
[Semantic Policy Registry] ──> [Detection & Trust Engine]
          │
          ▼
[Threat Intelligence Correlation] ──> [Risk Correlation & Scoring]
          │
          ▼
[Security Incidents] ──> [Forensic Case Investigation Workspace]
          │
          ▼
[Assurance & Remediation Recovery] ──> [Compliance Intelligence Engine]
          │
          ▼
[15-Domain Security Analytics] ──> [17-Stage Cryptographic Lineage Chain]
          │
          ▼
[Executive Security Reports] ──> [Reference-Only Evidence Packaging]
          │
          ▼
[Governance Ledger & Merkle Proof Tamper Console]
```

---

## 5. System Architecture & Layered Breakdown

### 5.1 Architecture Overview
SentinelTrace V5 uses a decoupled, layered architecture:
- **Presentation Layer**: 26 React Command Centers delivering real-time dashboards, investigation canvases, and cryptographic verification consoles.
- **API Gateway Layer**: 29 FastAPI REST router modules mounted at `/api/v1/` managing request validation and RBAC authorization.
- **Service Layer**: 25 Python domain services executing normalization, detection, threat correlation, incident lifecycles, compliance scoring, and analytics snapshots.
- **Persistence & Cryptographic Layer**: SQLAlchemy 2.0 ORM models backed by SHA-256 canonical hashing services and append-only governance ledgers.

---

## 6. The 17-Stage Cryptographic Lineage Chain

Every security event processed by SentinelTrace V5 passes through a 17-stage cryptographic lineage sequence. Each stage calculates a SHA-256 hash of its output state and links it to the `previous_hash` of the preceding stage:

1. `RAW_INGESTION`: Raw text/json payload captured and hashed.
2. `EVIDENCE_VAULT`: Raw event committed to immutable vault (`evt_...`).
3. `PARSER_DISCOVERY`: Log format matched to parsing pattern.
4. `FIELD_EXTRACTION`: Key-value pairs extracted.
5. `OCSF_MAPPING`: Fields normalized into OCSF v1.1.0 structure (`norm_...`).
6. `SEMANTIC_INTERPRETATION`: Domain semantics and intent attached.
7. `SEMANTIC_POLICY_EVALUATION`: Checked against organizational security policies.
8. `DETECTION_RULE_EXECUTION`: Evaluated by detection rule engine.
9. `DETECTION_TRUST_SCORING`: Detection confidence weighted by rule trust history.
10. `THREAT_INTEL_CORRELATION`: Matched against IOC feeds and ATT&CK patterns.
11. `RISK_CORRELATION`: Entity risk scores recalculated based on severity.
12. `SECURITY_INCIDENT_CREATION`: Incidents created for critical correlation thresholds (`inc_...`).
13. `SECURITY_INVESTIGATION`: Case workspace created (`arc_...`).
14. `RESPONSE_LINEAGE`: Remediation and containment plans evaluated.
15. `ASSURANCE_RECOVERY`: Verification of recovery actions.
16. `SECURITY_ANALYTICS_SNAPSHOT`: Snapshot generated (`SAS-YYYY-NNN`).
17. `GOVERNANCE_LEDGER_ANCHOR`: Block committed to Merkle ledger tree.

---

## 7. Security Governance & RBAC Model

### 7.1 Role-Based Access Control (5 Roles, 32 Permissions)

| Role | Purpose | Write Access | Admin Access |
|---|---|---|---|
| `ADMIN` | System administrator | Full | Full |
| `SECURITY_ANALYST` | Operations analyst | Triage & Cases | None |
| `SECURITY_REVIEWER` | Senior reviewer | Dual Approvals | None |
| `COMPLIANCE_AUDITOR` | Auditor | Read-only Audit | None |
| `VIEWER` | Executive observer | Read-only | None |

### 7.2 Maker-Checker Dual Governance Invariant
Privileged operations (e.g. promoting detection rule versions, approving incident containment authorizations) require dual-operator authorization:
$$\text{Proposer User ID} \neq \text{Approver User ID}$$
If `proposer_id == approver_id`, the system enforces a self-approval rejection (HTTP 422 Unprocessable Entity).

---

## 8. Threat Intelligence & Risk Correlation

- **IOC Ingestion**: Ingests IP addresses, domain names, file hashes (MD5, SHA-256), and URLs from threat feeds.
- **ATT&CK Mapping**: Maps indicators to MITRE ATT&CK tactics, techniques, and threat actor profiles.
- **Invariant**: **IOC MATCH != CONFIRMED INCIDENT**. An IOC match elevates entity risk scoring, but does not convert into a confirmed incident until contextual detection threshold rules are met.

---

## 9. Security Incidents & Forensic Case Investigation

- **Incident Triage**: Automatic incident creation (`inc_...`) based on risk thresholds and detection rule execution.
- **Forensic Case Workspace**: Deep investigation workspace (`arc_...`) binding hypotheses, timeline events, raw artifacts, and root cause analysis.

---

## 10. Assurance & Remediation Recovery

- **Assurance Cases**: Tracks remediation lifecycle (`arp_...`) from recommendation generation to plan submission, reviewer approval, execution attestation, and recovery verification.

---

## 11. Compliance Intelligence Engine

- **Supported Baselines**: NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022, SOC 2 Type II, CERT-In Cyber Security Directions.
- **Automated Gap Detection**: Calculates compliance percentage scores by evaluating evidence bindings against framework control requirements.

---

## 12. 15-Domain Security Analytics & Reporting Engine

- **15 Metric Domains**: Evidence, Normalization, Semantic Trust, Detection, Risk, Incidents, Response, Recovery, Compliance, Threat Intel, Investigations, Executive, Execution.
- **Point-in-Time Snapshots (`SAS-YYYY-NNN`)**: Captures platform health across time windows (`1H`, `24H`, `7D`, `30D`). Each snapshot receives a SHA-256 seal.
- **7 Executive Report Templates**: Synthesizes structured reports (`SRP-YYYY-NNN`) featuring 11 SHA-256 section hashes.
- **Reference-Only Evidence Packaging**: Generates evidence packages (`SEP-YYYY-NNN`) binding artifact hashes without payload duplication.

---

## 13. Scenario Execution & Replay Engine

- **Attack Scenario Simulation**: Simulates Brute Force, Lateral Movement, and Data Exfiltration scenarios to validate detection logic.
- **Replay Modes**: Supports `EVIDENCE_REPLAY` and `CONTROLLED_REEXECUTION` under isolated testing conditions.

---

## 14. Database Architecture & ORM Model Reference

27 SQLAlchemy 2.0 ORM models in `backend/app/models/` using `sentinel` schema isolation:

| ORM Model File | Primary Class | Purpose |
|---|---|---|
| `event.py` | `IngestedEvent` | Raw log payload vault & raw SHA-256 hash |
| `normalized_event.py` | `NormalizedEvent` | Normalized OCSF JSON event payload |
| `semantic_interpretation.py` | `SemanticInterpretation` | Domain semantic annotations |
| `semantic_policy.py` | `SemanticPolicy` | Policy definitions & mapping rules |
| `detection_rule.py` | `DetectionRule` | Detection rules & SIGMA patterns |
| `detection_rule_governance.py` | `DetectionRuleVersion` | Rule versioning & dual approval proposals |
| `threat_intelligence.py` | `ThreatIntelIndicator` | IOC indicators & feed mappings |
| `risk_correlation.py` | `EntityRiskScore` | Entity-level risk aggregation |
| `security_incident.py` | `SecurityIncident` | Security incident tracking & containment |
| `security_investigation.py` | `InvestigationCase` | Forensic investigation cases |
| `assurance_remediation.py` | `AssuranceCase` | Root cause analysis & remediation plans |
| `compliance_intelligence.py` | `ComplianceFramework` | Compliance controls & assessment scores |
| `security_analytics.py` | `SecurityAnalyticsSnapshot` | Snapshots, reports, evidence packages & 17-stage provenance |
| `governance.py` | `GovernanceRecord` | Governance audit records |
| `ledger.py` | `GovernanceLedger` | Append-only audit block chain |
| `merkle.py` | `MerkleTreeRecord` | Binary Merkle tree nodes & root hashes |

---

## 15. Backend FastAPI Implementation Reference

- **Location**: `backend/app/`
- **Main Entrypoint**: `main.py`
- **Routers (29 Modules)**: Mounted under `/api/v1/` handling ingestion, normalization, detection, incidents, analytics, merkle checks, etc.
- **Services (25 Modules)**: Encapsulate core business logic, hash calculations, and database transactions.

---

## 16. Frontend React Command Centers Reference

- **Location**: `frontend/src/pages/`
- **26 Command Centers**:
  - `Dashboard.jsx`: Executive hub.
  - `EvidenceVault.jsx`: Raw log inspector.
  - `Normalization.jsx`: OCSF mapping viewer.
  - `DetectionRuleGovernance.jsx`: Rule lifecycle & dual approval UI.
  - `SecurityIncidents.jsx`: Triage & response.
  - `SecurityInvestigationCommandCenter.jsx`: Forensic workspace canvas.
  - `SecurityAnalyticsCommandCenter.jsx`: 15-domain matrix, snapshots, reports & evidence packages.
  - `MerkleVerification.jsx`: Cryptographic tamper verification console.

---

## 17. Testing Strategy & Automated Verification Results

### 17.1 Hardening Suite (`tests/test_sprint13_final_hardening.py`)
- **Total Tests**: 68
- **Passed**: 66 OK
- **Skipped**: 2 (legitimate endpoint guards for optional containment routes)
- **Failures / Errors**: 0

### 17.2 Full Platform Regression Suite
- **Command**: `python -m unittest discover -s tests -p "test_*.py"`
- **Total Tests**: **935**
- **Passed**: **933 OK**
- **Skipped**: 2
- **Failures / Errors**: **0**
- **Suite Execution Time**: 74.64s

---

## 18. Installation & Local Execution Guide

### Step 1: Backend Setup
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m scratch.seed_sih_demo
uvicorn app.main:app --reload --port 8000
```

### Step 2: Frontend Setup
```powershell
cd frontend
npm install
npm run dev
```

### Step 3: Access
Open browser to `http://localhost:5173`. Log in using `admin_demo` / `password`.

---

## 19. SIH Judge Demonstration Script & Visual Guide

### 00:00 - 01:00: Problem & Architecture Introduction
- Open `/` (Dashboard). State problem: multi-vendor log format chaos and lack of tamper proof.
- Highlight SentinelTrace solution: OCSF Normalization + 17-Stage SHA-256 Cryptographic Lineage.

### 01:00 - 03:00: Ingestion & Normalization
- Open `/evidence` (Evidence Vault) and `/normalization` (Normalization).
- Show raw Syslog/JSON converting into standard OCSF format with instant SHA-256 hashing.

### 03:00 - 05:00: Threat Detection & Incident Triage
- Open `/threat-intelligence` and `/security-incidents`.
- Demonstrate IOC match escalating entity risk score and creating an incident (`inc_...`).

### 05:00 - 07:00: Security Analytics & Executive Reporting
- Open `/security-analytics`.
- Click **Generate Point-in-Time Snapshot (1H)** -> Show snapshot seal (`SAS-YYYY-NNN`).
- Click **Generate Executive Report** -> Show 11 section SHA-256 hashes.

### 07:00 - 09:00: Cryptographic Verification & Tamper Proof
- Open `/merkle-verification`.
- Click **Verify Provenance Chain** -> Show 17/17 STAGES VERIFIED GREEN.

### 09:00 - 10:00: Q&A & Summary
- Summarize: 935 automated tests, zero-trust telemetry rules, Maker-Checker dual governance.

---

## 20. SIH Judge Technical Defense Q&A

### Q1: How is SentinelTrace different from a standard SIEM like Splunk or QRadar?
**Answer**: Traditional SIEMs index text logs and evaluate alerts, but do not provide mathematical proof of evidence provenance or tamper detection. SentinelTrace hashes raw events upon ingestion and maintains a 17-stage cryptographic lineage chain. Furthermore, SentinelTrace enforces zero-trust telemetry rules (missing data degrades trust score) and Maker-Checker dual governance for rule/remediation approvals.

### Q2: Why choose OCSF for log normalization?
**Answer**: Open Cybersecurity Schema Framework (OCSF v1.1.0) is an open-source, vendor-agnostic industry standard backed by AWS, Cloudflare, and major security vendors. It provides standard categories, event classes, and attribute naming, eliminating custom parser re-writes for every new device.

### Q3: What happens if an attacker modifies a stored log in the database?
**Answer**: Every event and report section is sealed with a canonical SHA-256 hash. When a verification check is triggered, SentinelTrace recalculates the canonical hash. Any 1-bit alteration breaks the hash chain, causing the verification engine to mark the asset as `UNTRUSTED` and pinpoint the exact tampered section.

---

## 21. Complete Codebase File Map

```
SENTINEL-TRACE/
├── .env.example
├── .gitignore
├── README.md
├── docker-compose.yml
├── backend/
│   ├── app/
│   │   ├── core/ (auth.py, rbac.py, config.py)
│   │   ├── models/ (27 ORM models)
│   │   ├── parsers/ (Syslog, JSON, CSV, CEF parsers)
│   │   ├── routers/ (29 REST API routers)
│   │   ├── schemas/ (Pydantic validation schemas)
│   │   └── services/ (25 domain services)
│   ├── tests/ (935 full regression tests)
│   └── sentinel_trace.db
├── frontend/
│   ├── src/
│   │   ├── components/ (Header, Sidebar, KPI cards)
│   │   └── pages/ (26 Command Center pages)
│   ├── package.json
│   └── vite.config.js
├── prototype project report/ (24 technical reference documents)
│   └── ABHILASH_REPORT.md
├── sample-data/
└── scratch/ (seed_sih_demo.py)
```

---

## 22. Limitations & Production Roadmap

### Current Prototype Bounds
1. **SQLite Database**: Dev embedded database (`sentinel_trace.db`). Production deployment requires PostgreSQL / TimescaleDB.
2. **Single-Node Pipeline**: In-process Python execution. Production requires distributed Apache Kafka / Redis stream workers.
3. **In-App Key Management**: Signing keys managed in application env. Production roadmap mandates Hardware Security Module (HSM) or AWS KMS.

---

## 23. Technical Glossary

- **OCSF**: Open Cybersecurity Schema Framework v1.1.0 standard.
- **SHA-256**: 256-bit Secure Hash Algorithm digest.
- **Canonicalization (`compute_canonical_hash`)**: Sorting JSON keys alphabetically and stripping whitespace before hashing.
- **17-Stage Lineage Chain**: Hash linkage tracking an event from raw ingestion to executive report sealing.
- **Maker-Checker Governance**: Dual approval security principle requiring privileged operations proposed by user A to be approved by user B.
- **Zero-Trust Telemetry**: Principle dictating that missing or unverified data reduces security confidence scores.
