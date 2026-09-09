# FINAL_SECURITY_LIMITATIONS.md
# SentinelTrace V5 — Security Boundaries, Threat Model & Honest Limitations

**Platform**: SENTINELTRACE V5  
**Audience**: Security Architects, Evaluators, Evaluators, SIH Jury  
**Status**: Authoritative Reference  

---

## 1. Explicit Design Goals & Philosophy

SentinelTrace V5 is intentionally designed around **deterministic explainability, mathematical auditability, and offline air-gapped security governance**. 

### What SentinelTrace V5 IS:
- A **verifiable security log normalization and semantic trust platform**.
- A **deterministic detection, risk correlation, and investigation case management system**.
- A **cryptographically sealed security analytics and reporting engine**.
- A **dual-control maker-checker governed platform** enforcing separation of duties.

### What SentinelTrace V5 IS NOT:
- An autonomous AI agent making unsupervised production containment decisions.
- A generative LLM system fabricating narrative security reports.
- An autonomous SOAR engine executing arbitrary network reconfigurations without human approval.
- A black-box machine learning classifier.

---

## 2. Invariant Commitments & Truth Matrix

| Domain | Invariant Commitment | Honest Limitation & Boundary |
|---|---|---|
| **Evidence Vault** | Raw payload is preserved byte-for-byte and sealed with SHA-256 upon arrival. | If the network stream before ingestion is tapped or compromised, the vault preserves the compromised packet as received. Cryptographic verification detects post-ingestion tampering only. |
| **Normalization** | Normalizes events into OCSF-aligned canonical representations with field-level confidence scoring. | Incomplete source log fields result in reduced confidence penalties; normalization cannot synthesize missing upstream telemetry. |
| **Semantic Trust** | Detects vendor semantic schema drift against established baselines. | Requires an initial seeded semantic baseline for comparison; novel unknown vendors require initial mapping policies. |
| **Detection Trust** | Degrades detection rule trust if underlying semantic fields suffer drift. | High trust does not guarantee a detection rule will catch zero-day exploits outside its declarative logic scope. |
| **Threat Intelligence** | Offline IOC normalization and exact indicator matching. | `IOC MATCH != CONFIRMED INCIDENT`. Offline threat feeds reflect indicators known at the time of feed ingestion. |
| **Incident Response** | Enforces dual-control containment requests with mandatory human authorization. | SentinelTrace recommends containment actions and verifies attestation; it relies on SOC analysts to execute physical/network isolation. |
| **Investigations** | Formulates structured hypotheses and links cross-domain evidence without duplicating strings. | The quality of investigation findings depends on the breadth of correlated signals available across platform domains. |
| **Compliance** | Evaluates control effectiveness based on unexpired, cryptographically verified evidence bindings. | `CONTROL EXISTS != CONTROL EFFECTIVE`. Passing compliance assurance reflects evidence verification against defined requirements, not a guarantee against external breach. |
| **Analytics & Reports** | Deterministic synthesis from authoritative database records with section-level SHA-256 checksums. | Zero generative LLM narrative. Reports strictly summarize structured telemetry records. |
| **Cryptographic Provenance** | 17-stage sequential hash chain linking raw evidence to executive reports. | `CRYPTOGRAPHIC FAILURE > NUMERICAL REPORT SCORE`. Any hash mismatch forces confidence to 0.0 and report status to `UNTRUSTED`. |

---

## 3. Threat Model & Failure-Safe Behaviors

### 3.1 Self-Approval & Privilege Escalation (Maker-Checker)
- **Threat**: An analyst submits a policy change, detection rule activation, containment request, or case resolution and attempts to approve it themselves.
- **Mitigation**: Server-side checks strictly verify `user_id != author_id` and enforce distinct roles (`POLICY_REVIEWER` / `ADMIN`). Self-approval requests return `HTTP 400 Bad Request` or `HTTP 403 Forbidden`.

### 3.2 Data Tampering in Storage
- **Threat**: An adversary directly edits database records (raw events, normalized logs, section text, manifest JSON).
- **Mitigation**: Every read and verification endpoint re-computes SHA-256 hashes against canonical JSON / byte payloads. Any discrepancy immediately causes verification to fail (`status: UNTRUSTED`, `verified: false`).

### 3.3 Replay Poisoning
- **Threat**: A scenario replay or simulation run accidentally overwrites production incidents or creates duplicate authoritative evidence.
- **Mitigation**: Scenario executions are isolated in dedicated `sentinel.scenario_executions` tables, tagged with distinct execution IDs, and never mutate authoritative production event tables.

### 3.4 Missing Telemetry & Blind Spots
- **Threat**: A domain stops transmitting logs, falsely appearing "quiet" or "healthy".
- **Mitigation**: `NO DATA != GOOD PERFORMANCE`. Telemetry completeness penalties subtract up to 30% from overall confidence, and absent historical windows strictly return `INSUFFICIENT_DATA`.

---

## 4. Operational Environment & Pre-requisites

- **Operating System**: Linux (Ubuntu 22.04+ recommended) or Windows 10/11 / macOS.
- **Python**: Version 3.11 or higher.
- **Node.js**: Version 18 or higher (for frontend build/Vite).
- **Database**: PostgreSQL 15+ (production) or SQLite 3 (testing/air-gapped evaluation).
- **Network**: Completely operable in offline / air-gapped environments with zero external cloud dependencies.
