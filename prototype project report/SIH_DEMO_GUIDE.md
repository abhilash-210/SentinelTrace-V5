# SIH Demonstration Guide (5–10 Minute Presentation Script)

## Step-by-Step Demo Timeline

### 00:00 - 01:00: Problem & Architecture
- Open `/` (Dashboard). State problem: multi-vendor log chaos and lack of tamper proof.
- Highlight SentinelTrace's solution: OCSF Normalization + 17-Stage SHA-256 Lineage.

### 01:00 - 03:00: Ingestion & Normalization
- Open `/evidence` (Evidence Vault) and `/normalization` (Normalization).
- Show raw Syslog/JSON converting into standardized OCSF format with instant SHA-256 hashing.

### 03:00 - 05:00: Threat Detection & Incident Triage
- Open `/threat-intelligence` and `/security-incidents`.
- Demonstrate IOC match escalating entity risk score and creating an incident.

### 05:00 - 07:00: Security Analytics & Executive Reporting
- Open `/security-analytics`.
- Click **Generate Point-in-Time Snapshot (1H)** -> Show snapshot seal (`SAS-YYYY-NNN`).
- Click **Generate Executive Report** -> Show 11 section SHA-256 hashes.

### 07:00 - 09:00: Cryptographic Verification & Tamper Proof
- Open `/merkle-verification`.
- Click **Verify Provenance Chain** -> Show 17/17 STAGES VERIFIED GREEN.

### 09:00 - 10:00: Q&A & Summary
- Summarize: 935 automated tests, zero-trust telemetry rules, Maker-Checker dual governance.
