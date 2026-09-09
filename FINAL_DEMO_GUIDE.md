# FINAL_DEMO_GUIDE.md
# SentinelTrace V5 — Authoritative SIH Demonstration Guide

**Platform**: SENTINELTRACE V5  
**Scenario**: "From Adversarial Ingress to Executive Governance — The Verifiable 17-Stage Security Lifecycle"  
**Duration**: 5–8 Minutes  
**Mode**: Deterministic, Offline, Zero-Trust  

---

## 1. Demo Storyline Arc

The demo demonstrates the core SIH problem statement and beyond:
> *"How SentinelTrace transforms messy, untrusted security logs into mathematically verifiable, explainable security intelligence with dual-control human governance."*

```
[1. Ingest Log] -> [2. Normalize OCSF] -> [3. Detect Semantic Drift] -> [4. Execute Detection]
       |
[5. Correlate Threat Intel] -> [6. Formulate Incident] -> [7. SOC Investigation Dossier]
       |
[8. Containment Dual-Control] -> [9. Compliance Assurance] -> [10. Sealed Executive Report]
       |
[11. 17-Stage Provenance & Live Tamper Detection]
```

---

## 2. Quick Demo Setup & Fast Reset

To reset and seed the demo environment with 100% deterministic test data:

```bash
# Terminal (from repository root)
.\backend\.venv\Scripts\python.exe scratch/seed_sih_demo.py
```

This single command seeds:
- Raw firewall, auth, and cloud security logs
- OCSF canonical normalized events
- Semantic policies & vendor drift anomalies
- Active detection rules & trust evaluations
- Threat indicators (IOCs) & APT actor profiles
- Correlated security incident `INC-2026-000001`
- Active SOC investigation case `SIC-2026-001`
- Platform health assurance case & empirical recovery verification
- Sealed point-in-time security analytics snapshot `SAS-2026-001`
- Synthesized executive report `SRP-2026-001`

---

## 3. Step-by-Step Presentation Walkthrough

### Step 1: Raw Evidence Ingestion & Cryptographic Preservation
- **Navigate to**: `Evidence Vault` (`/evidence-vault`)
- **Key Talking Point**: "Logs are ingested without mutation. Every raw byte is hashed with SHA-256 upon arrival to guarantee zero post-ingestion alteration."
- **Action**: Click "Verify Integrity" on an ingested firewall event to show live SHA-256 match.

### Step 2: Canonical Normalization & Semantic Drift Governance
- **Navigate to**: `Normalization` (`/normalization`) & `Semantic Intelligence` (`/semantic-intelligence`)
- **Key Talking Point**: "We normalize logs to OCSF classes (4001 Network, 3001 Auth). When vendor formats change, our Semantic Trust engine detects field drift and applies deterministic confidence penalties instead of silently breaking."
- **Action**: Show normalized OCSF JSON and the active Semantic Drift Alert for `Cisco ASA -> Palo Alto` schema drift.

### Step 3: Detection Trust & Real-Time Rule Execution
- **Navigate to**: `Detection Rule Trust` (`/detection-trust`) & `Rule Execution` (`/detection-execution`)
- **Key Talking Point**: "Detection rules are treated as governed assets. If a rule relies on a drifted semantic field, its trust score automatically degrades."
- **Action**: Show declarative rule execution with input/output field resolutions.

### Step 4: Threat Intelligence Correlation & Incident Formulation
- **Navigate to**: `Threat Intelligence` (`/threat-intelligence`) & `SOC Incidents` (`/incidents`)
- **Key Talking Point**: "`IOC MATCH != CONFIRMED INCIDENT`. We correlate offline threat feed indicators with observed network events to formulate prioritized incidents."
- **Action**: Show Incident `INC-2026-000001` with correlated threat signals.

### Step 5: SOC Investigation Case Workspace
- **Navigate to**: `SOC Investigations` (`/investigations`)
- **Key Talking Point**: "Investigating analysts formulate hypotheses, bind cross-domain evidence artifacts, and assess 5D impact (Financial, Operational, Regulatory, Reputation, Technical)."
- **Action**: Open case `SIC-2026-001` and view bound artifacts and hypothesis scores.

### Step 6: Dual-Control Governance (Maker-Checker)
- **Navigate to**: `Incident Response` (`/incident-response`) & `Policy Governance` (`/approvals`)
- **Key Talking Point**: "High-impact actions (containment, rule activation, case closure) require maker-checker dual authorization. Self-approval is mathematically rejected."
- **Action**: Demonstrate that the author cannot approve their own containment request.

### Step 7: Security Analytics & 17-Stage Cryptographic Provenance
- **Navigate to**: `Security Analytics` (`/security-analytics`)
- **Key Talking Point**: "Our 15-domain matrix aggregates metrics into sealed point-in-time snapshots. The 17-stage cryptographic hash chain links the executive report directly back to the original raw evidence."
- **Action**:
  1. Show Executive Security Score, Confidence %, and 15-Domain Matrix.
  2. Open "17-Stage Provenance" tab to show unbroken sequential hash chain ($H_1 \rightarrow H_{17}$).
  3. Open "Cryptographic Verification" tab and click "Verify Report Lineage" to prove zero tampering.

### Step 8: Live Tamper Detection (The Wow Factor)
- **Key Talking Point**: "What happens if a rogue actor tampers with a report section or database entry?"
- **Action**: Show that altering a single character in stored report text immediately causes verification to flip to `UNTRUSTED`, and triggers the **Zero-Trust Cryptographic Dominance Rule** (forcing confidence to 0%).

---

## 4. Default Login Credentials

| Role | Username | Password | Access Level |
|---|---|---|---|
| **Admin** | `admin_demo` | `SentinelAdmin#2026` | Full platform access & checker authority |
| **Security Analyst** | `analyst_demo` | `SentinelAnalyst#2026` | Investigation, triage & submission (maker) |
| **Policy Reviewer** | `reviewer_demo` | `SentinelReviewer#2026` | Policy & response approval (checker) |
| **Auditor** | `auditor_demo` | `SentinelAuditor#2026` | Independent verification & audit |
| **Viewer** | `viewer_demo` | `SentinelViewer#2026` | Executive read-only |
