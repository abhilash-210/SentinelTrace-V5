# SentinelTrace V5 — Demo Guide

**SIH 2026 · PS 26156 · Universal Log Pre-processing Framework**

This guide provides a 5–10 minute demonstration sequence for judges to independently evaluate the SentinelTrace V5 prototype. All steps are executable on the running application at `http://localhost:5173`.

---

## Prerequisites

Start the application before beginning:

```bat
start_app.bat
```

Log in as **admin_demo / SentinelDemo!2026**.

---

## Demo Sequence

### Step 1 — Problem Statement (30 seconds)
Point to the **Architecture Dashboard** (`P1: OVERVIEW`).

*"Traditional log pipelines ingest heterogeneous logs, transform them, and discard the original. If a log is malformed, it is silently dropped. SentinelTrace solves this with a zero-data-loss architecture: every log is cryptographically sealed before any parsing occurs."*

---

### Step 2 — Ingest a Raw Log (1 minute)
1. Click **P1: INGESTION & EVIDENCE → Evidence Vault & Ingest**
2. Click the **Cisco ASA Firewall** preset button. The form populates with a Syslog payload.
3. Point out the `Source Type`, `Format: text`, and the raw Syslog payload.
4. Click **🔒 Preserve Evidence**.
5. The response shows:
   - **Event ID** (e.g., `evt_...`)
   - **SHA-256 Hash** (e.g., `60a6e3...`)

*"The raw log is stored verbatim. The SHA-256 hash is its cryptographic fingerprint — computed before any parsing."*

---

### Step 3 — Normalization (1 minute)
1. Click **P2: NORMALIZATION & DRIFT → OCSF Normalization**
2. Click **⚡ Normalize All Events** button.
3. Locate your Cisco ASA event in the **Canonical Security Events Ledger**.
4. Point out: `OCSF Class: Network Activity`, `Action: ALLOW`, `src_ip`, `dst_ip`, `Parser: SyslogParser`.

*"The raw Syslog string is now a canonical OCSF event. The `action` field maps from 'Built TCP connection' to `ALLOW`. Proprietary fields not in OCSF are preserved in the `unmapped_data` column."*

---

### Step 4 — Traceability (30 seconds)
1. Click **Trace Link ➔** on the normalized event row.
2. The Evidence Vault modal opens showing the original raw payload.

*"Every normalized event carries a foreign key to its raw evidence. An auditor can always trace a SIEM alert back to the byte-exact original log."*

---

### Step 5 — SHA-256 Integrity Verification (1 minute)
1. In the Evidence Vault modal, scroll to **Cryptographic Integrity Audit**.
2. Click **Run Live Verification**.
3. The system re-computes the SHA-256 hash of the stored `raw_content` and compares it to the stored fingerprint.
4. Result: **✓ 100% MATCH (VERIFIED)**

*"The hash proves the original log was never modified after ingestion. This is the forensic foundation of the platform."*

---

### Step 6 — Quarantine & Replay (2 minutes)

**Ingest a malformed event:**
1. Return to **Evidence Vault & Ingest**.
2. Click the **Auth Gateway (JSON)** preset.
3. In the raw payload box, delete the last `}` character (creating invalid JSON).
4. Click **🔒 Preserve Evidence**. It succeeds — because preservation happens before parsing.

**Trigger normalization:**
1. Click **⚡ Normalize All Events** in OCSF Normalization.
2. The broken event appears with `Status: FAILED`.

**Inspect the Quarantine:**
1. Click **P1: INGESTION & EVIDENCE → Quarantine (DLQ)**.
2. Locate your `auth-gateway-node` event. Point out `Failure Reason: JSONDecodeError`.
3. Click **Fix & Replay**.
4. In the modal, add the missing `}` back to the corrected payload.
5. Add a Resolution Note: *"Fixed missing closing bracket."*
6. Click **🔄 Replay & Re-Validate**.

*"The malformed log was preserved, not dropped. The human fix is applied at re-parse time. The original corrupted payload remains untouched in the vault."*

---

### Step 7 — SIEM & Data Lake Output (1 minute)
1. Click **P1: INGESTION & EVIDENCE → Evidence Vault & Ingest** → scroll to the **Evidence Ledger**.
2. Point out the events that have been normalized.

*"Every validated normalized event is appended to a JSONL SIEM stream in `backend/outputs/siem_stream.log` and batch-exported to Parquet files partitioned by date and source. This output is immediately consumable by AI/ML frameworks or downstream SIEMs."*

---

### Step 8 — Semantic Intelligence (1 minute, optional)
1. Click **P2: NORMALIZATION & DRIFT → Semantic Policies**.
2. Click the **Cisco ASA (PERMIT → ALLOWED)** scenario button.
3. Click the **Demo Vendor (PERMIT → MONITORED)** scenario button.
4. Show both results in the Registry Table.

*"The word 'PERMIT' means different things on different vendors. Our Semantic Policy Engine isolates meaning by vendor context. If a vendor changes their log vocabulary, this is flagged as Semantic Drift — not silently accepted."*

---

### Step 9 — Offline Operation (30 seconds)
*"This entire demonstration ran with no internet connection, no cloud APIs, and no external SaaS services. The full platform runs in Docker Compose with a single command. This makes it deployable in air-gapped government and military networks."*

---

## Expected Observations

| Step | What you should see |
|---|---|
| Ingest | Green success banner with Event ID and SHA-256 hash |
| Normalization | Row in Canonical Ledger with OCSF class, action, IPs |
| Trace Link | Evidence Vault modal with raw payload |
| Integrity | Green "VERIFIED" with matching hashes |
| Quarantine | Red `FAILED` row with JSONDecodeError reason |
| Replay | Event status changes to `NORMALIZED` / `RESOLVED` |
| Semantic | Two rows showing same token, different canonical meanings |
