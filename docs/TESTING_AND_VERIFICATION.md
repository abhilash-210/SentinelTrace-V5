# SentinelTrace V5 — Testing & Verification

**SIH 2026 · PS 26156 · Universal Log Pre-processing Framework**

This document describes the test architecture, how to run tests, and what has been verified through automated tests and manual end-to-end verification.

---

## Test Architecture

All automated tests are located in `backend/tests/`. The test suite is organized by sprint/feature module.

```
backend/tests/
├── auth_helper.py                        # Shared JWT token helpers for all tests
│
├── # ULPF Core Tests ─────────────────────────────────────────
├── test_sprint1_ingestion.py             # Raw event ingestion, SHA-256, traceability
├── test_sprint2_normalization.py         # OCSF normalization, field mapping
├── test_sprint2_validation.py            # Validation engine and confidence scoring
├── test_sprint2c_quarantine.py           # Quarantine DLQ and replay
├── test_sprint5_simulator.py             # Telemetry simulator API integration
├── test_sprint6d_source_profiles.py      # Source profile CRUD and governance
├── test_sprint7_siem_forwarder.py        # JSONL SIEM output
├── test_sprint8_dashboard.py             # Pipeline stats API
├── test_sprint9_parquet_export.py        # Parquet Data Lake export
│
├── # Security & Governance Tests ─────────────────────────────
├── test_sprint3_semantic_registry.py     # Semantic policy registry
├── test_sprint3b_semantic_interpretation.py
├── test_sprint3c_semantic_governance.py
├── test_sprint4a_identity_rbac.py        # RBAC and role enforcement
├── test_sprint4b_dual_control.py         # Maker-Checker governance
├── test_sprint5a_cryptographic_ledger.py # SHA-256 ledger and chain
├── test_sprint5b_merkle_proofs.py        # Merkle tree verification
│
├── # Detection & Intelligence Tests ───────────────────────────
├── test_sprint6a_detection_rules.py
├── test_sprint6b_detection_rule_trust.py
├── test_sprint6c_detection_rule_governance.py
├── test_sprint7a_detection_execution.py
├── test_sprint7b_risk_remediation.py
├── test_sprint8a_security_incidents.py
├── test_sprint8b_incident_response_governance.py
├── test_sprint9a_security_assurance.py
├── test_sprint9b_assurance_remediation.py
├── test_sprint10a_executive_security_intelligence.py
├── test_sprint10b_security_scenario_orchestration.py
├── test_sprint11a_compliance_intelligence.py
├── test_sprint11b_threat_intelligence.py
├── test_sprint12a_security_investigations.py
├── test_sprint12b_security_analytics.py
└── test_sprint13_final_hardening.py      # Full security hardening suite
```

---

## Running Tests

### Setup

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Run ULPF Core Tests Only

```powershell
python -m pytest tests/test_sprint1_ingestion.py `
                 tests/test_sprint2_normalization.py `
                 tests/test_sprint2_validation.py `
                 tests/test_sprint2c_quarantine.py `
                 tests/test_sprint6d_source_profiles.py `
                 tests/test_sprint7_siem_forwarder.py `
                 tests/test_sprint8_dashboard.py `
                 tests/test_sprint9_parquet_export.py -v
```

### Run Full Regression Suite

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

---

## Test Environment Notes

The test suite uses SQLite in-memory databases (`DATABASE_URL=sqlite:///:memory:`) for test isolation. Some PostgreSQL-specific type behaviors (JSONB, schema namespacing with `sentinel.`) are shimmed via SQLAlchemy compiler overrides in `database.py`.

Tests that exercise PostgreSQL-specific features may show skip warnings in SQLite mode. This is expected. The application code itself functions correctly when connected to PostgreSQL via Docker Compose.

---

## What is Verified by Automated Tests

### Sprint 1 — Ingestion & Evidence Preservation
- `POST /api/v1/ingest` accepts valid payloads
- SHA-256 hash is computed and matches expected value for known input
- Event ID format is correct (`evt_` prefix)
- Empty `raw_content` returns HTTP 400
- Unauthenticated requests return HTTP 401
- Requests without `EVIDENCE_INGEST` permission return HTTP 403
- `GET /api/v1/events/{event_id}/verify` returns `VERIFIED` for unmodified records

### Sprint 2 — Normalization
- Syslog payload (`perimeter-fw-01`) normalizes to `class_uid=4001` (Network Activity)
- JSON authentication event normalizes to `class_uid=3001` (Authentication)
- CSV system event normalizes to `class_uid=1001` (System Activity)
- `normalization_status` is `NORMALIZED` when confidence ≥ 0.70
- `normalization_status` is `PARTIAL` when confidence is 0.40–0.69
- Unmapped fields are stored in `unmapped_data` column, not discarded
- `original_event_id` FK is present on every normalized event

### Sprint 2c — Quarantine & Replay
- Malformed JSON event is quarantined rather than dropped
- `QuarantinedEvent.original_event_id` links back to the original `IngestedEvent`
- Corrected payload can be submitted via replay endpoint
- Replay creates a new `NormalizedEvent` with `NORMALIZED` status
- Original `IngestedEvent.raw_content` is unchanged after replay

### Sprint 6d — Source Profiles
- Source profiles can be created in `DRAFT` status
- Profiles require approval before activation (Maker-Checker)
- Same user cannot both propose and approve a profile
- Active profiles are used by the Source Detector

### Sprint 7 — SIEM Forwarder
- Normalized events are appended to `outputs/siem_stream.log`
- Each line is valid JSON (newline-delimited)
- Quarantined/failed events are excluded from SIEM output

### Sprint 8 — Dashboard
- `GET /api/v1/events/stats` returns correct aggregated counts
- Counts increment correctly as events are ingested and normalized

### Sprint 9 — Parquet Export
- Parquet export creates files in `outputs/datalake/partition_date=.../`
- Files are partitioned by `partition_date` and `source_name`
- Files can be read with `pandas.read_parquet()`

### Sprint 4a — RBAC
- 5 roles enforced on protected endpoints
- `VIEWER` role cannot write events
- `ADMIN` role has all permissions
- Invalid tokens return HTTP 401, insufficient roles return HTTP 403

### Sprint 13 — Security Hardening
- Maker-Checker invariant: `proposer_id != approver_id` enforced
- SHA-256 hash chain integrity verified across multiple events
- Boundary-case payloads (empty string, very large payload, unicode) handled gracefully

---

## End-to-End Manual Verification (Verified on Running Prototype)

The following workflow was manually verified on the local running application:

| Step | Action | Observed Result |
|---|---|---|
| 1 | `POST /api/v1/ingest` with Cisco ASA Syslog | `event_id` + `raw_content_hash` returned; status `PRESERVED` |
| 2 | `POST /api/v1/normalization/normalize-all` | Event normalized; `class_uid=4001`, `action=ALLOW`, `src_ip` extracted |
| 3 | `GET /api/v1/events/{id}/verify` | `integrity_status: VERIFIED`, `match: true` |
| 4 | `GET /api/v1/normalization/events` | Trace link resolves `original_event_id` to raw record |
| 5 | `POST /api/v1/ingest` with malformed JSON | Preserved; SHA-256 computed |
| 6 | `POST /api/v1/normalization/normalize-all` | Event quarantined; `status: PENDING` in DLQ |
| 7 | `POST /api/v1/quarantine/replay` with corrected JSON | New `NormalizedEvent` created; DLQ status `REPLAYED` |
| 8 | Check `backend/outputs/siem_stream.log` | JSONL line appended for each normalized event |
| 9 | `GET /api/v1/export/parquet` | Parquet files created in `backend/outputs/datalake/` |
| 10 | Disconnect network, restart application | Application runs normally without internet |

---

## Known Test Limitations

1. **SQLite schema translation**: PostgreSQL schema-prefixed queries (`sentinel.table_name`) are translated at runtime. In edge cases, cross-schema joins behave differently under SQLite than PostgreSQL.

2. **Parallel test isolation**: Tests that share the SQLite in-memory engine may fail when run in parallel due to schema initialization ordering. Run with `--no-header -p no:randomly` if using pytest-randomly.

3. **Parquet test dependency**: `test_sprint9_parquet_export.py` requires `pyarrow` to be installed. On some systems, this requires a C compiler. Pre-built wheels are available for Python 3.11 and 3.12.

4. **Extended intelligence tests**: Sprint 10–13 tests exercise the downstream security intelligence suite. Some of these use mock data fixtures and may not reflect production database constraints.
