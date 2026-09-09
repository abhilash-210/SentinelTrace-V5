# SentinelTrace V5 — Sprint 2 Completion Report

**Sprint Name**: Sprint 2 — Source Parsing & OCSF-Aligned Normalization  
**Architecture Version**: V5  
**Evaluation Status**: **PASS (100% Verified at Runtime)**  
**Date**: September 6, 2026  

---

## 1. Sprint Objective

Transform heterogeneous security logs (Syslog, structured JSON, CSV audit trails) preserved in the Evidence Vault into an OCSF-aligned canonical event taxonomy while maintaining strict, bidirectional cryptographic traceability back to the original raw evidence.

> **Architectural Standard**:  
> `OCSF-aligned canonical normalization for MVP demonstration.`  
> Raw evidence in the Evidence Vault remains 100% immutable throughout the entire parsing and normalization pipeline.

---

## 2. Architecture Implemented

The normalization engine follows a deterministic 5-stage pipeline:

```
[ 1. RAW EVIDENCE VAULT ]
          ↓
[ 2. SOURCE DETECTION ] ── Evaluates format, source_type, and structure
          ↓
[ 3. FORMAT PARSER ]    ── SyslogParser / JSONParser / CSVParser
          ↓
[ 4. CANONICAL MAPPING] ── Maps to OCSF Classes (4001, 3001, 1001)
          ↓
[ 5. CANONICAL EVENT ]  ── Persisted with confidence & original_event_id link
```

---

## 3. Parsers Implemented

1. **Syslog Parser (`SyslogParser` v1.0.0)**:
   - Formats: Cisco ASA, RFC 5424, RFC 3164, key-value syslog.
   - Extracted Attributes: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `action` (`ALLOW`/`DENY`/`CLOSE`), `hostname`, `severity`, `timestamp`.
2. **JSON Parser (`JSONParser` v1.0.0)**:
   - Formats: Structured JSON security events (IAM, cloud audit, API gateway).
   - Extracted Attributes: `timestamp`, `service`, `event_type`/`action` (`SUCCESS`/`FAILURE`), `client_ip`/`src_ip`, `user_name`, `session_id`, `metadata`.
3. **CSV Parser (`CSVParser` v1.0.0)**:
   - Formats: Comma-separated system audit & endpoint logs.
   - Extracted Attributes: `timestamp`, `hostname`, `process_name`, `process_id`, `user_name`, `action`.

---

## 4. Source Profiles

Seeded 3 structural Source Profiles in PostgreSQL (`sentinel.source_profiles`):
1. `sp_firewall_syslog` — Generic Firewall Syslog (`text` / `syslog` -> `SyslogParser`)
2. `sp_app_json` — Generic Application JSON Log (`json` -> `JSONParser`)
3. `sp_system_csv` — Generic System CSV Audit Log (`csv` -> `CSVParser`)

*Note: Source profiles represent structural extraction rules only. Semantic meaning policies are intentionally deferred to Sprint 3.*

---

## 5. OCSF-Aligned Canonical Mapping

Canonical schema classifications implemented:
- **Class 4001 (`Network Activity`)**: Firewall connection logs, traffic allowed/denied, TCP/UDP endpoints.
- **Class 3001 (`Authentication`)**: Logon events, user session activities, authentication failures/successes.
- **Class 1001 (`System Activity`)**: Process executions, host daemon audit events, command executions.

---

## 6. API Endpoints Verified

| Method | Endpoint | Description | Status Code |
|---|---|---|---|
| `POST` | `/api/v1/events/{event_id}/normalize` | Normalize one preserved raw event (idempotent) | `200 OK` |
| `GET` | `/api/v1/normalized-events` | List paginated canonical normalized events | `200 OK` |
| `GET` | `/api/v1/normalized-events/{normalized_event_id}` | Retrieve full normalized canonical event details | `200 OK` |
| `GET` | `/api/v1/events/{event_id}/normalization` | Bidirectional traceability report (raw hash ➔ normalized ID) | `200 OK` |
| `GET` | `/api/v1/source-profiles` | List active structural source profiles | `200 OK` |

---

## 7. Database Schema Changes

- **Schema**: `sentinel`
- **Migration**: Alembic revision `a1b2c3d4e5f6_create_normalization_tables.py` (stamped at head)
- **New Tables**:
  - `sentinel.source_profiles` (Indexed on `source_profile_id`, `source_type`)
  - `sentinel.normalized_events` (Indexed on `normalized_event_id`, `original_event_id`, `class_name`, `normalization_status`, `normalized_at`)

---

## 8. Automated Test Results

- **Suite**: [backend/tests/test_sprint2_normalization.py](file:///d:/SIH%202026/SENTINEL-TRACE/backend/tests/test_sprint2_normalization.py) + [backend/tests/test_sprint1_ingestion.py](file:///d:/SIH%202026/SENTINEL-TRACE/backend/tests/test_sprint1_ingestion.py)
- **Total Tests Executed**: 18
- **Passed**: 18
- **Failed**: 0
- **Duration**: 0.359s

| Test ID | Test Description | Result |
|---|---|---|
| Sprint 2 - T1 | Syslog parser extracts network, action, and header fields | **PASS** |
| Sprint 2 - T2 | JSON parser extracts structured authentication fields | **PASS** |
| Sprint 2 - T3 | CSV parser extracts system process audit fields | **PASS** |
| Sprint 2 - T4 | Normalization strictly links back to `original_event_id` | **PASS** |
| Sprint 2 - T5 | Normalized event record is successfully persisted in PostgreSQL | **PASS** |
| Sprint 2 - T6 | Missing fields remain None/null (no data fabrication) | **PASS** |
| Sprint 2 - T7 | Malformed input fails safely with appropriate status | **PASS** |
| Sprint 2 - T8 | Deterministic confidence scoring correctly computes penalties | **PASS** |
| Sprint 2 - T9 | Repeated normalization is idempotent (returns existing record) | **PASS** |
| Sprint 2 - T10 | Raw evidence in Evidence Vault remains completely immutable | **PASS** |
| Sprint 1 - T1..T8 | Full Sprint 1 regression suite (8 tests) | **PASS (8/8)** |

---

## 9. Traceability & Integrity Verification

- When an event is normalized, its `original_event_id` directly maps to the Evidence Vault record in `sentinel.ingested_events`.
- Raw evidence content and SHA-256 fingerprints remain unmodified after normalization.
- Live cryptographic integrity audits (`GET /api/v1/events/{id}/verify`) continue to return `VERIFIED`.

---

## 10. Real Runtime Evidence Captured

### Screenshots (`evidence/sprint-02/screenshots/`):
- `01_raw_to_normalized_pipeline.png` — Main Normalization dashboard & pipeline flow
- `02_syslog_normalization.png` — Network Activity normalized from Cisco ASA syslog
- `03_json_normalization.png` — Authentication event normalized from structured JSON
- `04_csv_normalization.png` — System Activity event normalized from tabular CSV
- `05_traceability_view.png` — Dual-pane Evidence Vault ➔ Canonical OCSF audit modal
- `06_api_normalization.png` — FastAPI Swagger UI interactive documentation
- `07_database_normalized_events.png` — Normalized events ledger table view
- `08_docker_services.png` — Health check endpoint and container verification

### Verification Logs (`evidence/sprint-02/logs/`):
- `automated-tests.txt` (Full 18-test runner output)
- `normalization-api-test.txt` (Live 3-format normalization output)
- `idempotency-test.txt` (Repeat execution confirmation)
- `traceability-test.txt` (Bidirectional link report)
- `docker-services-status.txt` (Docker Compose health status)

---

## 11. Known Limitations & Architectural Honesty

1. **OCSF Scope**: This implementation represents an OCSF-aligned canonical subset for MVP hackathon demonstration, not an official OCSF certification.
2. **Structural vs Semantic**: Source Profiles in Sprint 2 manage structural extraction only. Semantic equivalence governance (e.g. mapping vendor status codes to high-level policies) is intentionally deferred to Sprint 3.
3. **Deterministic Heuristics**: Confidence scores are calculated using deterministic penalty heuristics (missing timestamp, unknown profile, unparseable attributes), not machine learning.

---

## 12. Sprint Outcome

- **Sprint 2 Build Status**: **PASS**
- **Docker Services**: **HEALTHY**
- **Automated Tests**: **18/18 PASS**
- **Sprint 2 Frozen**: **YES**
- **Ready for Sprint 3**: **YES**
