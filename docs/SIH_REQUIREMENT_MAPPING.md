# SentinelTrace V5 — SIH PS 26156 Requirement Mapping

**Problem Statement:** PS 26156 — Universal Log Pre-processing Framework (ULPF)

This document maps every stated SIH requirement to the corresponding SentinelTrace V5 implementation, with references to specific source files and observable evidence.

---

## Requirement Mapping Table

| Req | Requirement Description | Status | SentinelTrace Implementation |
|---|---|---|---|
| **a** | Preserve the complete raw event data | ✅ Implemented | Raw payload stored verbatim in `IngestedEvent.raw_content` (PostgreSQL TEXT / SQLite TEXT). SHA-256 hash computed from the raw string before any parsing (`IngestedEvent.raw_content_hash`). The raw record is never updated after creation. |
| **b** | Extract and parse source-specific attributes | ✅ Implemented | Three parser modules: `backend/app/parsers/syslog_parser.py` (Syslog RFC 5424, RFC 3164, Cisco ASA), `backend/app/parsers/json_parser.py`, `backend/app/parsers/csv_parser.py`. Parser selected by `SourceDetector` based on `source_type` and `file_format`. |
| **c** | Normalize fields into a common event taxonomy | ✅ Implemented | `NormalizationService` maps extracted fields to OCSF-aligned columns: `class_uid` (1001 System Activity, 3001 Authentication, 4001 Network Activity), `action`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `user_name`, `hostname`, `severity`, `process_name`. |
| **d** | Maintain traceability to original events | ✅ Implemented | `NormalizedEvent.original_event_id` is a foreign key to `IngestedEvent.event_id`. `QuarantinedEvent.original_event_id` maintains the same link. The UI "Trace Link" resolves this FK to display the original raw payload. |
| **e** | Plug-and-play / extensible source onboarding | ✅ Implemented | `SourceProfile` ORM model (`backend/app/models/source_profile.py`). New sources registered via API (`POST /api/v1/source-profiles`) without modifying parser code. Draft → Approved → Active governance pipeline. |
| **f** | Unified visibility | ✅ Implemented | React Dashboard (`frontend/src/pages/Dashboard.jsx`) polls `GET /api/v1/events/stats` for live pipeline statistics: total ingested, total normalized, total quarantined, normalization success rate. |
| **g** | SIEM / Data Lake integration | ✅ Implemented | `LogForwarderService` appends validated normalized events to `backend/outputs/siem_stream.log` (newline-delimited JSON). `ParquetExportService` writes partitioned Parquet files to `backend/outputs/datalake/partition_date=.../source_name=.../`. |
| **h** | AI/ML-ready analytics output | ✅ Implemented | Parquet output uses columnar format with typed fields (timestamps, IPs, actions, confidence scores). Immediately consumable by pandas, PySpark, or scikit-learn. |
| **i** | Reduced parser development effort | ✅ Implemented | Source Profiles decouple source metadata (name, type, format) from parser logic. Adding a new JSON source requires only a new `SourceProfile` record — no new Python code. The three existing parsers cover the format space; source-specific field mapping is handled declaratively. |
| **j** | Offline / air-gapped deployment | ✅ Implemented | Zero external SaaS API calls in the production code path. All cryptographic operations use Python's built-in `hashlib`. Runs entirely on localhost. Docker Compose bundles all dependencies. |
| **k** | Optional container packaging | ✅ Implemented | `backend/Dockerfile`, `frontend/Dockerfile`, `docker-compose.yml` at repository root. Deploys PostgreSQL, FastAPI backend, and React/Nginx frontend with a single `docker compose up --build`. |

---

## Evidence References

### Requirement a — Raw Event Preservation
- **Model**: [`backend/app/models/normalized_event.py`](../backend/app/models/normalized_event.py) — `IngestedEvent` class
- **Service**: [`backend/app/services/event_service.py`](../backend/app/services/event_service.py) — `create_event()` method
- **Router**: [`backend/app/routers/ingest.py`](../backend/app/routers/ingest.py) — `POST /api/v1/ingest`
- **Observable**: Submit any event via the Evidence Vault UI → see SHA-256 in the success banner → click Inspect → see raw payload unchanged

### Requirement b — Source-Specific Parsing
- **Parsers**: [`backend/app/parsers/`](../backend/app/parsers/)
- **Source Detector**: [`backend/app/services/source_detector.py`](../backend/app/services/source_detector.py)
- **Observable**: Submit a Cisco ASA Syslog → after normalization, see `src_ip` and `dst_ip` extracted from the `outside:IP/port to inside:IP/port` pattern

### Requirement c — Common Taxonomy
- **Service**: [`backend/app/services/normalization_service.py`](../backend/app/services/normalization_service.py) — Steps 5–7
- **Observable**: OCSF Normalization ledger shows `class_name`, `action`, `src_ip`, `dst_ip` in unified columns regardless of input format

### Requirement d — Traceability
- **Model**: `NormalizedEvent.original_event_id` FK
- **Router**: [`backend/app/routers/normalization.py`](../backend/app/routers/normalization.py) — `GET /normalization/events/{id}/trace`
- **Observable**: Click "Trace Link ➔" on any normalized event → Evidence Vault modal opens with the original raw payload

### Requirement e — Source Onboarding
- **Model**: [`backend/app/models/source_profile.py`](../backend/app/models/source_profile.py)
- **Router**: [`backend/app/routers/source_profiles.py`](../backend/app/routers/source_profiles.py)
- **Observable**: Normalization UI → Source Profile Registry tab shows seeded profiles

### Requirement f — Unified Visibility
- **Frontend**: [`frontend/src/pages/Dashboard.jsx`](../frontend/src/pages/Dashboard.jsx)
- **Router**: [`backend/app/routers/events.py`](../backend/app/routers/events.py) — pipeline stats endpoint
- **Observable**: Dashboard cards show live counts updated in real-time

### Requirement g — SIEM / Data Lake
- **Service**: [`backend/app/services/log_forwarder_service.py`](../backend/app/services/log_forwarder_service.py)
- **Service**: [`backend/app/services/parquet_export_service.py`](../backend/app/services/parquet_export_service.py)
- **Router**: [`backend/app/routers/export.py`](../backend/app/routers/export.py)
- **Observable**: After normalization, check `backend/outputs/siem_stream.log` (JSONL) and `backend/outputs/datalake/` (Parquet)

### Requirement h — AI/ML Ready
- **Observable**: Open a `.parquet` file from `backend/outputs/datalake/` in Python: `import pandas as pd; pd.read_parquet('...')`

### Requirement j — Offline Operation
- **Config**: [`backend/app/database.py`](../backend/app/database.py) — SQLite fallback logic
- **Config**: [`backend/app/config.py`](../backend/app/config.py) — no external URLs
- **Observable**: Disconnect from internet → application continues to function normally

### Requirement k — Container Packaging
- **Files**: [`docker-compose.yml`](../docker-compose.yml), [`backend/Dockerfile`](../backend/Dockerfile), [`frontend/Dockerfile`](../frontend/Dockerfile)
- **Observable**: `docker compose up --build` starts all three services
