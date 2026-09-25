# SentinelTrace V5 — Final Project Report

**Project Title**: SentinelTrace V5 — Evidence-Preserving Universal Log Pre-processing Framework
**SIH Problem Statement**: PS 26156
**Track**: Cybersecurity
**Submission Year**: 2026

---

## 1. Executive Summary

SentinelTrace V5 is a prototype Universal Log Pre-processing Framework designed to address a critical gap in modern Security Operations Center (SOC) workflows: the absence of an evidence-preserving, format-agnostic log normalization pipeline. The system accepts heterogeneous security logs, cryptographically seals the raw payload before any transformation, extracts source-specific fields using format-aware parsers, maps known fields to an OCSF-aligned canonical schema, retains unmapped proprietary fields, validates processing results, and routes failures to an auditable quarantine queue with human-in-the-loop correction and replay. Validated normalized events are exported to a JSONL SIEM stream and Parquet Data Lake for downstream consumption by AI/ML frameworks or enterprise SIEMs.

---

## 2. SIH Problem Statement (PS 26156)

Modern SOCs face three compounding challenges:

1. **Format heterogeneity**: Firewalls, authentication gateways, servers, cloud services, and endpoints each emit logs in vendor-specific formats (Syslog, JSON, CSV, CEF, EVTX). Each format requires a custom parser, creating significant maintenance overhead.

2. **Evidence loss during normalization**: Traditional SIEM ingestion pipelines transform raw logs into structured records and discard the original payload. If a parser introduces an error, the forensic source is permanently lost.

3. **Silent data loss**: When a log cannot be parsed, most systems silently drop it. This creates gaps in security timelines that can hide intrusions.

---

## 3. Problem Analysis

| Problem | Impact |
|---|---|
| Proprietary vendor formats | Parser proliferation — one parser per format per vendor |
| Raw payload discarded after parsing | No forensic audit trail to original evidence |
| Malformed logs silently dropped | Gaps in security timelines |
| No universal field taxonomy | Cross-source correlation impossible without manual mapping |
| No source onboarding governance | Uncontrolled parser modifications create regression risks |

---

## 4. Objectives

1. Design and implement an evidence-first ingestion architecture that preserves raw payloads before any parsing.
2. Implement format-aware parser modules for Syslog, JSON, and CSV.
3. Normalize extracted fields into an OCSF-aligned canonical schema.
4. Preserve unmapped proprietary fields — zero forensic data loss.
5. Implement a Dead-Letter Queue (DLQ) for quarantine and human-corrected replay.
6. Maintain bidirectional traceability from normalized output to raw evidence.
7. Export normalized events for downstream SIEM and Data Lake integration.
8. Operate in offline and air-gapped environments.

---

## 5. Proposed Solution

SentinelTrace V5 enforces an **evidence-first, zero-loss normalization pipeline**:

- Every log is sealed with SHA-256 before parsing
- Parsing failures quarantine (never drop) the event
- All unmapped fields are preserved alongside canonical fields
- Every downstream artifact carries a foreign key to the original evidence
- Output is OCSF-aligned, Parquet-formatted, and SIEM-ready

---

## 6. System Architecture

See [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) for full component and data flow diagrams.

**Primary components:**
- **Frontend**: React 18 + Vite 5 SPA
- **Backend**: Python FastAPI REST API
- **Parsers**: SyslogParser, JSONParser, CSVParser
- **Database**: PostgreSQL (Docker) / SQLite (local fallback)
- **Export**: JSONL SIEM stream + Parquet Data Lake

---

## 7. End-to-End Data Flow

```
[Raw Log Source]
       │ POST /api/v1/ingest
       ▼
[Raw Content Stored Verbatim]
[SHA-256 Fingerprint Computed]
       │
       ▼
[Source Detector: format + type → parser selection]
       │
       ▼
[Parser: field extraction]
       │
       ├─ Parse OK ──► [OCSF Normalization]
       │                     │
       │               [Unmapped Preservation]
       │                     │
       │               [Confidence Scoring]
       │                     │
       │               [NORMALIZED] ──► JSONL + Parquet
       │
       └─ Parse FAIL ─► [Quarantine DLQ]
                             │
                         [Human Fix]
                             │
                         [Replay ──► Parser again]
                             │
                         [NORMALIZED]
```

---

## 8–11. Ingestion, Evidence Preservation, SHA-256, Parsing

### Ingestion Architecture
- Endpoint: `POST /api/v1/ingest`
- Auth: JWT Bearer + `EVIDENCE_INGEST` permission
- The `EventService.create_event()` method writes the complete raw payload to `IngestedEvent.raw_content`
- SHA-256 is computed using Python's `hashlib.sha256(raw_content.encode('utf-8')).hexdigest()`
- The hash is stored in `IngestedEvent.raw_content_hash` before any normalization

### Parser Architecture
Three parser classes inherit from `BaseParser`:

| Parser | Format | Key Extraction |
|---|---|---|
| `SyslogParser` | `text` | RFC 5424 header, Cisco ASA pattern, IP/port regex |
| `JSONParser` | `json` | `json.loads()` with field aliasing |
| `CSVParser` | `csv` | `csv.DictReader` with header detection |

Each parser returns: `{success, fields, timestamp, confidence_deductions}`.

---

## 12–13. Normalization & Unmapped Field Preservation

The `NormalizationService` performs:
1. Source detection (parser selection, profile lookup)
2. Parsing (calling the selected parser)
3. OCSF class classification:
   - Auth source → `class_uid=3001` (Authentication)
   - System source → `class_uid=1001` (System Activity)
   - Default → `class_uid=4001` (Network Activity)
4. Known field mapping to canonical columns
5. Unmapped field collection: `{k: v for k, v in fields.items() if k not in mapped_keys}`
6. Confidence scoring: starts at detected confidence, deducts for missing key fields
7. Status: `NORMALIZED` (≥0.70), `PARTIAL` (0.40–0.69), `FAILED` (<0.40 or parse error)

---

## 14–15. Source Profile Architecture

`SourceProfile` is a database-backed registry of source configurations:
- `source_name`, `source_type`, `file_format`, `vendor`, `product`
- Status lifecycle: `DRAFT` → `APPROVED` → `ACTIVE`
- Maker-Checker: approver cannot be the same user as creator
- The `SourceDetector` matches incoming events to active profiles

---

## 16–18. Validation, Quarantine, and Replay

- **Validation**: Confidence < threshold or parse failure triggers quarantine
- **Quarantine**: `QuarantineService.quarantine_event()` stores a `QuarantinedEvent` with:
  - `original_event_id` FK → raw evidence
  - `failure_reason` (parser error message)
  - `status: PENDING`
- **Replay**: `QuarantineService.replay_event()`:
  - Fetches original raw event by `original_event_id`
  - Applies the corrected content at parse time (original not mutated)
  - Runs normalization service again
  - Creates new `NormalizedEvent` on success
  - Updates quarantine record to `REPLAYED`

---

## 19. Traceability / Provenance

Every `NormalizedEvent` and `QuarantinedEvent` carries `original_event_id`, a foreign key to the immutable `IngestedEvent` record. The frontend "Trace Link" resolves this in a single API call to display the original raw payload alongside its SHA-256 hash. The live re-verification endpoint (`GET /api/v1/events/{event_id}/verify`) recomputes the hash on demand.

---

## 20–21. SIEM Output & Parquet Data Lake

- **JSONL forwarder**: `LogForwarderService.forward()` appends one JSON line per validated event to `backend/outputs/siem_stream.log`
- **Parquet export**: `ParquetExportService.export()` writes partitioned files to `backend/outputs/datalake/partition_date=YYYY-MM-DD/source_name=.../`
- Only `NORMALIZED` status events are forwarded — quarantined events are excluded

---

## 22–23. Offline & Container Deployment

- **Offline**: Zero external SaaS API calls in the critical path. Python `hashlib` is stdlib. SQLite auto-fallback.
- **Docker**: `docker-compose.yml` orchestrates PostgreSQL, FastAPI, and React/Nginx. `docker compose up --build` produces a fully isolated deployment.

---

## 24–25. Authentication & Maker-Checker Governance

- **Auth**: JWT tokens signed HMAC-SHA256, validated via `require_permission()` FastAPI dependency
- **RBAC**: 5 roles, 32 named permissions covering read, write, manage, approve operations
- **Maker-Checker**: Source profile activation and other privileged operations require `proposer_id ≠ approver_id`, enforced in service layer

---

## 26–29. Frontend, Backend, Database, and API Architecture

See [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) for detailed breakdowns.

---

## 30. Testing Strategy

35 test modules organized by sprint/feature. Tests use SQLite in-memory databases for isolation.

Core ULPF tests cover:
- Ingestion, SHA-256 hash computation, event ID generation
- Normalization pipeline (Syslog, JSON, CSV)
- Unmapped field retention
- Quarantine routing on parse failure
- Replay producing a new normalized event
- RBAC boundary enforcement
- SIEM forwarder and Parquet export

Full test command:
```powershell
cd backend
python -m unittest discover -s tests -p "test_*.py"
```

---

## 31. End-to-End Verification

Manually verified on the running prototype. See [`docs/TESTING_AND_VERIFICATION.md`](TESTING_AND_VERIFICATION.md) for the verification table.

---

## 32. SIH Requirement a–k Mapping

See [`docs/SIH_REQUIREMENT_MAPPING.md`](SIH_REQUIREMENT_MAPPING.md) for the complete table.

---

## 33. Demonstrated Prototype Capabilities

| Capability | Status |
|---|---|
| Syslog ingestion + SHA-256 | Demonstrated |
| JSON authentication event normalization | Demonstrated |
| CSV process audit normalization | Demonstrated |
| Quarantine on malformed JSON | Demonstrated |
| Human fix + replay to NORMALIZED | Demonstrated |
| Trace Link (normalized → raw) | Demonstrated |
| SHA-256 live re-verification | Demonstrated |
| JSONL SIEM stream append | Demonstrated |
| Parquet Data Lake partition | Demonstrated |
| Offline operation (no internet) | Demonstrated |
| Docker Compose startup | Implemented |

---

## 34. Limitations

See [`docs/LIMITATIONS_AND_FUTURE_SCOPE.md`](LIMITATIONS_AND_FUTURE_SCOPE.md) for full details.

Key limitations:
- Single-process ingestion (no distributed workers)
- SQLite fallback not suitable for concurrent high-volume production
- 3 active parsers (Syslog, JSON, CSV) — CEF and EVTX not yet implemented
- EPS throughput not benchmarked
- In-process key management (environment variables)

---

## 35. Future Scope

- Kafka ingestion workers
- PostgreSQL + TimescaleDB
- Additional parser modules (CEF, EVTX, LEEF)
- Live SIEM push adapters (Splunk HEC, Sentinel)
- Object storage for Data Lake
- Load benchmarking

---

## 36–38. Installation, Running, and Stopping

See the [README.md](../README.md) for complete installation and startup instructions.

**Quick start:**
```bat
start_app.bat
```

**Stop:**
```bat
stop_app.bat
```

---

## 39. Demonstration Workflow

See [`docs/DEMO_GUIDE.md`](DEMO_GUIDE.md) for the complete 5–10 minute judge demonstration sequence.

---

## 40. Conclusion

SentinelTrace V5 demonstrates that a zero-data-loss Universal Log Pre-processing Framework is achievable as a prototype using accessible open-source technologies (Python, FastAPI, SQLAlchemy, React). The core ULPF pipeline — ingest → preserve → parse → normalize → validate → quarantine/replay → export — is fully implemented and manually verified. The architecture is cleanly separated between evidence preservation, normalization, and output layers, making it straightforward to extend with additional parsers, output adapters, and distributed workers as the system scales toward production.
