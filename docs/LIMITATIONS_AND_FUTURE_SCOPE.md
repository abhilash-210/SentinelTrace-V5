# SentinelTrace V5 — Limitations & Future Scope

**SIH 2026 · PS 26156 · Universal Log Pre-processing Framework**

This document honestly describes the current limitations of the SentinelTrace V5 prototype and outlines the engineering work required to move toward production-scale deployment.

---

## Current Limitations

### 1. Single-Process Ingestion (Architecture)
**Status**: Known limitation of prototype design.

Log ingestion, parsing, and normalization all execute within the FastAPI application process using `BackgroundTasks`. This means the system processes one event at a time and there is no backpressure, queueing, or overflow management. Under high concurrent submission rates, API response times would degrade.

**Impact**: Cannot handle high-throughput log sources (e.g., >1,000 EPS) in the current design.

**Planned mitigation**: Async Celery workers or Apache Kafka consumer groups consuming from a partitioned event topic.

---

### 2. SQLite Local Database
**Status**: Intentional for prototype portability.

When PostgreSQL is unavailable (i.e., running outside Docker), the application auto-falls back to SQLite (`sentinel_trace.db`). SQLite does not support concurrent writes, row-level locking, or the JSONB type natively (shimmed via SQLAlchemy compiler hooks).

**Impact**: The SQLite fallback is not suitable for concurrent multi-user production use.

**Planned mitigation**: PostgreSQL + TimescaleDB for time-series partitioning of event tables.

---

### 3. Parser Coverage (3 Formats)
**Status**: Prototype scope.

Active parser modules:
- `SyslogParser` — RFC 5424, RFC 3164, Cisco ASA format
- `JSONParser` — Generic JSON key extraction
- `CSVParser` — CSV with header row detection

Not yet implemented: CEF (Common Event Format), Windows Event Log (EVTX/XML), LEEF (Log Event Extended Format), NetFlow, vendor-specific binary formats.

**Impact**: Logs from vendors using CEF or Windows Event Log formats cannot be normalized without a new parser module.

**Planned mitigation**: Additional source-pack parser modules. The `BaseParser` abstract class is designed for easy extension.

---

### 4. Throughput Not Benchmarked
**Status**: No load testing performed.

Events-per-second (EPS) capacity, memory consumption under load, and database write throughput have not been independently measured.

**Impact**: No performance guarantees can be stated.

**Planned mitigation**: Load testing with Apache JMeter or Locust against a PostgreSQL-backed Docker deployment.

---

### 5. In-Process Key Management
**Status**: Development configuration only.

JWT signing keys are stored as environment variables (`SECRET_KEY` in `.env`). This is acceptable for prototype and demo use, but does not meet production security standards.

**Impact**: Key rotation requires application restart.

**Planned mitigation**: Integration with HashiCorp Vault, AWS KMS, or Azure Key Vault for secret management and automated key rotation.

---

### 6. No Distributed Streaming Layer
**Status**: Planned.

The current SIEM output writes to a local JSONL file (`siem_stream.log`). There is no Kafka topic, Redis stream, or webhook push to an actual SIEM platform.

**Impact**: The JSONL file must be manually consumed by a downstream SIEM. There is no real-time push integration.

**Planned mitigation**: Kafka producer integration in `LogForwarderService`, with consumer configurations for Splunk HEC and Microsoft Sentinel.

---

### 7. No TLS / HTTPS in Local Dev
**Status**: Development configuration only.

The application runs over HTTP in development mode. Docker Compose does not configure TLS termination.

**Impact**: Credentials and tokens transmitted in plaintext on the network.

**Planned mitigation**: Nginx reverse proxy with TLS termination for any deployment outside localhost.

---

## Future Scope

The following engineering improvements are planned but not yet implemented. These are not presented as current capabilities.

### Near-Term (Prototype → Pilot)
- **Kafka ingestion**: Replace synchronous REST with async Kafka producers/consumers
- **PostgreSQL + TimescaleDB**: Optimized storage for time-series event partitioning
- **Additional parsers**: CEF, Windows Event Log, LEEF, NetFlow
- **Throughput benchmarking**: Load testing with EPS measurement

### Medium-Term (Pilot → Scalable)
- **Object storage for Data Lake**: AWS S3 / GCS / MinIO for Parquet partition storage
- **Distributed normalization workers**: Celery or Faust stream processors
- **Live SIEM push adapters**: Splunk HEC, Microsoft Sentinel, Elastic ECS
- **HSM key anchoring**: Production-grade secret management

### Long-Term (Scalable → Enterprise)
- **ML-based anomaly detection**: Train on normalized OCSF events from Parquet lake
- **Multi-tenancy**: Isolated schema-per-tenant in PostgreSQL
- **Geo-distributed deployment**: Active-active with conflict-free replicated data types (CRDTs) for the evidence ledger
- **Regulatory compliance packs**: Pre-built source profiles for PCI-DSS, HIPAA, NIS2 log requirements
