# SentinelTrace V5 — API Reference

**Base URL**: `http://localhost:8000`
**Authentication**: JWT Bearer Token — obtain via `POST /api/v1/auth/login`
**Documentation (Swagger UI)**: `http://localhost:8000/docs`
**OpenAPI JSON**: `http://localhost:8000/openapi.json`

All protected endpoints require:
```
Authorization: Bearer <access_token>
```

---

## Authentication

### POST /api/v1/auth/login
Authenticate and receive a JWT access token.

**Authentication required**: No

**Request body**:
```json
{
  "username": "admin_demo",
  "password": "SentinelDemo!2026"
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

---

## Health

### GET /api/v1/health
Check backend service health.

**Authentication required**: No

**Response** (200 OK):
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "0.1.0"
}
```

---

## Ingestion

### POST /api/v1/ingest
Preserve a raw security log event. SHA-256 fingerprint is computed before any parsing.

**Authentication required**: Yes — permission `EVIDENCE_INGEST`

**Request body**:
```json
{
  "source_name": "perimeter-fw-01",
  "source_type": "firewall",
  "file_format": "text",
  "raw_content": "<134>1 2026-09-06T12:00:01.120Z perimeter-fw-01 cisco-asa 4120 - - %ASA-6-302013: Built inbound TCP connection 982103 for outside:198.51.100.45/443 to inside:10.0.10.14/52140 action=ALLOW",
  "metadata": {
    "environment": "production",
    "zone": "perimeter-north"
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `source_name` | string | Yes | Identifier of the log source (e.g., hostname) |
| `source_type` | string | Yes | Category: `firewall`, `authentication`, `system`, etc. |
| `file_format` | string | Yes | `text` (syslog), `json`, or `csv` |
| `raw_content` | string | Yes | Verbatim raw log payload |
| `metadata` | object | No | Caller-supplied context key-value pairs |

**Response** (201 Created):
```json
{
  "event_id": "evt_3a9f8c1d7e2b04f6",
  "raw_content_hash": "60a6e3b2d9f1c4078a2e5d6b3f9a1c7e2d4b8f0a3c5e7d9b1f3a5c7e9d1b3f5",
  "ingested_at": "2026-09-25T12:00:01.120000Z",
  "processing_status": "PRESERVED",
  "source_name": "perimeter-fw-01"
}
```

---

## Raw Events

### GET /api/v1/events
List preserved raw events.

**Authentication required**: Yes — permission `EVIDENCE_READ`

**Query parameters**:
| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | integer | 50 | Max results per page |
| `offset` | integer | 0 | Pagination offset |
| `source_type` | string | — | Filter by source type |
| `file_format` | string | — | Filter by format |

**Response** (200 OK):
```json
{
  "items": [
    {
      "event_id": "evt_3a9f8c1d7e2b04f6",
      "source_name": "perimeter-fw-01",
      "source_type": "firewall",
      "file_format": "text",
      "processing_status": "NORMALIZED",
      "ingested_at": "2026-09-25T12:00:01Z",
      "raw_content_hash": "60a6e3..."
    }
  ],
  "total": 42,
  "limit": 50,
  "offset": 0
}
```

### GET /api/v1/events/{event_id}
Retrieve a specific raw event including its full payload.

**Authentication required**: Yes — permission `EVIDENCE_READ`

**Response** (200 OK): Full `IngestedEvent` object including `raw_content`.

### GET /api/v1/events/{event_id}/verify
Re-compute and verify the SHA-256 fingerprint of a raw event live.

**Authentication required**: Yes — permission `EVIDENCE_READ`

**Response** (200 OK):
```json
{
  "event_id": "evt_3a9f8c1d7e2b04f6",
  "stored_hash": "60a6e3...",
  "computed_hash": "60a6e3...",
  "integrity_status": "VERIFIED",
  "match": true
}
```

### GET /api/v1/events/stats
Live pipeline statistics for the dashboard.

**Authentication required**: Yes

**Response** (200 OK):
```json
{
  "total_events": 156,
  "normalized": 142,
  "quarantined": 8,
  "failed": 6,
  "normalization_rate": 0.91
}
```

---

## Normalization

### POST /api/v1/normalization/normalize-all
Trigger normalization for all `PRESERVED` events not yet normalized.

**Authentication required**: Yes — permission `NORMALIZATION_WRITE`

**Response** (200 OK):
```json
{
  "processed": 12,
  "normalized": 10,
  "quarantined": 2
}
```

### GET /api/v1/normalization/events
List canonical normalized events (OCSF-aligned ledger).

**Authentication required**: Yes — permission `NORMALIZATION_READ`

**Query parameters**: `limit`, `offset`, `source_type`, `status`

**Response** (200 OK):
```json
{
  "items": [
    {
      "normalized_event_id": "norm_7d2e1a3f9c5b4e8d",
      "original_event_id": "evt_3a9f8c1d7e2b04f6",
      "class_uid": 4001,
      "class_name": "Network Activity",
      "action": "ALLOW",
      "src_ip": "198.51.100.45",
      "src_port": 443,
      "dst_ip": "10.0.10.14",
      "dst_port": 52140,
      "protocol": "TCP",
      "severity": "Informational",
      "parser_name": "SyslogParser",
      "normalization_status": "NORMALIZED",
      "normalization_confidence": 0.85,
      "normalized_at": "2026-09-25T12:00:03Z"
    }
  ],
  "total": 142
}
```

---

## Quarantine (Dead-Letter Queue)

### GET /api/v1/quarantine
List quarantined events awaiting human correction.

**Authentication required**: Yes — permission `QUARANTINE_READ`

**Response** (200 OK): List of quarantined events with `failure_reason` and `status`.

### POST /api/v1/quarantine/replay
Submit a corrected payload to replay a quarantined event through the normalization pipeline.

**Authentication required**: Yes — permission `QUARANTINE_MANAGE`

**Request body**:
```json
{
  "quarantine_id": "dlq_1a2b3c4d5e6f7a8b",
  "corrected_content": "{\"timestamp\": \"2026-09-06T12:05:30Z\", \"event_type\": \"AUTH_FAILURE\", ...}",
  "resolution_notes": "Fixed missing closing brace in JSON payload"
}
```

**Response** (200 OK):
```json
{
  "quarantine_id": "dlq_1a2b3c4d5e6f7a8b",
  "replay_status": "NORMALIZED",
  "new_normalized_event_id": "norm_8e3f2b1a9d7c5e4f",
  "normalization_confidence": 0.90
}
```

---

## Source Profiles

### GET /api/v1/source-profiles
List all registered source profiles.

**Authentication required**: Yes — permission `SOURCE_PROFILE_READ`

**Response** (200 OK): List of `SourceProfile` records with `status` (`DRAFT`, `APPROVED`, `ACTIVE`).

### POST /api/v1/source-profiles
Register a new source profile.

**Authentication required**: Yes — permission `SOURCE_PROFILE_WRITE`

### POST /api/v1/source-profiles/{profile_id}/approve
Approve a DRAFT profile (requires different user from creator — Maker-Checker).

**Authentication required**: Yes — permission `SOURCE_PROFILE_APPROVE`

---

## Export

### GET /api/v1/export/parquet
Trigger a Parquet Data Lake batch export of all normalized events.

**Authentication required**: Yes — permission `EXPORT_WRITE`

**Response** (200 OK):
```json
{
  "exported_count": 142,
  "output_path": "outputs/datalake/partition_date=2026-09-25/",
  "format": "parquet"
}
```

### GET /api/v1/forwarder/status
Check SIEM JSONL forwarder status and record count.

**Authentication required**: Yes

---

## Error Responses

All endpoints return standard error envelopes:

```json
{
  "detail": "Human-readable error message"
}
```

| HTTP Code | Meaning |
|---|---|
| 400 | Bad request — validation or business logic error |
| 401 | Missing or invalid JWT token |
| 403 | Token valid but insufficient permissions |
| 404 | Resource not found |
| 422 | Pydantic validation failure (request body schema mismatch) |
| 500 | Unexpected server error |
