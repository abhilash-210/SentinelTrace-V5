# SentinelTrace V5 — Sprint 2 Freeze Declaration

**Sprint**: Sprint 2 — Source Parsing & OCSF-Aligned Normalization  
**Status**: **FROZEN (PASS)**  
**Date**: September 6, 2026  

---

## Freeze Statement

> **SPRINT 2 IS FROZEN.**  
> Future sprint features (Semantic Policy Registry, drift detection, dual-control approvals, cryptographic ledger, STIG graph propagation) must build ON TOP of Sprint 2 canonical events without modifying the underlying parser interfaces, raw evidence preservation, or database schema.

---

## Frozen Architecture & Interfaces

1. **Parser Interface (`BaseParser`)**:
   - `parse(raw_content: str, metadata: dict) -> dict`
   - Parsers: `SyslogParser`, `JSONParser`, `CSVParser` (v1.0.0).

2. **Source Profile Table (`sentinel.source_profiles`)**:
   - Seeded baseline: `sp_firewall_syslog`, `sp_app_json`, `sp_system_csv`.

3. **Canonical Normalized Event Model (`sentinel.normalized_events`)**:
   - OCSF-aligned classes: `Network Activity` (4001), `Authentication` (3001), `System Activity` (1001).
   - Mandatory `original_event_id` reference to Evidence Vault.

4. **Normalization API Routes**:
   - `POST /api/v1/events/{event_id}/normalize`
   - `GET /api/v1/normalized-events`
   - `GET /api/v1/normalized-events/{normalized_event_id}`
   - `GET /api/v1/events/{event_id}/normalization`
   - `GET /api/v1/source-profiles`

5. **Database Migration Baseline**:
   - Alembic migration `a1b2c3d4e5f6_create_normalization_tables` is stamped at head.

---

## Verification Summary

- **Automated Tests**: 18/18 Passing (Sprint 1 + Sprint 2)
- **Docker Compose Status**: Healthy (`sentinel-trace-backend`, `sentinel-trace-db`, `sentinel-trace-frontend`)
- **Evidence Files**: Genuine runtime screenshots and logs recorded in `evidence/sprint-02/`.

**Signed Off**: Lead Software Architect & Cybersecurity Engineering Team, SentinelTrace V5
