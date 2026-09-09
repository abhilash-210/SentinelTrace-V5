# Database Architecture Reference

## Schema Design & Isolation
All ORM models reside in the `sentinel` schema using SQLAlchemy 2.0.

## Primary Data Models (`backend/app/models/`)
1. `IngestedEvent` (`sentinel.ingested_events`): Stores raw log string, source name, format, and initial `raw_content_hash`.
2. `NormalizedEvent` (`sentinel.normalized_events`): Stores OCSF event class, activity ID, category, normalized JSON payload, and `normalized_hash`.
3. `SecurityIncident` (`sentinel.security_incidents`): Incident tracking with severity, status, entity score, and containment requests.
4. `InvestigationCase` (`sentinel.investigation_cases`): Forensic cases binding hypotheses, findings, and timeline events.
5. `SecurityAnalyticsSnapshot` (`sentinel.security_analytics_snapshots`): Point-in-time analytics snapshot (`SAS-YYYY-NNN`) with overall confidence, security score, and SHA-256 seal.
6. `SecurityAnalyticsProvenanceRecord` (`sentinel.security_analytics_provenance_records`): 17-stage cryptographic lineage records linking stage current hash to previous hash.
7. `GovernanceLedger` (`sentinel.governance_ledger`): Append-only audit block chain.
