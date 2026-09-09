# Exhaustive Module Reference

## Core Modules & Services

### 1. Ingestion & Normalization (`NormalizationService`)
Parses Syslog, JSON, CSV, and CEF logs into standard OCSF v1.1.0 event structures.

### 2. Detection & Trust Engine (`DetectionRuleService`, `DetectionRuleTrustService`)
Evaluates detection rules against normalized events and tracks historical false-positive rates to adjust rule trust metrics.

### 3. Threat Intelligence (`ThreatIntelService`)
Ingests IOC indicators (IPs, hashes, domain names), normalizes threat feeds, and correlates observed entity behavior.

### 4. Incident & Case Management (`SecurityIncidentService`, `SecurityInvestigationService`)
Manages security incidents (`inc_...`) and forensic investigation cases (`arc_...`), binding hypotheses, timeline events, and findings.

### 5. Security Analytics & Reporting (`SecurityAnalyticsService`, `SecurityReportingService`)
Evaluates 15 security domains, generates point-in-time snapshots (`SAS-YYYY-NNN`), synthesizes 7 executive report types, and builds reference-only evidence packages (`SEP-YYYY-NNN`).

### 6. Cryptographic Provenance (`SecurityAnalyticsProvenanceService`)
Maintains the 17-stage cryptographic lineage chain, verifying hash integrity from raw log capture to final executive report.
