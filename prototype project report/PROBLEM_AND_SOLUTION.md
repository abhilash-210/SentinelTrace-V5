# Problem Analysis & SentinelTrace V5 Solution

## The Heterogeneous Log Challenge
Modern enterprises generate terabytes of security logs daily across firewalls (Cisco, Palo Alto), endpoints (CrowdStrike, Defender), cloud platforms (AWS CloudTrail, GCP Audit), and identity providers (Okta, Azure AD).

### Key Problems:
1. **Inconsistent Log Schemas**: `src_ip`, `source_ip`, `src_address`, and `client_ip` all refer to the same field across different vendor formats.
2. **Format Chaos**: JSON, Syslog Key-Value, CSV, CEF, XML, and Windows Event Log formats require separate parsing scripts.
3. **Lack of Evidence Integrity**: Standard Syslog uses unencrypted UDP/TCP without cryptographic hashing. Adversaries who gain access to log servers can easily alter timestamps or erase evidence of intrusion.
4. **False Confidence in SOC Analytics**: Traditional SIEMs treat missing log streams as "0 alerts", leading to false clean reports.

## Original SIH Problem vs SentinelTrace V5 Final Prototype

| SIH Challenge Requirement | Core SentinelTrace Implementation | Extended Platform Capability |
|---|---|---|
| Ingest multi-vendor raw logs | Format-Agnostic Ingestion Engine (`IngestedEvent`) | Raw Evidence Vault with SHA-256 evidence hashing |
| Multi-format log parsing | Multi-Format Parser (`parsers/`) for JSON, Syslog, CSV, CEF | Automated pattern discovery & field extraction |
| Unified schema mapping | OCSF v1.1.0 & ECS Schema Mapping (`NormalizedEvent`) | Semantic Interpretation & Policy Registry |
| Log correlation & search | Incident & Case Management (`SecurityIncident`) | Threat Intel, Risk Correlation, & ATT&CK Mapping |
| Auditability | Governance Ledger (`GovernanceLedger`) | 17-Stage Cryptographic Provenance Chain (`SAS-YYYY-NNN`) |
