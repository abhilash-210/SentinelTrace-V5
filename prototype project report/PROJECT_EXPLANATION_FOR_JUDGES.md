# Project Defense Q&A for SIH Judges

## Top Judge Questions & Technical Answers

### Q1: How is SentinelTrace different from a standard SIEM like Splunk or QRadar?
**Answer**: Traditional SIEMs index text logs and evaluate alerts, but do not provide mathematical proof of evidence provenance or tamper detection. SentinelTrace hashes raw events upon ingestion and maintains a 17-stage cryptographic lineage chain. Furthermore, SentinelTrace enforces zero-trust telemetry rules (missing data degrades trust score) and Maker-Checker dual governance for rule/remediation approvals.

### Q2: Why choose OCSF for log normalization?
**Answer**: Open Cybersecurity Schema Framework (OCSF v1.1.0) is an open-source, vendor-agnostic industry standard backed by AWS, Cloudflare, and major security vendors. It provides standard categories, event classes, and attribute naming, eliminating custom parser re-writes for every new device.

### Q3: What happens if an attacker modifies a stored log in the database?
**Answer**: Every event and report section is sealed with a canonical SHA-256 hash. When a verification check is triggered, SentinelTrace recalculates the canonical hash. Any 1-bit alteration breaks the hash chain, causing the verification engine to mark the asset as `UNTRUSTED` and pinpoint the exact tampered section.
