# SentinelTrace V5: Project Overview

## Executive Summary
SentinelTrace V5 is a zero-trust, verifiable security intelligence platform built to eliminate log format chaos in modern Security Operations Centers (SOCs). By pairing multi-format log ingestion with Open Cybersecurity Schema Framework (OCSF v1.1.0) normalization and a 17-stage SHA-256 cryptographic lineage chain, SentinelTrace provides immutable auditability and mathematical confidence to enterprise security telemetry.

## Key Target Users & Personas
1. **Security Analysts (SOC L1/L2)**: Triage normalized events, run threat intelligence correlation, and manage investigation cases.
2. **Security Reviewers (SOC L3/Lead)**: Enforce Maker-Checker governance, approve detection rule versions, authorize incident containment, and sign off on remediation plans.
3. **Compliance Auditors**: Inspect append-only governance ledgers, review NIST/ISO/SOC2 control effectiveness, and verify Merkle proof chains.
4. **CISO & Executive Management**: View point-in-time security posture dashboards (`SAS-YYYY-NNN`), executive analytics, and verified multi-template security reports.

## Core Technical Differentiators
- **OCSF & ECS Alignment**: Standardized schema transformation for 100% vendor-agnostic log interpretation.
- **17-Stage Cryptographic Provenance Chain**: Every stage output is hashed and linked to the previous stage hash, rendering log tampering immediately detectable.
- **Zero-Trust Telemetry Rules**: Score capping logic ensures missing or unverified data degrades overall trust scores rather than fabricating a clean status.
- **Maker-Checker Governance**: Dual approval required for all administrative mutations (proposer != approver).
