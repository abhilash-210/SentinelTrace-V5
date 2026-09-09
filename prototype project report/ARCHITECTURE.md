# SentinelTrace V5 Architecture Master Reference

## System Architecture Diagram

```mermaid
graph TD
    A[Raw Log Telemetry] -->|POST /api/v1/ingest| B[Ingestion Vault]
    B -->|SHA-256 Evidence Seal| C[OCSF Normalization Engine]
    C --> D[Semantic Policy & Trust Engine]
    D --> E[Detection & Trust Evaluation]
    E --> F[Threat Intel & Risk Correlation]
    F --> G[Security Incidents & Investigations]
    G --> H[Assurance & Remediation Recovery]
    H --> I[15-Domain Security Analytics Engine]
    I --> J[17-Stage Cryptographic Lineage Chain]
    J --> K[Executive Report & Evidence Package]
    K --> L[Governance Ledger & Merkle Proof]
```

## Layered Component Breakdown
1. **API & Interface Layer**: 29 FastAPI routers delivering RESTful JSON endpoints to 26 React Command Centers.
2. **Parsing & Normalization Layer**: Formats raw telemetry into standard OCSF v1.1.0 JSON payloads.
3. **Detection & Correlation Layer**: Rules, threat intelligence feeds (IOCs), and risk scoring models.
4. **Governance & Ledger Layer**: Merkle tree builder, append-only ledger, and Maker-Checker enforcement.
