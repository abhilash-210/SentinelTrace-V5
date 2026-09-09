# SENTINEL-TRACE — Screenshot Manifest & Visual Evidence Catalog

This catalog documents all real visual evidence captures for SentinelTrace V5 across sprints, detailing the architectural proof and recommended slides for future Smart India Hackathon (SIH) presentation decks.

---

## Sprint 3 Visual Evidence Catalog

| Filename | Sprint | Feature | What It Proves | Future PPT Slide Use |
| :--- | :--- | :--- | :--- | :--- |
| `01_semantic_policy_registry.png` | 3C | Semantic Policy Registry | Complete vendor-scoped policy catalog with versioning and status governance. | Architecture / Governance Overview |
| `02_cisco_policy_detail.png` | 3C | Cisco ASA Policy Detail | Vendor-scoped mapping rules showing PERMIT $\rightarrow$ ALLOWED (COMPATIBLE). | Semantic Trust & Normalization |
| `03_demo_vendor_policy_detail.png` | 3C | Demo Vendor Policy Detail | Vendor-scoped mapping rules showing PERMIT $\rightarrow$ MONITORED (AMBIGUOUS). | Multi-Vendor Edge Handling |
| `04_same_token_different_meaning.png` | 3C | Vendor Semantic Isolation | Proves structural parsing $\neq$ semantic interpretation. Identical raw token `PERMIT` produces different canonical meanings depending on vendor context. | **Core Innovation / USP Slide (High Value)** |
| `05_protected_semantic_fields.png` | 3C | Protected Semantic Fields | Enforces heightened scrutiny on security-critical canonical fields (`action.result`, `authentication.outcome`, `severity`). | Security & Risk Governance |
| `06_semantic_policy_versioning.png` | 3C | Policy Version Lineage | Visual graph of policy revisions (`v0 SUPERSEDED` $\rightarrow$ `v1 ACTIVE` $\rightarrow$ `v2 DRAFT Candidate`). | Enterprise Version Control & Audit |
| `07_policy_comparison.png` | 3C | Read-Only Version Diff | Deterministic comparison between revisions highlighting meaning shifts (`PERMIT: ALLOWED -> MONITORED`) and HIGH semantic impact. | Policy Migration & Impact Analysis |
| `08_semantic_traceability_full_chain.png` | 3C | End-to-End Traceability | Complete 6-tier unbroken chain: Raw Evidence $\rightarrow$ Normalized Event $\rightarrow$ Source Profile $\rightarrow$ Semantic Policy $\rightarrow$ Policy Rule $\rightarrow$ Interpretation $\rightarrow$ Drift Alerts. | **System Architecture & Provenance (High Value)** |
| `09_semantic_drift_dashboard.png` | 3C | Defensive Drift Detection | Real-time detection and filtering of semantic anomalies (`UNMAPPED_VALUE`, `AMBIGUOUS_MAPPING`, `PROTECTED_FIELD_RISK`). | **Zero-Trust Security & Drift Alerts (High Value)** |
| `10_explainability_panel.png` | 3C | Explainable AI/Decision Logic | Complete mathematical confidence breakdown (Base 1.00 - deductions) and human-readable reasoning narrative. | Explainability & Auditability |
| `11_draft_policy_creation.png` | 3C | Draft Policy Governance | Enforces forced `DRAFT` status on newly registered policies to prevent unauthorized live activation. | Dual-Control Governance Pre-Requisite |
| `12_docker_services.png` | 3C | Live Infrastructure & API | Docker container health, PostgreSQL connectivity, and FastAPI OpenAPI live endpoints. | Technical Infrastructure & Readiness |

---

## High-Value PPT Assets Directory (`docs/ppt-assets/screenshots/`)

The following three high-value screenshots have been curated and copied for presentation slide design:
1. `04_same_token_different_meaning.png` — Visual hero illustrating vendor context isolation.
2. `08_semantic_traceability_full_chain.png` — Visual hero illustrating end-to-end evidence-to-drift audit trail.
3. `09_semantic_drift_dashboard.png` — Visual hero illustrating real-time semantic anomaly detection.
