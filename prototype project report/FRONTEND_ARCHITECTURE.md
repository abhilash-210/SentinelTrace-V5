# Frontend Architecture Reference

## Framework & Tooling
- **Core**: React 18, Vite 5
- **Icons**: Lucide React
- **Styling**: Vanilla CSS custom properties (Glassmorphism theme) with responsive flex/grid layouts.
- **Routing**: React Router DOM v6 (`App.jsx`)

## Key Command Centers (`frontend/src/pages/`)
1. `Dashboard.jsx`: Central operational hub.
2. `EvidenceVault.jsx`: Raw ingested event inspector.
3. `Normalization.jsx`: OCSF mapping viewer.
4. `DetectionRuleGovernance.jsx`: Rule lifecycle management & dual approval.
5. `SecurityIncidents.jsx`: Incident triage & response.
6. `SecurityInvestigationCommandCenter.jsx`: Deep forensic investigation workspace.
7. `SecurityAnalyticsCommandCenter.jsx`: 15-domain metric matrix, snapshots, reports & packages.
8. `MerkleVerification.jsx`: Cryptographic tamper detection console.
