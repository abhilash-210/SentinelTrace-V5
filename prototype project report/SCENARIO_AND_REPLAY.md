# Scenario Execution & Replay Engine

## Attack Scenario Simulation
Executes pre-configured attack sequences (e.g. Brute Force, Lateral Movement, Data Exfiltration) to validate the end-to-end detection and provenance pipeline.

## Replay Modes
- `EVIDENCE_REPLAY`: Re-injects historical log streams into the ingestion pipeline under isolated testing flags.
- `CONTROLLED_REEXECUTION`: Re-runs normalization and detection evaluation over existing stored raw evidence.
