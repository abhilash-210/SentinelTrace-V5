# Cryptographic Architecture & Verification

## Cryptographic Guarantees
SentinelTrace V5 uses standard SHA-256 hashing across every stage of data processing to deliver verifiable evidence integrity.

## Hashing Principles
1. **Raw Evidence Hash**: SHA-256 hash of raw input content immediately upon edge receipt.
2. **Canonical JSON Hash (`compute_canonical_hash`)**: Keys are sorted alphabetically and whitespace stripped before hashing to guarantee determinism across platforms.
3. **17-Stage Hash Lineage**: Each stage S_i calculates:
   $$H(S_i) = \text{SHA256}(H(S_{i-1}) + \text{CanonicalJSON}(\text{StageOutput}_i))$$
4. **Report Sealing**: Reports feature SHA-256 section hashes and an overall report seal.
5. **Merkle Proof Ledger**: Transaction records are aggregated into a binary Merkle tree for rapid tamper verification.

## Tamper Detection Workflow
If a single bit in a raw log or report section is altered, recalculating `compute_canonical_hash` produces a completely different hash, immediately causing `verify_report` or `verify_provenance_chain` to return `status: UNTRUSTED` and flag the tampered section.
