# Current Limitations & Future Scope

## Current Prototype Limitations
1. **Database Engine**: Uses SQLite backend for dev simplicity (`sentinel_trace.db`). Production deployment will require PostgreSQL / TimescaleDB.
2. **Single-Node Execution**: Current ingestion pipeline runs in-process; production scaling requires distributed Apache Kafka / Redis stream workers.
3. **Key Management**: Cryptographic keys are managed in-application; production roadmap mandates Hardware Security Module (HSM) or AWS KMS integration.

## Future Scope Roadmap
- **Distributed Ingestion Workers**: Scale to 100,000+ events per second using Kafka + Rust edge agents.
- **Hardware Security Module (HSM) Anchoring**: Anchor Merkle tree roots to public blockchains (Ethereum/Polygon) or enterprise HSMs.
