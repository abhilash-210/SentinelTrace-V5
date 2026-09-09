-- ============================================================
-- SENTINEL-TRACE — PostgreSQL Evidence Vault Initialization
-- Sprint 1: Evidence Vault & Secure Log Ingestion
-- ============================================================

CREATE SCHEMA IF NOT EXISTS sentinel;

-- Evidence Events Table
CREATE TABLE IF NOT EXISTS sentinel.evidence_events (
    event_id UUID PRIMARY KEY,
    source_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(100) NOT NULL,
    raw_event TEXT NOT NULL,
    raw_event_hash VARCHAR(64) NOT NULL,
    ingested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    integrity_status VARCHAR(50) NOT NULL DEFAULT 'STORED'
);

-- Performance and Query Indexes
CREATE INDEX IF NOT EXISTS ix_evidence_events_ingested_at 
    ON sentinel.evidence_events (ingested_at DESC);

CREATE INDEX IF NOT EXISTS ix_evidence_events_source_name 
    ON sentinel.evidence_events (source_name);

CREATE INDEX IF NOT EXISTS ix_evidence_events_source_type 
    ON sentinel.evidence_events (source_type);

-- Permissions
GRANT ALL PRIVILEGES ON TABLE sentinel.evidence_events TO sentinel;
