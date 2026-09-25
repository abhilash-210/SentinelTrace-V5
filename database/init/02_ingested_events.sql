-- ============================================================
-- SENTINEL-TRACE — PostgreSQL Ingested Events Table
-- Sprint 1: Raw Event Preservation & Traceable Ingestion
-- ============================================================

CREATE SCHEMA IF NOT EXISTS sentinel;

-- Ingested Events Table
CREATE TABLE IF NOT EXISTS sentinel.ingested_events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(64) UNIQUE NOT NULL,
    source_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(100) NOT NULL,
    file_format VARCHAR(50) NOT NULL DEFAULT 'text',
    raw_content TEXT NOT NULL,
    raw_content_hash VARCHAR(64) NOT NULL,
    content_size INTEGER NOT NULL DEFAULT 0,
    ingested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processing_status VARCHAR(50) NOT NULL DEFAULT 'PRESERVED',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Performance and Query Indexes
CREATE UNIQUE INDEX IF NOT EXISTS ix_ingested_events_event_id 
    ON sentinel.ingested_events (event_id);

CREATE INDEX IF NOT EXISTS ix_ingested_events_ingested_at 
    ON sentinel.ingested_events (ingested_at DESC);

CREATE INDEX IF NOT EXISTS ix_ingested_events_source_name 
    ON sentinel.ingested_events (source_name);

CREATE INDEX IF NOT EXISTS ix_ingested_events_source_type 
    ON sentinel.ingested_events (source_type);

-- Permissions
GRANT ALL PRIVILEGES ON TABLE sentinel.ingested_events TO sentinel;
GRANT USAGE, SELECT ON SEQUENCE sentinel.ingested_events_id_seq TO sentinel;
