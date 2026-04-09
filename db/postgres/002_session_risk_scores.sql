-- session_id has no FK to sessions — the security consumer processes events
-- directly from Kafka and must not fail on a race with the ingest server.
CREATE TABLE IF NOT EXISTS session_risk_scores (
    session_id          UUID        PRIMARY KEY,
    tenant_id           UUID        NOT NULL,
    agent_id            UUID,
    llm_score           SMALLINT    NOT NULL DEFAULT 0
                            CHECK (llm_score BETWEEN 0 AND 100),
    llm_band            TEXT        NOT NULL DEFAULT 'clean'
                            CHECK (llm_band IN ('clean', 'low', 'medium', 'high', 'critical')),
    asi_score           SMALLINT    NOT NULL DEFAULT 0
                            CHECK (asi_score BETWEEN 0 AND 100),
    asi_band            TEXT        NOT NULL DEFAULT 'clean'
                            CHECK (asi_band IN ('clean', 'low', 'medium', 'high', 'critical')),
    llm_signal_status   JSONB       NOT NULL DEFAULT '{}',
    asi_signal_status   JSONB       NOT NULL DEFAULT '{}',
    scorer_version      TEXT        NOT NULL,
    scored_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
