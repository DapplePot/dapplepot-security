CREATE TABLE IF NOT EXISTS session_risk_scores (
    session_id      UUID        PRIMARY KEY REFERENCES sessions(session_id),
    tenant_id       UUID        NOT NULL,
    agent_id        UUID,
    risk_score      INT         NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_band       TEXT        NOT NULL CHECK (risk_band IN ('clean','low','medium','high','critical')),
    signal_count    INT         NOT NULL DEFAULT 0,
    signal_ids      TEXT[]      NOT NULL DEFAULT '{}',
    scorer_version  TEXT        NOT NULL,
    scored_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
