-- Per-agent aggregate risk table. One row per agent, upserted after every session.
-- Powers "top agents by risk" views and agent-level dashboards.
CREATE TABLE IF NOT EXISTS agent_risk_scores (
    agent_id          UUID        PRIMARY KEY,
    tenant_id         UUID        NOT NULL,
    session_count     INT         NOT NULL DEFAULT 0,
    avg_llm_score     NUMERIC(5,2) NOT NULL DEFAULT 0,
    avg_asi_score     NUMERIC(5,2) NOT NULL DEFAULT 0,
    max_llm_score     SMALLINT    NOT NULL DEFAULT 0,
    max_asi_score     SMALLINT    NOT NULL DEFAULT 0,
    last_scored_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
