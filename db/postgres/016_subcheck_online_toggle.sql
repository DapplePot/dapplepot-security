-- Per-agent sub-check online detection overrides.
-- Stores which sub-checks a tenant has toggled to "online" mode for a given agent.
-- Key: (tenant_id, agent_id)
-- Value: overrides JSONB — map of sub_check_id → {online_detection: bool}
--   e.g. {"PI-01a": {"online_detection": true}, "SID-01a": {"online_detection": true}}
--
-- This table is the durable source of truth.
-- The security scorer reads this at cache-miss time and folds it into AgentSecurityConfig.
-- The API writes here AND invalidates the Redis cfg cache so changes are picked up quickly.
CREATE TABLE IF NOT EXISTS agent_subcheck_overrides (
    tenant_id   TEXT        NOT NULL,
    agent_id    TEXT        NOT NULL,
    overrides   JSONB       NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_aso_tenant_agent
    ON agent_subcheck_overrides (tenant_id, agent_id);
