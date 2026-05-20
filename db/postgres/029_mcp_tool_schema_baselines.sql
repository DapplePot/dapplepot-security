-- 029: baseline table for MCP tool schema change detection (ASCV-01c)
CREATE TABLE IF NOT EXISTS mcp_tool_schema_baselines (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID        NOT NULL,
    agent_id    UUID        NOT NULL,
    tool_name   TEXT        NOT NULL,
    schema_hash TEXT        NOT NULL,
    schema_json JSONB       NOT NULL DEFAULT '{}',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, agent_id, tool_name)
);

CREATE INDEX IF NOT EXISTS idx_mcp_tool_schema_baselines_agent
    ON mcp_tool_schema_baselines (tenant_id, agent_id);
