-- 029 created mcp_tool_schema_baselines with CREATE TABLE IF NOT EXISTS, so if the
-- table already existed without schema_json the column was never added. Add it now.
ALTER TABLE mcp_tool_schema_baselines
  ADD COLUMN IF NOT EXISTS schema_json JSONB NOT NULL DEFAULT '{}';
