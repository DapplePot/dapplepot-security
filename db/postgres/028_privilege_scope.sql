-- Per-agent privilege scope: tool names the agent is explicitly authorized to
-- perform privilege-level operations with (e.g. assume_role, execute_sql for a
-- DBA agent, gcp_api for a cloud-admin agent).
--
-- privilege_scope: JSONB array of tool names.
--   []   = not configured → IPA-01a flags all privilege operations (safe default).
--   [...] = these tools are authorized to perform privilege ops for this agent;
--           IPA-01a skips both name-level and payload-level detection for them.
--
-- Set via the agent profile UI: each tool in the manifest has a
-- "Privilege-capable" checkbox that populates this list.

ALTER TABLE agent_alert_config
  ADD COLUMN IF NOT EXISTS privilege_scope JSONB NOT NULL DEFAULT '[]';
