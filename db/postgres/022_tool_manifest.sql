-- Per-agent tool manifest and max-tool-calls-per-session config.
-- tool_manifest: JSONB array of allowed tool names (e.g. '["read_file","search_web"]').
--   Empty array [] = no manifest configured → manifest-dependent sub-checks skip silently.
-- max_tool_calls_per_session: user-defined hard cap on total tool calls per session.
--   NULL = not set → scorer falls back to statistical baseline (EA-02b, RA-01a).

ALTER TABLE agent_alert_config
  ADD COLUMN IF NOT EXISTS tool_manifest              JSONB NOT NULL DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS max_tool_calls_per_session INT;
