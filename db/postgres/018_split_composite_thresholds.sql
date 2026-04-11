-- Split the single composite_threshold into separate LLM and ASI thresholds.
-- NULL = not overridden → scorer falls back to platform default (60).
ALTER TABLE agent_alert_config
  ADD COLUMN IF NOT EXISTS llm_composite_threshold INT,
  ADD COLUMN IF NOT EXISTS asi_composite_threshold INT;
