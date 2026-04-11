-- Per-agent alert threshold overrides.
-- composite_threshold: alert if LLM or ASI composite score >= this value (default 60).
-- signal_thresholds: JSONB map of { "OW-LLM01": 70, ... } per-signal threshold overrides.
-- Absent signals fall back to SIGNAL_ALERT_THRESHOLDS_V3 in core/config.py.

CREATE TABLE IF NOT EXISTS agent_alert_config (
    tenant_id           TEXT        NOT NULL,
    agent_id            TEXT        NOT NULL,
    composite_threshold INT         NOT NULL DEFAULT 60,
    signal_thresholds   JSONB       NOT NULL DEFAULT '{}',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, agent_id)
);
