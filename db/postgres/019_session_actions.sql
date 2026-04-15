-- Audit trail for online security actions taken during live agent sessions.
-- Written by Zone 6 (security engine) when an online sub-check fires with
-- action = sanitize, block_call, or terminate_session.
-- monitor and alert actions produce a security_finding row only; no action row.
--
-- sanitize          → harmful content stripped in-flight; session continues.
-- block_call        → in-flight LLM/tool call refused; session continues.
-- terminate_session → session killed immediately via SecurityViolationError.
CREATE TABLE IF NOT EXISTS session_actions (
    id              BIGSERIAL    PRIMARY KEY,
    session_id      TEXT         NOT NULL,
    tenant_id       TEXT         NOT NULL,
    agent_id        TEXT,
    sub_check_id    TEXT         NOT NULL,
    owasp_signal_id TEXT         NOT NULL,
    severity        TEXT         NOT NULL,
    action_taken    TEXT         NOT NULL,  -- sanitize | block_call | terminate_session
    triggered_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_session_actions_session
    ON session_actions (session_id);

CREATE INDEX IF NOT EXISTS idx_session_actions_tenant_time
    ON session_actions (tenant_id, triggered_at DESC);
