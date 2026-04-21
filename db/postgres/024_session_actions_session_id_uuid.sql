-- Align session_actions TEXT id columns with the UUID types used elsewhere.
-- Must drop and recreate v_session_online_actions because it references session_id.
DROP VIEW IF EXISTS v_session_online_actions;

ALTER TABLE session_actions
    ALTER COLUMN session_id TYPE UUID USING session_id::uuid,
    ALTER COLUMN tenant_id  TYPE UUID USING tenant_id::uuid;

CREATE OR REPLACE VIEW v_session_online_actions AS
SELECT
    sa.session_id,
    sa.tenant_id,
    sa.agent_id,
    sa.sub_check_id,
    sa.owasp_signal_id,
    sa.severity,
    sa.action_taken,
    sa.triggered_at,
    sf.check_label,
    sf.category,
    sf.framework,
    sf.matched_text,
    sf.detail
FROM session_actions sa
LEFT JOIN security_findings sf
    ON  sf.session_id   = sa.session_id
    AND sf.sub_check_id = sa.sub_check_id;
