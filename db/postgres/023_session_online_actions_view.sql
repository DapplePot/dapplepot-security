-- v_session_online_actions depends on session_actions (019) so it must be
-- created after that table exists. Moved here from 007_views.sql.
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
    ON  sf.session_id   = sa.session_id::uuid
    AND sf.sub_check_id = sa.sub_check_id;
