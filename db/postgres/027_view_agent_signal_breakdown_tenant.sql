-- Add tenant_id to v_agent_signal_breakdown so callers can filter per-tenant.
-- Must DROP first — CREATE OR REPLACE cannot insert a column mid-list.
DROP VIEW IF EXISTS v_agent_signal_breakdown;
CREATE VIEW v_agent_signal_breakdown AS
SELECT
    s.agent_id,
    s.tenant_id,
    sf.owasp_signal_id,
    sf.framework,
    sf.category,
    COUNT(*)                       AS fired_count,
    COUNT(DISTINCT sf.session_id)  AS sessions_affected,
    MAX(sf.check_score)            AS max_check_score,
    MAX(sf.created_at)             AS last_seen_at
FROM security_findings sf
JOIN session_risk_scores s ON s.session_id = sf.session_id
WHERE s.agent_id IS NOT NULL
GROUP BY
    s.agent_id,
    s.tenant_id,
    sf.owasp_signal_id,
    sf.framework,
    sf.category;
