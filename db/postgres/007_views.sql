-- All reporting views. CREATE OR REPLACE so re-running is idempotent.

-- ─────────────────────────────────────────────────────────────────────────────
-- v_session_findings_summary
-- Per session: findings grouped by framework + signal + category + severity.
-- Used by session detail page.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_session_findings_summary AS
SELECT
    sf.session_id,
    sf.tenant_id,
    sf.framework,
    sf.owasp_signal_id,
    sf.category,
    sf.severity,
    COUNT(*)                AS finding_count,
    MAX(sf.check_score)     AS max_check_score,
    MAX(sf.created_at)      AS last_seen_at
FROM security_findings sf
GROUP BY
    sf.session_id,
    sf.tenant_id,
    sf.framework,
    sf.owasp_signal_id,
    sf.category,
    sf.severity;

-- ─────────────────────────────────────────────────────────────────────────────
-- v_signal_category_breakdown
-- Findings grouped by framework + signal + category across all sessions.
-- Powers the "Top Signals" and "Top Categories" dashboard panels.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_signal_category_breakdown AS
SELECT
    sf.framework,
    sf.owasp_signal_id,
    sf.category,
    sf.tenant_id,
    COUNT(*)                                            AS total_findings,
    COUNT(DISTINCT sf.session_id)                       AS sessions_affected,
    MAX(sf.check_score)                                 AS max_check_score,
    SUM(CASE WHEN sf.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
    SUM(CASE WHEN sf.severity = 'high'     THEN 1 ELSE 0 END) AS high_count,
    SUM(CASE WHEN sf.severity = 'medium'   THEN 1 ELSE 0 END) AS medium_count,
    MAX(sf.created_at)                                  AS last_seen_at
FROM security_findings sf
GROUP BY sf.framework, sf.owasp_signal_id, sf.category, sf.tenant_id;

-- ─────────────────────────────────────────────────────────────────────────────
-- v_top_agents_by_risk
-- Top agents ordered by composite risk score.
-- Powers "Top Agents" dashboard table.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_top_agents_by_risk AS
SELECT
    ar.agent_id,
    ar.tenant_id,
    ar.session_count,
    ar.avg_llm_score,
    ar.avg_asi_score,
    ar.max_llm_score,
    ar.max_asi_score,
    ROUND((ar.avg_llm_score + ar.avg_asi_score) / 2, 2) AS composite_risk_score,
    ar.last_scored_at
FROM agent_risk_scores ar
ORDER BY composite_risk_score DESC;

-- ─────────────────────────────────────────────────────────────────────────────
-- v_agent_signal_breakdown
-- Per-agent signal fire counts and affected session counts.
-- Consumed by GET /v1/security/agents/:id in dapplepot-api.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW v_agent_signal_breakdown AS
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
