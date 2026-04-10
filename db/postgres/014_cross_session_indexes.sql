-- Migration 014 — cross-session support indexes
-- Run after 013_v3_scoring.sql

-- Index for cross-session queries by agent
CREATE INDEX IF NOT EXISTS idx_risk_scores_agent_scored
    ON session_risk_scores (agent_id, scored_at DESC);

-- Index for user-context cross-session queries
CREATE INDEX IF NOT EXISTS idx_risk_scores_tenant_scored
    ON session_risk_scores (tenant_id, scored_at DESC);
