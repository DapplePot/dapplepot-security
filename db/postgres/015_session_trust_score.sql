-- Migration 015 — per-session trust score
-- Stores the Bayesian trust score computed at the end of each session so we
-- can check true consecutive low-trust sessions and power the trend sparkline.

ALTER TABLE session_risk_scores
    ADD COLUMN IF NOT EXISTS trust_score NUMERIC(5,1);
