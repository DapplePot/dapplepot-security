-- Migration 013 — v3 scoring columns
-- Run after 012_signal_registry.sql

-- Add confidence tier to signal_registry
ALTER TABLE signal_registry ADD COLUMN IF NOT EXISTS confidence_tier TEXT
    NOT NULL DEFAULT 'high'
    CHECK (confidence_tier IN ('deterministic','high','medium','low','skeletal'));

-- Add v3 columns to session_risk_scores
ALTER TABLE session_risk_scores
    ADD COLUMN IF NOT EXISTS v3_llm_composite JSONB,
    ADD COLUMN IF NOT EXISTS v3_asi_composite JSONB,
    ADD COLUMN IF NOT EXISTS attack_chains_detected TEXT[] NOT NULL DEFAULT '{}';

-- Add trust score columns to agent_risk_scores
ALTER TABLE agent_risk_scores
    ADD COLUMN IF NOT EXISTS trust_score NUMERIC(5,1) NOT NULL DEFAULT 80.0,
    ADD COLUMN IF NOT EXISTS trust_trend TEXT NOT NULL DEFAULT 'stable'
        CHECK (trust_trend IN ('improving','stable','degrading')),
    ADD COLUMN IF NOT EXISTS trust_trend_slope NUMERIC(6,3) NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS trust_alpha NUMERIC(8,3) NOT NULL DEFAULT 2.0,
    ADD COLUMN IF NOT EXISTS trust_beta NUMERIC(8,3) NOT NULL DEFAULT 8.0;

-- Add confidence to security_findings
ALTER TABLE security_findings
    ADD COLUMN IF NOT EXISTS confidence_tier TEXT,
    ADD COLUMN IF NOT EXISTS confidence NUMERIC(3,2);
