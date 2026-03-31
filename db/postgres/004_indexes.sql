-- security_findings indexes
CREATE INDEX IF NOT EXISTS idx_findings_session   ON security_findings (session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_tenant    ON security_findings (tenant_id,  created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_signal    ON security_findings (signal_id);
CREATE INDEX IF NOT EXISTS idx_findings_owasp     ON security_findings (owasp_id, tenant_id);

-- session_risk_scores indexes
CREATE INDEX IF NOT EXISTS idx_scores_tenant_band  ON session_risk_scores (tenant_id, risk_band, scored_at DESC);
CREATE INDEX IF NOT EXISTS idx_scores_tenant_score ON session_risk_scores (tenant_id, risk_score DESC);

-- injection_signatures index
CREATE INDEX IF NOT EXISTS idx_sigs_tenant ON injection_signatures (tenant_id, enabled) WHERE enabled = true;
