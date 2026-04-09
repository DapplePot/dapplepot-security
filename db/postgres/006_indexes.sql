-- security_findings indexes
CREATE INDEX IF NOT EXISTS idx_sf_session        ON security_findings (session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sf_tenant         ON security_findings (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sf_signal         ON security_findings (owasp_signal_id);
CREATE INDEX IF NOT EXISTS idx_sf_tenant_signal  ON security_findings (tenant_id, owasp_signal_id);
CREATE INDEX IF NOT EXISTS idx_sf_sub_check      ON security_findings (sub_check_id);
CREATE INDEX IF NOT EXISTS idx_sf_framework      ON security_findings (framework, tenant_id);
CREATE INDEX IF NOT EXISTS idx_sf_category       ON security_findings (category, tenant_id);

-- session_risk_scores indexes
CREATE INDEX IF NOT EXISTS idx_srs_tenant_llm_band  ON session_risk_scores (tenant_id, llm_band, scored_at DESC);
CREATE INDEX IF NOT EXISTS idx_srs_tenant_llm_score ON session_risk_scores (tenant_id, llm_score DESC);
CREATE INDEX IF NOT EXISTS idx_srs_tenant_asi_score ON session_risk_scores (tenant_id, asi_score DESC);
CREATE INDEX IF NOT EXISTS idx_srs_llm_status       ON session_risk_scores USING gin(llm_signal_status);
CREATE INDEX IF NOT EXISTS idx_srs_asi_status       ON session_risk_scores USING gin(asi_signal_status);

-- injection_signatures indexes
CREATE INDEX IF NOT EXISTS idx_isig_tenant  ON injection_signatures (tenant_id, enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_isig_signal  ON injection_signatures (owasp_signal_id);

-- signal_registry indexes
CREATE INDEX IF NOT EXISTS idx_sr_framework  ON signal_registry (framework);
CREATE INDEX IF NOT EXISTS idx_sr_category   ON signal_registry (category);
CREATE INDEX IF NOT EXISTS idx_sr_phase      ON signal_registry (detection_phase);
CREATE INDEX IF NOT EXISTS idx_sr_excluded   ON signal_registry (excluded) WHERE excluded = TRUE;
