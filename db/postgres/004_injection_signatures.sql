-- Tenant-scoped injection pattern registry.
-- pattern_type: 'regex' | 'blocklist' | 'indirect'
-- Cached in Redis (dp:sec:sigs:<tenant_id>) with sig_cache_ttl_s TTL.
CREATE TABLE IF NOT EXISTS injection_signatures (
    sig_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        REFERENCES tenants(tenant_id),
    owasp_signal_id TEXT        NOT NULL,
    pattern_type    TEXT        NOT NULL CHECK (pattern_type IN ('regex', 'blocklist', 'indirect')),
    pattern         TEXT,
    severity        TEXT        NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    enabled         BOOLEAN     NOT NULL DEFAULT true,
    version         INT         NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
