CREATE TABLE IF NOT EXISTS injection_signatures (
    sig_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        REFERENCES tenants(tenant_id),
    signal_id       TEXT        NOT NULL,
    sig_type        TEXT        NOT NULL CHECK (sig_type IN ('regex','blocklist','indirect')),
    pattern         TEXT,
    severity        TEXT        NOT NULL,
    enabled         BOOLEAN     NOT NULL DEFAULT true,
    version         INT         NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
