CREATE TABLE IF NOT EXISTS security_findings (
    finding_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    session_id      UUID        NOT NULL REFERENCES sessions(session_id),
    event_id        UUID        NOT NULL,
    event_type      TEXT        NOT NULL,
    signal_id       TEXT        NOT NULL,
    sig_type        TEXT        NOT NULL,
    owasp_id        TEXT        NOT NULL,
    severity        TEXT        NOT NULL CHECK (severity IN ('critical','warning','info')),
    matched_text    TEXT,
    detail          TEXT,
    score_contrib   INT         NOT NULL DEFAULT 0,
    detection_phase TEXT        NOT NULL CHECK (detection_phase IN ('online','post_session')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
