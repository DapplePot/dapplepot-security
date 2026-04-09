CREATE TABLE IF NOT EXISTS security_findings (
    finding_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    session_id      UUID        NOT NULL,
    event_id        UUID        NOT NULL,
    event_type      TEXT        NOT NULL,
    framework       TEXT        NOT NULL,
    owasp_signal_id TEXT        NOT NULL,
    sub_check_id    TEXT        NOT NULL,
    check_label     TEXT        NOT NULL,
    check_score     SMALLINT    NOT NULL CHECK (check_score BETWEEN 0 AND 100),
    category        TEXT        NOT NULL,
    severity        TEXT        NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    detection_phase TEXT        NOT NULL CHECK (detection_phase IN ('online', 'post_session')),
    matched_text    TEXT,
    detail          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
