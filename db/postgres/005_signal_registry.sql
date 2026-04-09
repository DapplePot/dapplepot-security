-- Canonical source of truth for all sub-checks across all frameworks.
-- framework: 'LLM' | 'ASI' | any future framework (no CHECK — extensible by design).
-- category: threat category (prompt_injection, data_disclosure, etc.).
-- Populated by scripts/seed_signal_registry.py.
CREATE TABLE IF NOT EXISTS signal_registry (
    owasp_signal_id  TEXT        NOT NULL,
    sub_check_id     TEXT        NOT NULL,
    check_label      TEXT        NOT NULL,
    framework        TEXT        NOT NULL,
    signal_number    SMALLINT    NOT NULL CHECK (signal_number BETWEEN 1 AND 20),
    category         TEXT        NOT NULL,
    detection_phase  TEXT        NOT NULL CHECK (detection_phase IN ('online', 'post_session', 'both')),
    check_score      SMALLINT    NOT NULL CHECK (check_score BETWEEN 0 AND 100),
    severity         TEXT        NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    excluded         BOOLEAN     NOT NULL DEFAULT FALSE,
    exclusion_reason TEXT,
    PRIMARY KEY (owasp_signal_id, sub_check_id)
);
