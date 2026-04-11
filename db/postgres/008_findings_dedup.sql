-- One row per (session, sub-check): the upsert in write_findings keeps
-- whichever phase has the higher score / higher severity.

ALTER TABLE security_findings
    DROP CONSTRAINT IF EXISTS uq_findings_session_subcheck;

ALTER TABLE security_findings
    ADD CONSTRAINT uq_findings_session_subcheck
    UNIQUE (session_id, sub_check_id);
