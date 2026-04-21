-- Broaden the security_findings uniqueness constraint from (session_id, sub_check_id)
-- to (session_id, sub_check_id, event_id) so that the same sub-check can fire
-- multiple times within a session (once per LLM/tool invocation) and all firings
-- are stored individually.  Previously the upsert kept only the highest-score row,
-- silently discarding subsequent firings.
--
-- The ON CONFLICT clause in findings.py is updated in the same changeset.

ALTER TABLE security_findings
    DROP CONSTRAINT IF EXISTS uq_findings_session_subcheck;

ALTER TABLE security_findings
    ADD CONSTRAINT uq_findings_session_subcheck_event
    UNIQUE (session_id, sub_check_id, event_id);
