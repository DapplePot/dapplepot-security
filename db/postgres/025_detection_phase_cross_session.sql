-- Allow cross_session as a valid detection_phase in security_findings.
-- The cross-session scorer (scorer/cross_session.py) writes findings with
-- detection_phase = 'cross_session' but the original constraint only permitted
-- 'online' and 'post_session'.

ALTER TABLE security_findings
    DROP CONSTRAINT IF EXISTS security_findings_detection_phase_check;

ALTER TABLE security_findings
    ADD CONSTRAINT security_findings_detection_phase_check
    CHECK (detection_phase IN ('online', 'post_session', 'cross_session'));
