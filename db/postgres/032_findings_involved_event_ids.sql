-- Migration 032 — involved_event_ids on security_findings
--
-- Adds an array of every event that contributed to a finding. For per-event
-- detections (Runtime Guard + per-event session detectors) this equals
-- [event_id] — kept in the array form so the UI has a single source of truth.
-- For session-level scorers that match a pattern across multiple events
-- (multi-turn jailbreak, aggregate limits, drift), this holds the full
-- contributing set so the UI can highlight every event on the timeline.
--
-- Empty array is legal ({}) — cross-session findings, structural checks,
-- and any legacy row inserted before this migration. The application layer
-- and UI both treat {} as "no per-event highlight," falling back to the
-- primary event_id column when it's meaningful.
--
-- No default backfill needed for existing rows: the app writer's ON CONFLICT
-- prefers the larger array, so the first re-firing after this migration will
-- populate it. Historical rows stay at NULL / {} — that's the correct state
-- for data written by scorers that didn't produce this info.

ALTER TABLE security_findings
    ADD COLUMN IF NOT EXISTS involved_event_ids UUID[] NOT NULL DEFAULT '{}';
