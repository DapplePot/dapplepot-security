-- Workstream G — engine visibility on Session Analysis.
--
-- Adds columns to session_risk_scores so the UI can render the "141 checks
-- evaluated · 5 findings · analyzed 2m after session end" strip on the
-- session report. The scorer already knows all of this; we just persist it.
--
-- All columns are nullable so old rows aren't broken; the API returns null
-- and the UI hides the strip when the data isn't there.

ALTER TABLE session_risk_scores
    ADD COLUMN IF NOT EXISTS checks_evaluated INTEGER,
    ADD COLUMN IF NOT EXISTS checks_skipped   INTEGER,
    -- JSON breakdown of skipped checks by reason:
    --   { "needs_setup": ["EA-01c", "EA-03b"], "not_applicable": ["SC-EXCL", ...] }
    -- Kept as JSONB so we can render "12 need setup — Complete setup →" hooks
    -- on the session report without another table join.
    ADD COLUMN IF NOT EXISTS checks_skipped_by_reason JSONB DEFAULT '{}'::jsonb,
    -- Wall-clock duration of the scoring pass. Used to render "analyzed 1.8s
    -- after session end" — customers care about latency SLAs on this path.
    ADD COLUMN IF NOT EXISTS analysis_duration_ms INTEGER,
    -- When the scoring pass started (may lag graph_end by a few seconds due
    -- to the CH-retry loop). Distinct from scored_at, which is when the
    -- upsert happened.
    ADD COLUMN IF NOT EXISTS analysis_started_at TIMESTAMPTZ;
