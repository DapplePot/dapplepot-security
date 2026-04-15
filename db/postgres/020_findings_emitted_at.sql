-- Add emitted_at to security_findings so the timeline can show the SDK event
-- timestamp instead of the Zone 6 DB insert time (created_at).
ALTER TABLE security_findings
    ADD COLUMN IF NOT EXISTS emitted_at TIMESTAMPTZ;

-- Back-fill existing rows with created_at so the column is non-null for old data.
UPDATE security_findings SET emitted_at = created_at WHERE emitted_at IS NULL;
