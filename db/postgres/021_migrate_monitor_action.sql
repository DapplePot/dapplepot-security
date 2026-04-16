-- Rename "monitor" action → "alert" across all stored configs.
--
-- agent_subcheck_overrides.overrides is a JSONB map of
--   sub_check_id → { online_detection: bool, action: string }
-- Rows where any entry has action="monitor" are rewritten in-place.

UPDATE agent_subcheck_overrides
SET overrides = (
    SELECT jsonb_object_agg(
        key,
        CASE
            WHEN value->>'action' = 'monitor'
            THEN value || '{"action": "alert"}'::jsonb
            ELSE value
        END
    )
    FROM jsonb_each(overrides)
)
WHERE overrides::text LIKE '%"monitor"%';
