-- Objects keep no times beyond when they were filed: only whether one is
-- doomed, and how often removing it failed. While storage is down, doomed
-- objects wait, and a time on each would have recorded when its secret was
-- deleted or its download ended, for as long as the outage lasted.
ALTER TABLE objects
    ADD COLUMN doomed          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN failed_removals INTEGER NOT NULL DEFAULT 0;

UPDATE objects
SET doomed = doomed_at IS NOT NULL,
    failed_removals = CASE WHEN attempted_at IS NULL THEN 0 ELSE 1 END;

DROP INDEX idx_objects_doomed;
ALTER TABLE objects
    DROP COLUMN doomed_at,
    DROP COLUMN attempted_at;

-- The object sweep: fewest failed removals first, then the oldest.
CREATE INDEX idx_objects_doomed
    ON objects (failed_removals, created_at)
    WHERE doomed;

-- When each part arrived was written and never read.
ALTER TABLE upload_parts DROP COLUMN created_at;

---- create above / drop below ----
ALTER TABLE upload_parts ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();

DROP INDEX IF EXISTS idx_objects_doomed;
ALTER TABLE objects
    ADD COLUMN doomed_at    TIMESTAMPTZ,
    ADD COLUMN attempted_at TIMESTAMPTZ;
UPDATE objects SET doomed_at = now() WHERE doomed;
ALTER TABLE objects
    DROP COLUMN doomed,
    DROP COLUMN failed_removals;
CREATE INDEX idx_objects_doomed
    ON objects (attempted_at NULLS FIRST, doomed_at)
    WHERE doomed_at IS NOT NULL;
