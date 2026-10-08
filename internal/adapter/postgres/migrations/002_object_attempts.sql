-- When the cleanup last failed to remove an object. The object sweep tries
-- objects it has not tried yet first, then the ones it tried longest ago, so
-- a few objects that storage keeps refusing cannot hold up the rest.
ALTER TABLE objects ADD COLUMN attempted_at TIMESTAMPTZ;

DROP INDEX idx_objects_doomed;
CREATE INDEX idx_objects_doomed
    ON objects (attempted_at NULLS FIRST, doomed_at)
    WHERE doomed_at IS NOT NULL;

---- create above / drop below ----
DROP INDEX IF EXISTS idx_objects_doomed;
CREATE INDEX idx_objects_doomed
    ON objects (doomed_at)
    WHERE doomed_at IS NOT NULL;
ALTER TABLE objects DROP COLUMN IF EXISTS attempted_at;
