-- An upload that stops sending is abandoned after 30 minutes, not only at
-- the end of its 24 hours.
--
-- A secret's size counts against the storage cap from the start of its
-- upload, before a byte has arrived. An upload that never sends anything
-- kept that reservation, and its public id, for a whole day. idle_until is
-- when an upload under way is given up if no part arrives first: 30 minutes
-- after its start, and 30 minutes after each new part, never past the
-- upload's own expiry. It is a deadline, not a history: one value per
-- upload under way, to the minute, gone with the upload's row.
--
-- The default sets it for every new upload, also those a server from before
-- this migration starts while both run during a rollout. For the same
-- reason the check only asks for a deadline while an upload is under way:
-- an older server finishing an upload leaves the value, which nothing reads
-- once the upload is over.
ALTER TABLE uploads
    ADD COLUMN idle_until TIMESTAMPTZ
        DEFAULT (date_trunc('minute', now()) + interval '30 minutes');

-- Uploads under way when this runs get a fresh half hour; finished ones none.
UPDATE uploads
SET idle_until = CASE
    WHEN state = 'uploading'
        THEN LEAST(expires_at, date_trunc('minute', now()) + interval '30 minutes')
    END;

ALTER TABLE uploads
    ADD CONSTRAINT uploads_idle_until_while_uploading
        CHECK (state <> 'uploading' OR idle_until IS NOT NULL);

-- The abandon sweep looks for uploads under way past their deadline.
CREATE INDEX idx_uploads_idle_until
    ON uploads (idle_until)
    WHERE state = 'uploading';

---- create above / drop below ----
DROP INDEX IF EXISTS idx_uploads_idle_until;
ALTER TABLE uploads DROP CONSTRAINT IF EXISTS uploads_idle_until_while_uploading;
ALTER TABLE uploads DROP COLUMN IF EXISTS idle_until;
