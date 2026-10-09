-- A secret's row exists only while the secret can be opened, plus the upload
-- before and the download after, and its times are kept to the minute.
--
-- No tombstones. A deleted secret kept a row until its expiry, and so did an
-- opened one-time secret, so that its link could be told how it ended. Now
-- deleting a secret deletes its row, and nothing about it is kept: its link
-- gets the same 404 as one that never existed. An opened one-time secret is
-- closing: its row keeps only what the download that opened it needs, the
-- object, its size and the expiry, and goes with the object once that
-- download has ended. outcome goes, and opened is kept only for a live
-- reusable secret a recipient has opened.
--
-- No time tells how long an upload took. expires_at was set when the upload
-- started and created_at when it completed, both to the microsecond, so the
-- two gave the upload's duration. A secret is now created in the minute its
-- upload completes and expires its lifetime and one minute later: the
-- lifetime counts from the completed upload, is never shorter than chosen,
-- and the two times differ by the same for every secret of that lifetime.
-- Until then the lifetime waits on the upload. objects.created_at kept the
-- upload's start to the microsecond for as long as the object lived, only to
-- order the object sweep; it goes.
--
-- The constraints on secrets get names, so that later migrations need not
-- rely on the ones Postgres made up.

-- Every rule on secrets changes: the ones that served ended rows go first.
ALTER TABLE secrets
    DROP CONSTRAINT secrets_check,
    DROP CONSTRAINT secrets_check1,
    DROP CONSTRAINT secrets_check2,
    DROP CONSTRAINT secrets_check3,
    DROP CONSTRAINT secrets_check4,
    DROP CONSTRAINT secrets_check5,
    DROP CONSTRAINT secrets_state_check,
    ALTER COLUMN metadata_token_hash DROP NOT NULL;

-- Ended secrets whose object is already doomed, deleted ones and opened ones
-- whose download ended, go now. Their retrieval sessions go with them, and
-- their uploads forget them.
DELETE FROM secrets
WHERE state = 'ended'
  AND storage_key IS NULL;

-- What is left of the ended ones are opened one-time secrets still being
-- downloaded.
UPDATE secrets
SET state               = 'closing',
    metadata_token_hash = NULL,
    created_at          = NULL
WHERE state = 'ended';

-- Live secrets keep the expiry they were given.
UPDATE secrets
SET created_at = date_trunc('minute', created_at, 'UTC')
WHERE state = 'live';

-- secrets_outcome_check goes with the column.
ALTER TABLE secrets DROP COLUMN outcome;

-- Every secret left holds its object: the row goes when the object is doomed.
ALTER TABLE secrets ALTER COLUMN storage_key SET NOT NULL;

ALTER TABLE secrets
    ADD CONSTRAINT secrets_known_state
        CHECK (state IN ('uploading', 'live', 'closing')),
    -- Only a live secret has a creation time: an upload has none yet, and a
    -- closing secret keeps none.
    ADD CONSTRAINT secrets_created_while_live
        CHECK ((state = 'live') = (created_at IS NOT NULL)),
    -- A closing secret keeps only what its last download needs: no content
    -- and no token that could open it or ask after it.
    ADD CONSTRAINT secrets_closing_keeps_only_the_download
        CHECK (num_nulls(metadata_token_hash, blob_token_hash, deletion_token_hash, encrypted_meta)
            = CASE WHEN state = 'closing' THEN 4 ELSE 0 END),
    -- Only opening a one-time secret closes it.
    ADD CONSTRAINT secrets_closing_only_one_time
        CHECK (state <> 'closing' OR burn_after_read),
    -- Whether a recipient has opened it is kept for a live reusable secret
    -- only.
    ADD CONSTRAINT secrets_opened_only_live_reusable
        CHECK (NOT opened OR (state = 'live' AND NOT burn_after_read));

-- Closing secrets, for the sweep that deletes them once their download ended.
DROP INDEX idx_secrets_draining;
CREATE INDEX idx_secrets_closing
    ON secrets (public_id)
    WHERE state = 'closing';

-- How long the secret lives once its upload completes. Kept only while the
-- upload runs.
ALTER TABLE uploads ADD COLUMN lifetime INTERVAL;

-- An upload under way when this runs: its secret was to expire its lifetime
-- after the upload started, which its object's created_at holds.
UPDATE uploads AS u
SET lifetime = s.expires_at - o.created_at
FROM secrets AS s
JOIN objects AS o ON o.storage_key = s.storage_key
WHERE u.state = 'uploading'
  AND s.public_id = u.public_id;

ALTER TABLE uploads
    ADD CONSTRAINT uploads_lifetime_while_uploading
        CHECK ((state = 'uploading') = (lifetime IS NOT NULL));

-- An upload's own times are kept to the minute too.
UPDATE uploads
SET expires_at  = date_trunc('minute', expires_at, 'UTC'),
    finished_at = date_trunc('minute', finished_at, 'UTC');

-- The object sweep: fewest failed removals first, then by key, a stable
-- order without a time.
DROP INDEX idx_objects_doomed;
ALTER TABLE objects DROP COLUMN created_at;
CREATE INDEX idx_objects_doomed
    ON objects (failed_removals, storage_key)
    WHERE doomed;

---- create above / drop below ----
-- What this migration dropped stays gone. Deleted secrets, and opened ones
-- whose download ended, had no row any more, so version 3 cannot tell their
-- links how they ended; it answers 404 as for an expired secret. A closing
-- secret becomes an opened one, its other columns get values the old code
-- needs and never reads, and its link is told nothing either: no metadata
-- token hash matches the empty one.
DROP INDEX IF EXISTS idx_objects_doomed;
ALTER TABLE objects ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX idx_objects_doomed
    ON objects (failed_removals, created_at)
    WHERE doomed;

ALTER TABLE uploads DROP COLUMN IF EXISTS lifetime;

DROP INDEX IF EXISTS idx_secrets_closing;

ALTER TABLE secrets
    DROP CONSTRAINT IF EXISTS secrets_known_state,
    DROP CONSTRAINT IF EXISTS secrets_created_while_live,
    DROP CONSTRAINT IF EXISTS secrets_closing_keeps_only_the_download,
    DROP CONSTRAINT IF EXISTS secrets_closing_only_one_time,
    DROP CONSTRAINT IF EXISTS secrets_opened_only_live_reusable,
    ALTER COLUMN storage_key DROP NOT NULL,
    ADD COLUMN outcome TEXT CONSTRAINT secrets_outcome_check CHECK (outcome IN ('opened', 'deleted'));

UPDATE secrets
SET state               = 'ended',
    outcome             = 'opened',
    metadata_token_hash = '',
    created_at          = now()
WHERE state = 'closing';

ALTER TABLE secrets
    ALTER COLUMN metadata_token_hash SET NOT NULL,
    ADD CONSTRAINT secrets_state_check CHECK (state IN ('uploading', 'live', 'ended')),
    ADD CONSTRAINT secrets_check CHECK ((state = 'uploading') = (created_at IS NULL)),
    ADD CONSTRAINT secrets_check1 CHECK ((state = 'ended') = (outcome IS NOT NULL)),
    ADD CONSTRAINT secrets_check2 CHECK (num_nulls(encrypted_meta, blob_token_hash, deletion_token_hash)
        = CASE WHEN state = 'ended' THEN 3 ELSE 0 END),
    ADD CONSTRAINT secrets_check3 CHECK (state = 'ended' OR storage_key IS NOT NULL),
    ADD CONSTRAINT secrets_check4 CHECK (outcome IS DISTINCT FROM 'deleted' OR storage_key IS NULL),
    ADD CONSTRAINT secrets_check5 CHECK (NOT (burn_after_read AND opened));

CREATE INDEX idx_secrets_draining
    ON secrets (public_id)
    WHERE state = 'ended' AND storage_key IS NOT NULL;
