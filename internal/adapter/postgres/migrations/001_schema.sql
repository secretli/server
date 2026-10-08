-- The whole schema. The server keeps as little as it can: ciphertext, token
-- hashes, sizes and the expiry, and once a secret has ended only how it ended,
-- never when. Nothing about a secret outlives its expiry.

-- Every object the server writes to storage, from before the write until
-- after the delete. Objects are only ever deleted through this table: a
-- business change marks one doomed in the same transaction, and the cleanup's
-- object sweep removes it from storage and then forgets it. So storage never
-- holds an object this table does not know about.
CREATE TABLE objects
(
    -- 'blobs/' and the upload session id: never reused.
    storage_key  TEXT        PRIMARY KEY,

    -- writing until the upload is assembled, then stored.
    state        TEXT        NOT NULL CHECK (state IN ('writing', 'stored')),

    -- The provider's multipart upload, recorded once it exists. An object
    -- whose upload id never got recorded is found by listing its key.
    s3_upload_id TEXT,

    created_at   TIMESTAMPTZ NOT NULL,

    -- Set once nothing may read the object any more.
    doomed_at    TIMESTAMPTZ
);

CREATE INDEX idx_objects_doomed
    ON objects (doomed_at)
    WHERE doomed_at IS NOT NULL;

-- One row per secret, from the start of its upload until its expiry.
CREATE TABLE secrets
(
    -- Derived from the share secret by the client.
    public_id           TEXT        PRIMARY KEY,

    -- uploading until the upload completes, then live, then ended once it is
    -- opened (one-time) or deleted. Expiry ends nothing: the row goes.
    state               TEXT        NOT NULL CHECK (state IN ('uploading', 'live', 'ended')),

    -- The secret's object. Cleared in the transaction that dooms the object.
    storage_key         TEXT        UNIQUE REFERENCES objects,

    -- Hashed bearer tokens; raw tokens are never stored. The metadata token,
    -- part of every link, also unlocks the answer to how an ended secret ended.
    metadata_token_hash TEXT        NOT NULL,
    blob_token_hash     TEXT,
    deletion_token_hash TEXT,

    -- The client-encrypted metadata envelope and the encrypted object's size.
    encrypted_meta      TEXT,
    blob_size           BIGINT      NOT NULL,

    burn_after_read     BOOLEAN     NOT NULL,

    -- Counted from the start of the upload, never moved.
    expires_at          TIMESTAMPTZ NOT NULL,

    -- When the upload completed.
    created_at          TIMESTAMPTZ,

    -- Whether someone other than the owner has opened a reusable secret. Not
    -- when, and never for a one-time secret, which ends when it is opened.
    opened              BOOLEAN     NOT NULL DEFAULT FALSE,

    -- How an ended secret ended.
    outcome             TEXT        CHECK (outcome IN ('opened', 'deleted')),

    CHECK ((state = 'uploading') = (created_at IS NULL)),
    CHECK ((state = 'ended') = (outcome IS NOT NULL)),
    -- An ended secret keeps nothing but what tells how it ended.
    CHECK (num_nulls(encrypted_meta, blob_token_hash, deletion_token_hash)
        = CASE WHEN state = 'ended' THEN 3 ELSE 0 END),
    CHECK (state = 'ended' OR storage_key IS NOT NULL),
    -- Deleting dooms the object at once.
    CHECK (outcome IS DISTINCT FROM 'deleted' OR storage_key IS NULL),
    CHECK (NOT (burn_after_read AND opened))
);

-- The expiry sweep.
CREATE INDEX idx_secrets_expires_at
    ON secrets (expires_at)
    WHERE state <> 'uploading';

-- Opened one-time secrets whose object waits for the last download to end.
CREATE INDEX idx_secrets_draining
    ON secrets (public_id)
    WHERE state = 'ended' AND storage_key IS NOT NULL;

-- Upload sessions. The secret's own fields live on its row from the start;
-- an upload keeps what its session needs, and for an hour after it finished
-- enough to answer a repeated complete or abort.
CREATE TABLE uploads
(
    session_id        TEXT        PRIMARY KEY,

    -- The secret the upload creates. Abandoning an upload deletes that row,
    -- which frees the public id and clears this.
    public_id         TEXT        REFERENCES secrets ON DELETE SET NULL,

    upload_token_hash TEXT        NOT NULL,

    state             TEXT        NOT NULL CHECK (state IN ('uploading', 'completed', 'abandoned')),
    expires_at        TIMESTAMPTZ NOT NULL,
    finished_at       TIMESTAMPTZ,

    CHECK ((state = 'uploading') = (finished_at IS NULL)),
    CHECK (state <> 'uploading' OR public_id IS NOT NULL)
);

CREATE INDEX idx_uploads_public_id
    ON uploads (public_id);

CREATE INDEX idx_uploads_expires_at
    ON uploads (expires_at)
    WHERE state = 'uploading';

CREATE INDEX idx_uploads_finished_at
    ON uploads (finished_at)
    WHERE state <> 'uploading';

-- Uploaded parts, recorded for idempotency and completion.
CREATE TABLE upload_parts
(
    session_id  TEXT        NOT NULL REFERENCES uploads ON DELETE CASCADE,
    part_number INTEGER     NOT NULL,

    -- Byte placement and integrity in the final encrypted object.
    part_offset BIGINT      NOT NULL,
    part_size   BIGINT      NOT NULL,
    part_sha256 TEXT        NOT NULL,

    -- What storage needs to assemble the object.
    etag        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (session_id, part_number)
);

-- Short-lived authorization for range downloads.
CREATE TABLE retrieval_sessions
(
    session_token_hash TEXT        PRIMARY KEY,
    public_id          TEXT        NOT NULL REFERENCES secrets ON DELETE CASCADE,
    expires_at         TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_retrieval_sessions_public_expires_at
    ON retrieval_sessions (public_id, expires_at);

CREATE INDEX idx_retrieval_sessions_expires_at
    ON retrieval_sessions (expires_at);

-- Short-code transfers as one row each. The protocol has exactly three
-- legs, so their messages are columns: the sender's offer, the receiver's
-- answer and the sender's delivery. The server stores public PAKE shares, a
-- confirmation tag and ciphertext; the code's words never reach it.
CREATE TABLE code_transfers
(
    -- 32 random bytes, base64url, chosen by the sender: it is also the PAKE
    -- session id, and the offer depends on it.
    transfer_id         TEXT        PRIMARY KEY,

    -- The number at the start of the code. Unique among active transfers.
    nameplate           INTEGER     NOT NULL,

    -- Hashed bearer tokens. Raw tokens are never stored.
    sender_token_hash   TEXT        NOT NULL,
    receiver_token_hash TEXT,

    -- The sender's PAKE share, stored when the transfer is created.
    offer               BYTEA       NOT NULL,

    -- The receiver's PAKE share and confirmation tag, written together once.
    answer_share        BYTEA,
    answer_confirmation BYTEA,

    -- The sealed link. Storing it closes the transfer as done.
    delivery            BYTEA,

    -- done, cancelled, mismatch or expired, set together with closed_at.
    close_reason        TEXT,

    created_at          TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    closed_at           TIMESTAMPTZ,

    CHECK ((answer_share IS NULL) = (answer_confirmation IS NULL)),
    CHECK ((close_reason IS NULL) = (closed_at IS NULL))
);

-- A nameplate names at most one active transfer; ended ones free it.
CREATE UNIQUE INDEX idx_code_transfers_active_nameplate
    ON code_transfers (nameplate)
    WHERE closed_at IS NULL;

CREATE INDEX idx_code_transfers_expires_at
    ON code_transfers (expires_at);

-- Wakes waiting long-polls on every replica: a changed transfer sends its
-- transfer_id on the transfer_events channel. Postgres delivers a
-- notification only once the writing transaction has committed, so a woken
-- reader always finds the change.
CREATE FUNCTION notify_transfer_event() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    PERFORM pg_notify('transfer_events', NEW.transfer_id);
    RETURN NULL;
END;
$$;

-- Every change of a transfer (claim, answer, delivery, close) wakes the
-- long-polls waiting on it.
CREATE TRIGGER code_transfers_notify
    AFTER UPDATE
    ON code_transfers
    FOR EACH ROW
EXECUTE FUNCTION notify_transfer_event();

---- create above / drop below ----
DROP TABLE IF EXISTS code_transfers;
DROP FUNCTION IF EXISTS notify_transfer_event();
DROP TABLE IF EXISTS retrieval_sessions;
DROP TABLE IF EXISTS upload_parts;
DROP TABLE IF EXISTS uploads;
DROP TABLE IF EXISTS secrets;
DROP TABLE IF EXISTS objects;
