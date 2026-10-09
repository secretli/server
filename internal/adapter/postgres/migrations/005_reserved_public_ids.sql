-- A link stays reserved until its secret's expiry, whatever became of the
-- secret.
--
-- Anyone holding a link can derive everything a secret under it needs: the
-- public id, the tokens and the keys. Since 004, the row of an opened
-- one-time secret goes once its download ends, and a deleted secret's row at
-- once. Someone who intercepted a link could open a one-time secret and then
-- upload their own content under the same link, and its recipient would read
-- that instead, with nothing to show it. A password does not help: they
-- would leave it out.
--
-- So public_ids holds every public id in use, from the start of its upload
-- until the expiry of the secret that took it. A secret's row comes and goes
-- within it; its primary key makes a second upload with the same id fail
-- atomically, and no delete or drain touches it, so none can race an upload
-- start. (A table of reservations written on delete and drain would have
-- needed its check and the new secret's insert made atomic by hand.) It keeps
-- the id and the expiry only: not whether the secret was opened or deleted,
-- nor when.
CREATE TABLE public_ids
(
    public_id  TEXT        PRIMARY KEY,

    -- The expiry of the secret that took the id: until then nobody else may
    -- take it. While uploading, the secret's provisional one.
    expires_at TIMESTAMPTZ NOT NULL
);

-- The sweep that frees ids once their time is up.
CREATE INDEX idx_public_ids_expires_at
    ON public_ids (expires_at);

-- Every secret's id. Secrets deleted, or opened and drained, before this ran
-- have no row left to take an id from: their links are free already.
INSERT INTO public_ids (public_id, expires_at)
SELECT public_id, expires_at
FROM secrets;

-- A secret's id is taken for as long as the secret exists, and after.
ALTER TABLE secrets
    ADD CONSTRAINT secrets_public_id_registered
        FOREIGN KEY (public_id) REFERENCES public_ids;

---- create above / drop below ----
-- The reserved ids go: an id is then taken only while a secret's row holds
-- it, so the links of secrets whose rows are gone can be reused.
ALTER TABLE secrets DROP CONSTRAINT IF EXISTS secrets_public_id_registered;
DROP TABLE IF EXISTS public_ids;
