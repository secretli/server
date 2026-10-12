-- A wrong password counts against the secret it was tried on.
--
-- A password-protected secret could be guessed at for its whole lifetime:
-- a wrong password costs nothing, and only the rate limit per address
-- slowed the guessing. wrong_blob_tokens counts the wrong blob tokens a
-- secret has been tried with, a wrong password as a rule or a damaged
-- link; at ten the secret is deleted, as its owner could delete it. It is
-- a count, without times or addresses, and goes with the row.
--
-- The default fills the rows there are, and those a server from before
-- this migration inserts while both run during a rollout; such a server
-- doesn't count, which only leaves its guesses as uncounted as before.
ALTER TABLE secrets
    ADD COLUMN wrong_blob_tokens SMALLINT NOT NULL DEFAULT 0;

---- create above / drop below ----
ALTER TABLE secrets DROP COLUMN IF EXISTS wrong_blob_tokens;
