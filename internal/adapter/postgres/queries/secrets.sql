-- name: CreateSecret :exec
-- A secret is filed when its upload starts, so its public id is taken from
-- then on.
INSERT INTO secrets (
    public_id,
    state,
    storage_key,
    metadata_token_hash,
    blob_token_hash,
    deletion_token_hash,
    encrypted_meta,
    blob_size,
    burn_after_read,
    expires_at
)
VALUES (
    $1, 'uploading', $2, $3, $4, $5, $6, $7, $8, $9
);

-- name: GetSecret :one
SELECT *
FROM secrets
WHERE public_id = $1;

-- name: GetReadableSecretForUpdate :one
SELECT *
FROM secrets
WHERE public_id = sqlc.arg(public_id)
  AND state = 'live'
  AND expires_at > sqlc.arg(now_at)
FOR UPDATE;

-- name: MakeSecretLive :execrows
UPDATE secrets
SET state = 'live',
    created_at = sqlc.arg(now_at)
WHERE public_id = sqlc.arg(public_id)
  AND state = 'uploading';

-- name: EndSecretOpened :exec
-- Opening a one-time secret ends it. Its object stays until the download
-- that opened it has ended.
UPDATE secrets
SET state = 'ended',
    outcome = 'opened',
    encrypted_meta = NULL,
    blob_token_hash = NULL,
    deletion_token_hash = NULL
WHERE public_id = $1;

-- name: MarkSecretOpened :exec
-- Someone other than the owner opened a reusable secret.
UPDATE secrets
SET opened = TRUE
WHERE public_id = $1;

-- name: EndSecretDeleted :exec
-- Deleting ends the secret; the caller dooms its object in the same
-- transaction.
UPDATE secrets
SET state = 'ended',
    outcome = 'deleted',
    storage_key = NULL,
    encrypted_meta = NULL,
    blob_token_hash = NULL,
    deletion_token_hash = NULL
WHERE public_id = $1;

-- name: DeleteUploadingSecrets :many
-- An abandoned upload's secret never existed: its row goes, which frees the
-- public id. Returns the keys of the objects to doom.
DELETE FROM secrets
WHERE public_id = ANY(sqlc.arg(public_ids)::text[])
  AND state = 'uploading'
RETURNING storage_key;

-- name: ListDrainedSecretsForUpdate :many
-- Opened one-time secrets whose last download session has ended.
SELECT s.public_id, s.storage_key
FROM secrets AS s
WHERE s.state = 'ended'
  AND s.storage_key IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM retrieval_sessions AS rs
      WHERE rs.public_id = s.public_id
        AND rs.expires_at > sqlc.arg(now_at)
  )
ORDER BY s.public_id
LIMIT sqlc.arg(batch_size)
FOR UPDATE OF s SKIP LOCKED;

-- name: ClearStorageKeys :exec
UPDATE secrets
SET storage_key = NULL
WHERE public_id = ANY(sqlc.arg(public_ids)::text[]);

-- name: ListExpiredSecretsForUpdate :many
-- Live and ended secrets past their expiry, oldest first. An upload under
-- way is left to its own expiry.
SELECT public_id, storage_key
FROM secrets
WHERE state <> 'uploading'
  AND expires_at <= sqlc.arg(now_at)
ORDER BY expires_at
LIMIT sqlc.arg(batch_size)
FOR UPDATE SKIP LOCKED;

-- name: DeleteSecretsByPublicIDs :execrows
DELETE FROM secrets
WHERE public_id = ANY(sqlc.arg(public_ids)::text[]);

-- name: LockUploadStarts :exec
-- Serializes upload starts while storage is capped, so that two cannot both
-- squeeze under the cap with room for one.
SELECT pg_advisory_xact_lock(7302102);

-- name: StoredBytes :one
-- What the secrets that hold an object take up in storage, uploads under way
-- included. Doomed objects are left out: they are gone within a minute.
SELECT COALESCE(SUM(blob_size), 0)::bigint AS stored_bytes
FROM secrets
WHERE storage_key IS NOT NULL;

-- name: StorageStats :one
-- Totals for the metrics: no secret is told apart.
SELECT
    (SELECT count(*) FROM secrets AS l WHERE l.state = 'live' AND l.expires_at > sqlc.arg(now_at))::bigint AS live_secrets,
    (SELECT COALESCE(SUM(h.blob_size), 0) FROM secrets AS h WHERE h.storage_key IS NOT NULL)::bigint AS stored_bytes,
    (SELECT count(*) FROM objects AS o WHERE o.doomed)::bigint AS doomed_objects;
