-- name: CreateSecret :exec
-- A secret is filed when its upload starts, so its public id is taken from
-- then on. Its expiry is provisional until the upload completes.
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
-- The completed upload sets both times, to the minute: the secret's lifetime
-- counts from here, and nothing kept tells how long the upload took.
UPDATE secrets
SET state = 'live',
    created_at = sqlc.arg(created_at),
    expires_at = sqlc.arg(expires_at)
WHERE public_id = sqlc.arg(public_id)
  AND state = 'uploading';

-- name: CloseSecret :exec
-- Opening a one-time secret closes it, whoever opens it. Its row keeps only
-- what the download that opened it needs, the object, its size and the
-- expiry, until that download has ended.
UPDATE secrets
SET state = 'closing',
    created_at = NULL,
    metadata_token_hash = NULL,
    encrypted_meta = NULL,
    blob_token_hash = NULL,
    deletion_token_hash = NULL
WHERE public_id = $1;

-- name: MarkSecretOpened :exec
-- A recipient, not the owner, opened a reusable secret.
UPDATE secrets
SET opened = TRUE
WHERE public_id = $1;

-- name: DeleteUploadingSecrets :many
-- An abandoned upload's secret never existed: its row goes. Returns its id,
-- to free, and the key of the object to doom.
DELETE FROM secrets
WHERE public_id = ANY(sqlc.arg(public_ids)::text[])
  AND state = 'uploading'
RETURNING public_id, storage_key;

-- name: ListDrainedSecretsForUpdate :many
-- Closing secrets whose last download session has ended.
SELECT s.public_id, s.storage_key
FROM secrets AS s
WHERE s.state = 'closing'
  AND NOT EXISTS (
      SELECT 1
      FROM retrieval_sessions AS rs
      WHERE rs.public_id = s.public_id
        AND rs.expires_at > sqlc.arg(now_at)
  )
ORDER BY s.public_id
LIMIT sqlc.arg(batch_size)
FOR UPDATE OF s SKIP LOCKED;

-- name: ListExpiredSecretsForUpdate :many
-- Live and closing secrets past their expiry, oldest first. An upload under
-- way is left to its own expiry.
SELECT public_id, storage_key
FROM secrets
WHERE state <> 'uploading'
  AND expires_at <= sqlc.arg(now_at)
ORDER BY expires_at
LIMIT sqlc.arg(batch_size)
FOR UPDATE SKIP LOCKED;

-- name: DeleteSecretsByPublicIDs :execrows
-- Nothing about a deleted secret is kept but its id, which stays reserved
-- until the expiry, and its retrieval sessions go with it. The caller dooms
-- the objects in the same transaction.
DELETE FROM secrets
WHERE public_id = ANY(sqlc.arg(public_ids)::text[]);

-- name: LockUploadStarts :exec
-- Serializes upload starts while storage is capped, so that two cannot both
-- squeeze under the cap with room for one.
SELECT pg_advisory_xact_lock(7302102);

-- name: StoredBytes :one
-- What the secrets take up in storage, uploads under way and downloads that
-- drain included. Every secret holds its object; doomed objects are left
-- out, since they are gone within a minute.
SELECT COALESCE(SUM(blob_size), 0)::bigint AS stored_bytes
FROM secrets;

-- name: MetricsStats :one
-- Totals for the metrics, read at every scrape: how things stand now, never
-- a secret told apart and never a time. Overdue secrets and stuck uploads
-- are what the expiry and abandon sweeps would pick up now, on their
-- indexes; the other counts pass over tables that hold only what exists now.
SELECT
    live.one_time::bigint AS live_one_time,
    live.reusable::bigint AS live_reusable,
    (SELECT COALESCE(SUM(h.blob_size), 0) FROM secrets AS h)::bigint AS stored_bytes,
    (SELECT count(*) FROM secrets AS e WHERE e.state <> 'uploading' AND e.expires_at <= sqlc.arg(now_at))::bigint AS overdue_secrets,
    (SELECT count(*) FROM objects AS o WHERE o.doomed)::bigint AS doomed_objects,
    (SELECT count(*) FROM objects AS f WHERE f.doomed AND f.failed_removals > 0)::bigint AS removal_failed_objects,
    (SELECT count(*) FROM uploads AS u WHERE u.state = 'uploading' AND u.expires_at < sqlc.arg(now_at))::bigint AS stuck_uploads,
    (SELECT count(*) FROM public_ids AS p WHERE NOT EXISTS (
        SELECT 1 FROM secrets AS s WHERE s.public_id = p.public_id
    ))::bigint AS reserved_public_ids
FROM (
    SELECT
        count(*) FILTER (WHERE l.burn_after_read) AS one_time,
        count(*) FILTER (WHERE NOT l.burn_after_read) AS reusable
    FROM secrets AS l
    WHERE l.state = 'live'
      AND l.expires_at > sqlc.arg(now_at)
) AS live;
