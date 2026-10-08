-- name: CreateObject :exec
INSERT INTO objects (
    storage_key,
    state,
    created_at
)
VALUES (
    $1, 'writing', $2
);

-- name: RecordS3UploadID :execrows
UPDATE objects
SET s3_upload_id = sqlc.arg(s3_upload_id)
WHERE storage_key = sqlc.arg(storage_key)
  AND state = 'writing';

-- name: MarkObjectStored :exec
UPDATE objects
SET state = 'stored'
WHERE storage_key = $1;

-- name: DoomObjects :exec
UPDATE objects
SET doomed_at = sqlc.arg(now_at)
WHERE storage_key = ANY(sqlc.arg(storage_keys)::text[])
  AND doomed_at IS NULL;

-- name: ListDoomedObjectsForUpdate :many
-- Doomed objects, one batch at a time: those not tried yet first, oldest
-- first, then those whose removal failed, the longest ago first. One a secret
-- still points at would be a bug; it is left alone rather than deleted from
-- under the secret.
SELECT o.*
FROM objects AS o
WHERE o.doomed_at IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM secrets AS s
      WHERE s.storage_key = o.storage_key
  )
ORDER BY o.attempted_at NULLS FIRST, o.doomed_at
LIMIT sqlc.arg(batch_size)
FOR UPDATE OF o SKIP LOCKED;

-- name: MarkObjectsAttempted :exec
UPDATE objects
SET attempted_at = sqlc.arg(now_at)
WHERE storage_key = ANY(sqlc.arg(storage_keys)::text[]);

-- name: DeleteObjects :execrows
DELETE FROM objects
WHERE storage_key = ANY(sqlc.arg(storage_keys)::text[]);
