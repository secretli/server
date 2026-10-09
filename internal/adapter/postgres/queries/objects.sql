-- name: CreateObject :exec
INSERT INTO objects (
    storage_key,
    state
)
VALUES (
    $1, 'writing'
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
SET doomed = TRUE
WHERE storage_key = ANY(sqlc.arg(storage_keys)::text[]);

-- name: ListDoomedObjectsForUpdate :many
-- Doomed objects, one batch at a time: the fewest failed removals first, so
-- objects that storage keeps refusing sink behind the rest, then by key, an
-- order that needs no time. One a secret still points at would be a bug; it
-- is left alone rather than deleted from under the secret.
SELECT o.*
FROM objects AS o
WHERE o.doomed
  AND NOT EXISTS (
      SELECT 1
      FROM secrets AS s
      WHERE s.storage_key = o.storage_key
  )
ORDER BY o.failed_removals, o.storage_key
LIMIT sqlc.arg(batch_size)
FOR UPDATE OF o SKIP LOCKED;

-- name: CountFailedRemovals :exec
UPDATE objects
SET failed_removals = failed_removals + 1
WHERE storage_key = ANY(sqlc.arg(storage_keys)::text[]);

-- name: DeleteObjects :execrows
DELETE FROM objects
WHERE storage_key = ANY(sqlc.arg(storage_keys)::text[]);
