-- name: CreateUpload :exec
-- The upload has half an hour for its first part (idle_until), never past
-- its own expiry. The column's default does the same for servers from before
-- it, which leave it out.
INSERT INTO uploads (
    session_id,
    public_id,
    upload_token_hash,
    state,
    expires_at,
    lifetime,
    idle_until
)
VALUES (
    $1, $2, $3, 'uploading', $4, $5,
    LEAST($4, date_trunc('minute', now()) + interval '30 minutes')
);

-- name: GetUpload :one
-- The upload with what it needs of its secret and object, while the secret
-- has them. Until the upload completes, the secret's expiry is provisional.
SELECT
    u.session_id,
    u.public_id,
    u.upload_token_hash,
    u.state,
    u.expires_at,
    u.finished_at,
    u.lifetime,
    s.storage_key,
    s.blob_size,
    s.expires_at AS secret_expires_at,
    o.s3_upload_id
FROM uploads AS u
LEFT JOIN secrets AS s ON s.public_id = u.public_id
LEFT JOIN objects AS o ON o.storage_key = s.storage_key
WHERE u.session_id = $1;

-- name: GetUploadForUpdate :one
-- The upload as GetUpload returns it, locked for completing or abandoning it.
SELECT
    u.session_id,
    u.public_id,
    u.upload_token_hash,
    u.state,
    u.expires_at,
    u.finished_at,
    u.lifetime,
    s.storage_key,
    s.blob_size,
    s.expires_at AS secret_expires_at,
    o.s3_upload_id
FROM uploads AS u
LEFT JOIN secrets AS s ON s.public_id = u.public_id
LEFT JOIN objects AS o ON o.storage_key = s.storage_key
WHERE u.session_id = $1
FOR UPDATE OF u;

-- name: MarkUploadCompleted :exec
-- The secret has its expiry now, so the lifetime goes, and with nothing more
-- to wait for, the idle deadline.
UPDATE uploads
SET state = 'completed',
    finished_at = sqlc.arg(finished_at),
    lifetime = NULL,
    idle_until = NULL
WHERE session_id = sqlc.arg(session_id)
  AND state = 'uploading';

-- name: MarkUploadsAbandoned :many
-- Returns the public ids of the abandoned uploads' secrets.
UPDATE uploads
SET state = 'abandoned',
    finished_at = sqlc.arg(finished_at),
    lifetime = NULL,
    idle_until = NULL
WHERE session_id = ANY(sqlc.arg(session_ids)::text[])
  AND state = 'uploading'
RETURNING public_id;

-- name: ListExpiredUploadsForUpdate :many
-- Uploads under way past their expiry, or that sent nothing new for half an
-- hour (idle_until).
SELECT session_id
FROM uploads
WHERE state = 'uploading'
  AND (expires_at < sqlc.arg(now_at) OR idle_until < sqlc.arg(now_at))
ORDER BY expires_at
LIMIT sqlc.arg(batch_size)
FOR UPDATE SKIP LOCKED;

-- name: ExtendUploadIdleDeadline :exec
-- A new part arrived: the upload has another half hour before it counts as
-- idle, to the minute, but never past its own expiry.
UPDATE uploads
SET idle_until = LEAST(expires_at, date_trunc('minute', now()) + interval '30 minutes')
WHERE session_id = $1
  AND state = 'uploading';

-- name: DeleteFinishedUploads :execrows
-- Finished uploads are kept a few minutes so a repeated complete or abort
-- gets the same answer; their parts go with them.
DELETE FROM uploads
WHERE state <> 'uploading'
  AND finished_at < sqlc.arg(finished_before);

-- name: ListUploadParts :many
SELECT *
FROM upload_parts
WHERE session_id = $1
ORDER BY part_number;

-- name: GetUploadPartForUpdate :one
SELECT *
FROM upload_parts
WHERE session_id = $1
  AND part_number = $2
FOR UPDATE;

-- name: CreateUploadPart :one
INSERT INTO upload_parts (
    session_id,
    part_number,
    part_offset,
    part_size,
    part_sha256,
    etag
)
VALUES (
    $1, $2, $3, $4, $5, $6
)
RETURNING *;

-- name: DeleteUploadParts :exec
DELETE FROM upload_parts
WHERE session_id = $1;
