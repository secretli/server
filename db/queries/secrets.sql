-- name: StoreSecret :exec
INSERT INTO secrets (public_id, retrieval_token, nonce, encrypted_data, expires_at, burn_after_read, already_read, deletion_token)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetSecret :one
SELECT * FROM secrets WHERE public_id = $1;

-- name: MarkAsRead :exec
UPDATE secrets
SET already_read = true
WHERE public_id = $1
AND already_read = false;

-- name: DeleteSecret :exec
DELETE FROM secrets WHERE public_id = $1;
