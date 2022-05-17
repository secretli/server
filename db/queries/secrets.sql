-- name: StoreSecret :exec
INSERT INTO secrets (public_id, retrieval_token, nonce, encrypted_data, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetSecret :one
SELECT * FROM secrets WHERE public_id = $1;
