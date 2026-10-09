-- name: CreateRetrievalSession :exec
INSERT INTO retrieval_sessions (
    session_token_hash,
    public_id,
    expires_at
)
VALUES (
    $1, $2, $3
);

-- name: GetDownloadableSecret :one
-- The secret a valid session may read, live or closing, until it expires.
-- Whatever dooms an object deletes its secret in the same transaction, and
-- the secret's sessions with it, so deleting a secret ends running downloads.
SELECT s.*
FROM retrieval_sessions AS rs
JOIN secrets AS s ON s.public_id = rs.public_id
WHERE rs.session_token_hash = sqlc.arg(session_token_hash)
  AND rs.public_id = sqlc.arg(public_id)
  AND rs.expires_at > sqlc.arg(now_at)
  AND s.expires_at > sqlc.arg(now_at);

-- name: DeleteExpiredRetrievalSessions :execrows
DELETE FROM retrieval_sessions
WHERE expires_at < sqlc.arg(now_at);
