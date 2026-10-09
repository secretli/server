-- name: RegisterPublicID :exec
-- Takes a public id until expires_at. A second upload with the same id fails
-- on the primary key, whatever became of the secret that took it first.
INSERT INTO public_ids (
    public_id,
    expires_at
)
VALUES (
    $1, $2
);

-- name: SetPublicIDExpiry :exec
-- The completed upload gives the secret, and so its id, the final expiry.
UPDATE public_ids
SET expires_at = sqlc.arg(expires_at)
WHERE public_id = sqlc.arg(public_id);

-- name: DeletePublicIDs :exec
-- An abandoned upload's secret never existed: its id is free again.
DELETE FROM public_ids
WHERE public_id = ANY(sqlc.arg(public_ids)::text[]);

-- name: DeleteExpiredPublicIDs :execrows
-- Frees one batch of ids past their expiry whose secret is gone, oldest
-- first. A secret's id stays while its row does: an upload that outlasts
-- its provisional expiry keeps it until it completes or is abandoned.
DELETE FROM public_ids
WHERE public_id IN (
    SELECT p.public_id
    FROM public_ids AS p
    WHERE p.expires_at <= sqlc.arg(now_at)
      AND NOT EXISTS (
          SELECT 1
          FROM secrets AS s
          WHERE s.public_id = p.public_id
      )
    ORDER BY p.expires_at
    LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
);
