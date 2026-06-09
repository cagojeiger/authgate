-- name: InsertSession :exec
INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetValidSessionUser :one
SELECT u.id, u.email, u.email_verified, u.name, u.status,
       u.created_at, u.updated_at
FROM sessions s
JOIN users u ON s.user_id = u.id
WHERE s.token_hash = sqlc.arg(token_hash)::text
  AND s.expires_at > sqlc.arg(expires_at)
  AND s.revoked_at IS NULL;

-- name: RevokeSessionsByUserID :exec
UPDATE sessions
SET revoked_at = $1
WHERE user_id = $2 AND revoked_at IS NULL;
