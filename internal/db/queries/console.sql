-- name: GetActiveConnectionsByUserID :many
SELECT DISTINCT client_id
FROM refresh_tokens
WHERE user_id = $1
  AND revoked_at IS NULL
  AND expires_at > $2
ORDER BY client_id;
