-- name: GetActiveConnectionsByUserID :many
WITH active_tokens AS (
  SELECT DISTINCT ON (client_id)
         client_id,
         scopes
  FROM refresh_tokens
  WHERE user_id = $1
    AND revoked_at IS NULL
    AND expires_at > $2
  ORDER BY client_id, created_at DESC
),
last_used_tokens AS (
  SELECT client_id,
         MAX(used_at) AS last_used
  FROM refresh_tokens
  WHERE user_id = $1
    AND used_at IS NOT NULL
  GROUP BY client_id
)
SELECT active_tokens.client_id,
       active_tokens.scopes,
       last_used_tokens.last_used
FROM active_tokens
LEFT JOIN last_used_tokens ON last_used_tokens.client_id = active_tokens.client_id
ORDER BY active_tokens.client_id;

-- name: RevokeActiveRefreshTokensByUserIDAndClientID :exec
UPDATE refresh_tokens
SET revoked_at = $1
WHERE user_id = $2
  AND client_id = $3
  AND revoked_at IS NULL;
