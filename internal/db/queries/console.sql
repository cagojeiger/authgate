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

-- name: RevokeActiveRefreshTokensByUserIDAndClientID :execrows
UPDATE refresh_tokens
SET revoked_at = $1
WHERE user_id = $2
  AND client_id = $3
  AND revoked_at IS NULL;

-- name: GetActiveSessionsByUserID :many
SELECT s.id,
       s.expires_at,
       COALESCE(login.ip_address::text, '') AS ip_address,
       COALESCE(login.user_agent, '') AS user_agent,
       login.created_at
FROM sessions s
LEFT JOIN LATERAL (
  SELECT audit_log.ip_address,
         audit_log.user_agent,
         audit_log.created_at
  FROM audit_log
  WHERE audit_log.user_id = s.user_id
    AND audit_log.event_type = 'auth.login'
    AND audit_log.metadata->>'session_id' = s.id::text
  ORDER BY audit_log.created_at DESC
  LIMIT 1
) login ON true
WHERE s.user_id = $1
  AND s.expires_at > $2
  AND s.revoked_at IS NULL
ORDER BY s.created_at DESC;

-- name: RevokeSessionByUserIDAndID :execrows
UPDATE sessions
SET revoked_at = $1
WHERE user_id = $2
  AND id = $3
  AND revoked_at IS NULL;

-- name: RevokeOtherActiveSessionsByUserID :exec
UPDATE sessions
SET revoked_at = $1
WHERE user_id = $2
  AND id <> $3
  AND expires_at > $4
  AND revoked_at IS NULL;

-- name: GetAuditLogByUserID :many
SELECT id,
       event_type,
       COALESCE(ip_address::text, '') AS ip_address,
       COALESCE(user_agent, '') AS user_agent,
       COALESCE(metadata, '{}'::jsonb) AS metadata,
       created_at,
       COUNT(*) OVER() AS total
FROM audit_log
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountAuditLogByUserID :one
SELECT COUNT(*)
FROM audit_log
WHERE user_id = $1;
