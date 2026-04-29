-- name: GetActiveConnectionsByUserID :many
WITH active_tokens AS (
  SELECT DISTINCT ON (client_id)
         client_id,
         scopes
  FROM refresh_tokens
  WHERE refresh_tokens.user_id = $1
    AND refresh_tokens.revoked_at IS NULL
    AND refresh_tokens.expires_at > $2
  ORDER BY refresh_tokens.client_id, refresh_tokens.created_at DESC
),
last_used_tokens AS (
  SELECT client_id,
         MAX(used_at)::timestamptz AS last_used
  FROM refresh_tokens
  WHERE refresh_tokens.user_id = $1
    AND refresh_tokens.used_at IS NOT NULL
  GROUP BY refresh_tokens.client_id
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
WHERE refresh_tokens.user_id = $2
  AND refresh_tokens.client_id = $3
  AND refresh_tokens.revoked_at IS NULL;

-- name: GetActiveSessionsByUserID :many
SELECT s.id,
       s.expires_at,
       COALESCE(login.ip_address::text, '')::text AS ip_address,
       COALESCE(login.user_agent, '')::text AS user_agent,
       COALESCE(login.created_at, s.created_at) AS created_at
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

-- name: RevokeSessionByUserIDAndID :exec
UPDATE sessions
SET revoked_at = $1
WHERE sessions.user_id = $2
  AND sessions.id = $3
  AND sessions.revoked_at IS NULL;

-- name: RevokeOtherActiveSessionsByUserID :exec
UPDATE sessions
SET revoked_at = $1
WHERE sessions.user_id = $2
  AND sessions.id <> $3
  AND sessions.expires_at > $4
  AND sessions.revoked_at IS NULL;

-- name: GetAuditLogByUserID :many
SELECT id,
       event_type,
       COALESCE(ip_address::text, '')::text AS ip_address,
       COALESCE(user_agent, '')::text AS user_agent,
       COALESCE(metadata, '{}'::jsonb)::jsonb AS metadata,
       created_at,
       COUNT(*) OVER() AS total
FROM audit_log
WHERE audit_log.user_id = NULLIF(sqlc.arg(user_id)::text, '')::uuid
ORDER BY created_at DESC
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: CountAuditLogByUserID :one
SELECT COUNT(*)
FROM audit_log
WHERE audit_log.user_id = NULLIF(sqlc.arg(user_id)::text, '')::uuid;
