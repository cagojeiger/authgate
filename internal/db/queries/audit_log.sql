-- name: InsertAuditLog :exec
INSERT INTO audit_log (user_id, event_type, ip_address, user_agent, metadata, created_at)
VALUES (
  NULLIF(sqlc.arg(user_id)::text, '')::uuid,
  sqlc.arg(event_type),
  NULLIF(sqlc.arg(ip_address), '')::inet,
  NULLIF(sqlc.arg(user_agent), ''),
  sqlc.arg(metadata)::jsonb,
  sqlc.arg(created_at)
);

-- name: GetAuditClientContextBySessionID :one
SELECT
  COALESCE(metadata->>'client_id', '')::text AS client_id,
  COALESCE(metadata->>'client_name', '')::text AS client_name
FROM audit_log
WHERE user_id = NULLIF(sqlc.arg(user_id)::text, '')::uuid
  AND event_type = 'auth.login'
  AND metadata->>'session_id' = sqlc.arg(session_id)::text
ORDER BY created_at DESC
LIMIT 1;
