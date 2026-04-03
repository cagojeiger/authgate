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
