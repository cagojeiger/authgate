-- name: DeleteRevokedRefreshTokensBefore :execrows
DELETE FROM refresh_tokens
WHERE revoked_at IS NOT NULL AND revoked_at < sqlc.arg(cutoff);

-- name: DeleteExpiredRefreshTokensBefore :execrows
DELETE FROM refresh_tokens
WHERE expires_at < sqlc.arg(cutoff);

-- name: DeleteExpiredOrRevokedSessions :execrows
DELETE FROM sessions
WHERE expires_at < sqlc.arg(cutoff) OR revoked_at IS NOT NULL;

-- name: DeleteExpiredAuthRequestsBefore :execrows
DELETE FROM auth_requests
WHERE expires_at < sqlc.arg(cutoff);

-- name: DeleteExpiredDeviceCodesBefore :execrows
DELETE FROM device_codes
WHERE expires_at < sqlc.arg(cutoff);

-- name: TryCleanupAdvisoryLock :one
SELECT pg_try_advisory_lock(sqlc.arg(lock_key)::bigint);

-- name: UnlockCleanupAdvisoryLock :one
SELECT pg_advisory_unlock(sqlc.arg(lock_key)::bigint);

-- name: ListPendingDeletionUserIDsBefore :many
SELECT id
FROM users
WHERE status = 'pending_deletion' AND deletion_scheduled_at < sqlc.arg(cutoff);

-- name: DeleteUserIdentitiesByUserID :exec
DELETE FROM user_identities
WHERE user_id = $1;

-- name: DeleteSessionsByUserID :exec
DELETE FROM sessions
WHERE user_id = $1;

-- name: DeleteRefreshTokensByUserID :exec
DELETE FROM refresh_tokens
WHERE user_id = $1;

-- name: MarkUserDeletedByID :exec
UPDATE users SET
  email = 'deleted-' || id::text || '@deleted.invalid',
  name = NULL,
  avatar_url = NULL,
  status = 'deleted',
  deleted_at = sqlc.arg(deleted_at),
  deletion_requested_at = NULL,
  deletion_scheduled_at = NULL
WHERE id = sqlc.arg(user_id) AND status = 'pending_deletion' AND deletion_scheduled_at < sqlc.arg(deleted_at);

-- name: InsertDeletionCompletedAudit :exec
INSERT INTO audit_log (user_id, event_type, created_at)
VALUES (NULLIF(sqlc.arg(user_id)::text, '')::uuid, 'auth.deletion_completed', sqlc.arg(created_at));

-- name: AnonymizeAuditLogBefore :execrows
UPDATE audit_log
SET user_id = NULL
WHERE created_at < sqlc.arg(cutoff) AND user_id IS NOT NULL;
