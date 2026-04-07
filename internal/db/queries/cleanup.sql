-- name: DeleteRevokedRefreshTokensBatch :execrows
WITH doomed AS (
    SELECT id
    FROM refresh_tokens
    WHERE refresh_tokens.revoked_at IS NOT NULL AND refresh_tokens.revoked_at < sqlc.arg(cutoff)
    LIMIT sqlc.arg(batch_size)
)
DELETE FROM refresh_tokens t
USING doomed d
WHERE t.id = d.id;

-- name: DeleteExpiredRefreshTokensBatch :execrows
WITH doomed AS (
    SELECT id
    FROM refresh_tokens
    WHERE refresh_tokens.expires_at < sqlc.arg(cutoff)
    LIMIT sqlc.arg(batch_size)
)
DELETE FROM refresh_tokens t
USING doomed d
WHERE t.id = d.id;

-- name: DeleteExpiredOrRevokedSessionsBatch :execrows
WITH doomed AS (
    SELECT id
    FROM sessions
    WHERE sessions.expires_at < sqlc.arg(cutoff) OR sessions.revoked_at IS NOT NULL
    LIMIT sqlc.arg(batch_size)
)
DELETE FROM sessions t
USING doomed d
WHERE t.id = d.id;

-- name: DeleteExpiredAuthRequestsBatch :execrows
WITH doomed AS (
    SELECT id
    FROM auth_requests
    WHERE auth_requests.expires_at < sqlc.arg(cutoff)
    LIMIT sqlc.arg(batch_size)
)
DELETE FROM auth_requests t
USING doomed d
WHERE t.id = d.id;

-- name: DeleteExpiredDeviceCodesBatch :execrows
WITH doomed AS (
    SELECT id
    FROM device_codes
    WHERE device_codes.expires_at < sqlc.arg(cutoff)
    LIMIT sqlc.arg(batch_size)
)
DELETE FROM device_codes t
USING doomed d
WHERE t.id = d.id;

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

-- name: AnonymizeAuditLogBatch :execrows
WITH target AS (
    SELECT id
    FROM audit_log
    WHERE audit_log.created_at < sqlc.arg(cutoff) AND audit_log.user_id IS NOT NULL
    LIMIT sqlc.arg(batch_size)
)
UPDATE audit_log a
SET user_id = NULL
FROM target t
WHERE a.id = t.id;
