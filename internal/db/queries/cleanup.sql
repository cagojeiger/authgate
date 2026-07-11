-- Each delete is bounded by LIMIT and the caller loops until fewer than the
-- batch size come back, so a backlog (e.g. after downtime) is drained in
-- bounded transactions instead of one lock-holding statement over millions of
-- rows. ctid IN (...) is the standard Postgres batched-delete idiom.

-- name: DeleteRevokedRefreshTokensBefore :execrows
DELETE FROM refresh_tokens
WHERE ctid IN (
  SELECT t.ctid FROM refresh_tokens t
  WHERE t.revoked_at IS NOT NULL AND t.revoked_at < sqlc.arg(cutoff)
  LIMIT sqlc.arg(batch_size)
);

-- name: DeleteExpiredRefreshTokensBefore :execrows
DELETE FROM refresh_tokens
WHERE ctid IN (
  SELECT t.ctid FROM refresh_tokens t
  WHERE t.expires_at < sqlc.arg(cutoff)
  LIMIT sqlc.arg(batch_size)
);

-- name: DeleteExpiredOrRevokedSessions :execrows
DELETE FROM sessions
WHERE ctid IN (
  SELECT t.ctid FROM sessions t
  WHERE t.expires_at < sqlc.arg(cutoff) OR t.revoked_at IS NOT NULL
  LIMIT sqlc.arg(batch_size)
);

-- name: DeleteExpiredAuthRequestsBefore :execrows
DELETE FROM auth_requests
WHERE ctid IN (
  SELECT t.ctid FROM auth_requests t
  WHERE t.expires_at < sqlc.arg(cutoff)
  LIMIT sqlc.arg(batch_size)
);

-- name: DeleteExpiredDeviceCodesBefore :execrows
DELETE FROM device_codes
WHERE ctid IN (
  SELECT t.ctid FROM device_codes t
  WHERE t.expires_at < sqlc.arg(cutoff)
  LIMIT sqlc.arg(batch_size)
);

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

-- name: MarkUserDeletedByID :execrows
-- PII redaction on deletion (ADR-002): every encrypted/hashed email/name column
-- is cleared so no recoverable PII remains for the deleted user.
UPDATE users SET
  email_ciphertext = NULL, email_nonce = NULL, email_enc_key_id = NULL, email_enc_version = NULL,
  email_hash = NULL, email_hash_key_id = NULL, email_hash_version = NULL,
  name_ciphertext = NULL, name_nonce = NULL, name_enc_key_id = NULL, name_enc_version = NULL,
  status = 'deleted',
  deleted_at = sqlc.arg(deleted_at),
  deletion_requested_at = NULL,
  deletion_scheduled_at = NULL
WHERE id = sqlc.arg(user_id) AND status = 'pending_deletion' AND deletion_scheduled_at < sqlc.arg(deleted_at);

-- name: InsertDeletionCompletedAudit :exec
INSERT INTO audit_log (user_id, event_type, metadata, created_at)
VALUES (
  NULLIF(sqlc.arg(user_id)::text, '')::uuid,
  'auth.deletion_completed',
  jsonb_build_object('reason', sqlc.arg(reason)::text),
  sqlc.arg(created_at)
);

-- name: RedactAuditLogPIIByUserID :execrows
UPDATE audit_log
SET ip_address = NULL,
    user_agent = NULL
WHERE user_id = NULLIF(sqlc.arg(user_id)::text, '')::uuid
  AND (ip_address IS NOT NULL OR user_agent IS NOT NULL);

-- name: AnonymizeAuditLogBefore :execrows
UPDATE audit_log
SET user_id = NULL,
    ip_address = NULL,
    user_agent = NULL
WHERE created_at < sqlc.arg(cutoff)
  AND (user_id IS NOT NULL OR ip_address IS NOT NULL OR user_agent IS NOT NULL);
