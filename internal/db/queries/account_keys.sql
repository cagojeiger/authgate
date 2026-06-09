-- name: GetAccountEncryptionKey :one
SELECT wrapped_dek, kek_id, kek_version, destroyed_at
FROM account_encryption_keys
WHERE account_id = $1;

-- name: InsertAccountEncryptionKey :exec
INSERT INTO account_encryption_keys (account_id, wrapped_dek, kek_id, kek_version, created_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (account_id) DO NOTHING;

-- name: DestroyAccountEncryptionKey :execrows
UPDATE account_encryption_keys
SET wrapped_dek = NULL,
    destroyed_at = sqlc.arg(destroyed_at)
WHERE account_id = sqlc.arg(account_id) AND destroyed_at IS NULL;
