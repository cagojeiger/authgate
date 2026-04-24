-- name: GetRefreshFamilyIDByTokenHash :one
SELECT family_id
FROM refresh_tokens
WHERE token_hash = $1;

-- name: RevokeRefreshTokenByHash :execrows
UPDATE refresh_tokens
SET revoked_at = $1, used_at = $1
WHERE token_hash = $2 AND revoked_at IS NULL;

-- name: InsertRefreshToken :exec
INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, resource, scopes, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetRefreshTokenForUpdateByHash :one
SELECT id, token_hash, family_id, user_id, client_id, COALESCE(resource, '') AS resource,
       scopes, expires_at, revoked_at, used_at
FROM refresh_tokens
WHERE token_hash = $1
FOR UPDATE;

-- name: RevokeRefreshFamily :exec
UPDATE refresh_tokens
SET revoked_at = $1
WHERE family_id = $2 AND revoked_at IS NULL;

-- name: MarkRefreshTokenUsedAndRevokedByID :exec
UPDATE refresh_tokens
SET used_at = $1, revoked_at = $1
WHERE id = $2;

-- name: RevokeRefreshTokenByID :execrows
UPDATE refresh_tokens
SET revoked_at = $1
WHERE id = $2 AND revoked_at IS NULL;

-- name: GetRefreshTokenInfoByHashAndClientID :one
SELECT user_id, id
FROM refresh_tokens
WHERE token_hash = $1 AND client_id = $2;
