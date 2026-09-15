-- name: GetRefreshFamilyIDByTokenHash :one
SELECT family_id
FROM refresh_tokens
WHERE token_hash = $1;

-- name: RevokeRefreshTokenByHash :execrows
-- Revocation leaves used_at alone: used_at is set only when the token is
-- redeemed at the token endpoint, which is what refresh reuse grace relies on
-- to tell a rotated token from a revoked one.
UPDATE refresh_tokens
SET revoked_at = $1
WHERE token_hash = $2 AND revoked_at IS NULL;

-- name: InsertRefreshToken :exec
INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, resource, scopes, expires_at, created_at, parent_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

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

-- name: RevokeRefreshTokenByID :exec
UPDATE refresh_tokens
SET revoked_at = $1
WHERE id = $2 AND revoked_at IS NULL;

-- name: GetRefreshTokenInfoByHashAndClientID :one
SELECT user_id, id
FROM refresh_tokens
WHERE token_hash = $1 AND client_id = $2;

-- name: TombstoneRefreshFamily :execrows
INSERT INTO refresh_token_families (family_id, user_id, reason, revoked_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (family_id) DO NOTHING;

-- name: CountRefreshTokenChildren :one
SELECT count(*)
FROM refresh_tokens
WHERE parent_id = sqlc.arg(parent_id)::uuid;

-- name: HasRevokedUnredeemedRefreshTokenInFamily :one
-- A token revoked without being redeemed was revoked on purpose (/oauth/revoke,
-- a user-wide revoke, reuse detection). Rotation always sets used_at together
-- with revoked_at.
SELECT EXISTS (
    SELECT 1 FROM refresh_tokens
    WHERE family_id = $1 AND revoked_at IS NOT NULL AND used_at IS NULL
) AS revoked;

-- name: IsRefreshFamilyRevoked :one
SELECT EXISTS (
    SELECT 1 FROM refresh_token_families WHERE family_id = $1
) AS revoked;
