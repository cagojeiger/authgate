-- name: InsertUser :exec
INSERT INTO users (id, email, email_verified, name, avatar_url, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, 'active', $6, $6);

-- name: InsertUserIdentity :exec
INSERT INTO user_identities (id, user_id, provider, provider_user_id, provider_email, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetUserByProviderIdentity :one
SELECT u.id, u.email, u.email_verified, u.name, u.avatar_url, u.status,
       u.created_at, u.updated_at
FROM users u
JOIN user_identities ui ON u.id = ui.user_id
WHERE ui.provider = $1 AND ui.provider_user_id = $2;

-- name: GetUserByID :one
SELECT id, email, email_verified, name, avatar_url, status,
       created_at, updated_at
FROM users
WHERE id = $1;

-- name: GetUserForTxByID :one
SELECT id, email, email_verified, name, status
FROM users
WHERE id = $1;

-- name: GetUserInfoFieldsByID :one
SELECT id, email, email_verified, name
FROM users
WHERE id = $1;
