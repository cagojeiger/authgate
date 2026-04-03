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

-- name: CompleteAuthRequestByID :execrows
UPDATE auth_requests
SET subject = $1, auth_time = $2, done = true
WHERE id = $3 AND expires_at > $2;

-- name: SetUserStatusByID :exec
UPDATE users
SET status = $1, updated_at = $2
WHERE id = $3;

-- name: RecoverPendingDeletionUserByID :exec
UPDATE users
SET status = 'active',
    deletion_requested_at = NULL,
    deletion_scheduled_at = NULL,
    updated_at = $1
WHERE id = $2 AND status = 'pending_deletion';

-- name: MarkUserPendingDeletionByID :exec
UPDATE users
SET status = 'pending_deletion',
    deletion_requested_at = $1,
    deletion_scheduled_at = $2,
    updated_at = $1
WHERE id = $3;

-- name: RevokeActiveRefreshTokensByUserID :exec
UPDATE refresh_tokens
SET revoked_at = $1
WHERE user_id = $2 AND revoked_at IS NULL;

-- name: InsertTestAuthRequest :exec
INSERT INTO auth_requests (
  id,
  client_id,
  redirect_uri,
  scopes,
  state,
  nonce,
  code_challenge,
  code_challenge_method,
  expires_at,
  created_at
)
VALUES (
  $1,
  'test-app',
  'http://localhost/callback',
  '{openid}',
  $2,
  'test-nonce',
  'E9Melhoa2OwvFrEMT',
  'S256',
  $3,
  $4
);
