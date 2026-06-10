-- name: InsertUser :exec
INSERT INTO users (
    id, email, email_verified, name, status,
    email_ciphertext, email_nonce, email_enc_key_id, email_enc_version,
    email_hash, email_hash_key_id, email_hash_version,
    name_ciphertext, name_nonce, name_enc_key_id, name_enc_version,
    created_at, updated_at
) VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16);

-- name: InsertUserIdentity :exec
INSERT INTO user_identities (
    id, user_id, provider, provider_user_id,
    provider_sub_hash, provider_sub_hash_key_id, provider_sub_hash_version,
    provider_sub_ciphertext, provider_sub_nonce, provider_sub_enc_key_id, provider_sub_enc_version,
    created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetUserByProviderIdentity :one
SELECT u.id, u.email, u.email_verified, u.name, u.status,
       u.email_ciphertext, u.email_nonce, u.email_enc_key_id, u.email_enc_version,
       u.name_ciphertext, u.name_nonce, u.name_enc_key_id, u.name_enc_version,
       u.created_at, u.updated_at
FROM users u
JOIN user_identities ui ON u.id = ui.user_id
WHERE ui.provider = $1 AND ui.provider_user_id = $2;

-- name: GetUserByProviderSubHash :one
SELECT u.id, u.email, u.email_verified, u.name, u.status,
       u.email_ciphertext, u.email_nonce, u.email_enc_key_id, u.email_enc_version,
       u.name_ciphertext, u.name_nonce, u.name_enc_key_id, u.name_enc_version,
       u.created_at, u.updated_at
FROM users u
JOIN user_identities ui ON u.id = ui.user_id
WHERE ui.provider = $1 AND ui.provider_sub_hash = $2;

-- name: ListProviderSubBackfill :many
SELECT id, user_id, provider, provider_user_id
FROM user_identities
WHERE provider_sub_hash IS NULL AND provider_user_id IS NOT NULL
ORDER BY id
LIMIT $1;

-- name: CountProviderSubUnbackfilled :one
SELECT count(*)
FROM user_identities
WHERE provider_sub_hash IS NULL AND provider_user_id IS NOT NULL;

-- name: BackfillProviderSub :exec
UPDATE user_identities SET
    provider_sub_hash         = $2,
    provider_sub_hash_key_id  = $3,
    provider_sub_hash_version = $4,
    provider_sub_ciphertext   = $5,
    provider_sub_nonce        = $6,
    provider_sub_enc_key_id   = $7,
    provider_sub_enc_version  = $8
WHERE id = $1;

-- name: GetUserByID :one
SELECT id, email, email_verified, name, status,
       email_ciphertext, email_nonce, email_enc_key_id, email_enc_version,
       name_ciphertext, name_nonce, name_enc_key_id, name_enc_version,
       created_at, updated_at
FROM users
WHERE id = $1;

-- name: GetUserForTxByID :one
SELECT id, email, email_verified, name, status,
       email_ciphertext, email_nonce, email_enc_key_id, email_enc_version,
       name_ciphertext, name_nonce, name_enc_key_id, name_enc_version
FROM users
WHERE id = $1;

-- name: GetUserInfoFieldsByID :one
SELECT id, email, email_verified, name,
       email_ciphertext, email_nonce, email_enc_key_id, email_enc_version,
       name_ciphertext, name_nonce, name_enc_key_id, name_enc_version
FROM users
WHERE id = $1;

-- name: ListUsersBackfill :many
SELECT id, email, name
FROM users
WHERE email_hash IS NULL AND email IS NOT NULL
ORDER BY id
LIMIT $1;

-- name: CountUsersUnbackfilled :one
SELECT count(*)
FROM users
WHERE email_hash IS NULL AND email IS NOT NULL;

-- name: BackfillUserPII :exec
UPDATE users SET
    email_ciphertext   = $2,
    email_nonce        = $3,
    email_enc_key_id   = $4,
    email_enc_version  = $5,
    email_hash         = $6,
    email_hash_key_id  = $7,
    email_hash_version = $8,
    name_ciphertext    = $9,
    name_nonce         = $10,
    name_enc_key_id    = $11,
    name_enc_version   = $12
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

-- name: MarkUserPendingDeletionByID :execrows
UPDATE users
SET status = 'pending_deletion',
    deletion_requested_at = $1,
    deletion_scheduled_at = $2,
    updated_at = $1
WHERE id = $3 AND status = 'active';

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

-- name: InsertTestAuthRequestWithResource :exec
INSERT INTO auth_requests (
  id,
  client_id,
  redirect_uri,
  scopes,
  state,
  nonce,
  code_challenge,
  code_challenge_method,
  resource,
  expires_at,
  created_at
)
VALUES (
  $1,
  'test-mcp-app',
  'http://localhost/callback',
  '{openid}',
  $2,
  'test-nonce',
  'E9Melhoa2OwvFrEMT',
  'S256',
  $3,
  $4,
  $5
);
