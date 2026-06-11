-- name: InsertUser :exec
INSERT INTO users (
    id, email_verified, status,
    email_ciphertext, email_nonce, email_enc_key_id, email_enc_version,
    email_hash, email_hash_key_id, email_hash_version,
    name_ciphertext, name_nonce, name_enc_key_id, name_enc_version,
    created_at, updated_at
) VALUES ($1, $2, 'active', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14);

-- name: InsertUserIdentity :exec
INSERT INTO user_identities (
    id, user_id, provider,
    provider_sub_hash, provider_sub_hash_key_id, provider_sub_hash_version,
    provider_sub_ciphertext, provider_sub_nonce, provider_sub_enc_key_id, provider_sub_enc_version,
    created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetUserByProviderSubHash :one
SELECT u.id, u.email_verified, u.status,
       u.email_ciphertext, u.email_nonce, u.email_enc_key_id, u.email_enc_version,
       u.name_ciphertext, u.name_nonce, u.name_enc_key_id, u.name_enc_version,
       u.created_at, u.updated_at
FROM users u
JOIN user_identities ui ON u.id = ui.user_id
WHERE ui.provider = $1 AND ui.provider_sub_hash = $2;

-- name: GetUserByID :one
SELECT id, email_verified, status,
       email_ciphertext, email_nonce, email_enc_key_id, email_enc_version,
       name_ciphertext, name_nonce, name_enc_key_id, name_enc_version,
       created_at, updated_at
FROM users
WHERE id = $1;

-- name: GetUserForTxByID :one
SELECT id, email_verified, status,
       email_ciphertext, email_nonce, email_enc_key_id, email_enc_version,
       name_ciphertext, name_nonce, name_enc_key_id, name_enc_version
FROM users
WHERE id = $1;

-- name: GetUserInfoFieldsByID :one
SELECT id, email_verified,
       email_ciphertext, email_nonce, email_enc_key_id, email_enc_version,
       name_ciphertext, name_nonce, name_enc_key_id, name_enc_version
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
