-- name: InsertAuthRequest :exec
INSERT INTO auth_requests (
  id, client_id, resource, redirect_uri, scopes, state, nonce,
  code_challenge, code_challenge_method, expires_at, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetAuthRequestByID :one
SELECT id,
       client_id,
       COALESCE(resource, '') AS resource,
       redirect_uri,
       scopes,
       COALESCE(state, '') AS state,
       COALESCE(nonce, '') AS nonce,
       COALESCE(code_challenge, '') AS code_challenge,
       COALESCE(code_challenge_method, '') AS code_challenge_method,
       subject,
       auth_time,
       done,
       code,
       expires_at,
       created_at
FROM auth_requests
WHERE id = $1;

-- name: GetAuthRequestByCode :one
SELECT id,
       client_id,
       COALESCE(resource, '') AS resource,
       redirect_uri,
       scopes,
       COALESCE(state, '') AS state,
       COALESCE(nonce, '') AS nonce,
       COALESCE(code_challenge, '') AS code_challenge,
       COALESCE(code_challenge_method, '') AS code_challenge_method,
       subject,
       auth_time,
       done,
       code,
       expires_at,
       created_at
FROM auth_requests
WHERE code = $1;

-- name: UpdateAuthRequestCode :exec
UPDATE auth_requests
SET code = $1
WHERE id = $2;

-- name: DeleteAuthRequestByID :exec
DELETE FROM auth_requests
WHERE id = $1;
