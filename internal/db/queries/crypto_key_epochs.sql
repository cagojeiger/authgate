-- name: GetActiveEpoch :one
SELECT key_id, verify_tag, version
FROM crypto_key_epochs
WHERE domain = $1 AND status = 'active';

-- name: InsertActiveEpoch :exec
INSERT INTO crypto_key_epochs (key_id, domain, status, verify_tag, version, created_at, activated_at)
VALUES ($1, $2, 'active', $3, 1, $4, $4)
ON CONFLICT DO NOTHING;
