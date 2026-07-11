-- The cleanup job (internal/db/queries/cleanup.sql) runs every 10 minutes and
-- deletes expired/revoked rows filtered on expires_at / revoked_at. None of
-- these columns is indexed, so every cycle sequential-scans refresh_tokens,
-- sessions, auth_requests and device_codes — tables that grow with login
-- traffic. revoked_at indexes are partial: most rows have revoked_at IS NULL
-- and the cleanup predicates only match non-null values.
CREATE INDEX IF NOT EXISTS refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);
CREATE INDEX IF NOT EXISTS refresh_tokens_revoked_at_idx ON refresh_tokens (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS sessions_revoked_at_idx ON sessions (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS auth_requests_expires_at_idx ON auth_requests (expires_at);
CREATE INDEX IF NOT EXISTS device_codes_expires_at_idx ON device_codes (expires_at);
