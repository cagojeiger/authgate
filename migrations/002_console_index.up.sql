CREATE INDEX idx_refresh_tokens_active_connections
    ON refresh_tokens (user_id, expires_at, client_id)
    WHERE revoked_at IS NULL;
