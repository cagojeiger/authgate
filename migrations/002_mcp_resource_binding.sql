-- MCP OAuth 2.1 resource binding
-- Adds per-grant resource state so MCP access/refresh tokens can remain bound
-- to a canonical protected resource across code exchange and refresh rotation.

ALTER TABLE auth_requests
ADD COLUMN IF NOT EXISTS resource TEXT;

ALTER TABLE refresh_tokens
ADD COLUMN IF NOT EXISTS resource TEXT;
