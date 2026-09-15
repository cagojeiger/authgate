-- OIDC prompt values from /authorize (none, login, select_account, consent).
-- The login handlers read them to decide whether an existing session may be
-- reused or the request must end without interaction.
ALTER TABLE auth_requests
ADD COLUMN prompt TEXT[] NOT NULL DEFAULT '{}';
