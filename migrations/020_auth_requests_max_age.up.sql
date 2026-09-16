-- OIDC Core 3.1.2.1 max_age: the seconds the RP is willing to accept since the
-- End-User last authenticated. NULL means the RP did not ask, which is not the
-- same as 0 (prompt=login normalizes to 0: re-authenticate now).
ALTER TABLE auth_requests
ADD COLUMN max_age BIGINT;
