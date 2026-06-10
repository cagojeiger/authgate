-- Foreign-key columns with ON DELETE CASCADE but no supporting index. A user
-- deletion cascades into these three child tables; without an index each
-- cascade does a sequential scan. refresh_tokens(family_id) is also scanned on
-- every refresh-token reuse detection (RevokeRefreshFamily WHERE family_id=$).
-- Existing UNIQUE/composite indexes do not lead with these columns, so none
-- cover these lookups.
CREATE INDEX IF NOT EXISTS user_identities_user_id_idx ON user_identities (user_id);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_family_id_idx ON refresh_tokens (family_id);
