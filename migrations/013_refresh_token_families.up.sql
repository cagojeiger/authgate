-- Family-level tombstone for refresh-token reuse detection. RevokeRefreshFamily
-- only flips revoked_at on rows that already exist, so a child token inserted
-- into a family in the narrow window just after a reuse-triggered family revoke
-- could escape revocation. This table records a permanent per-family tombstone
-- when reuse is detected; CreateAccessAndRefreshTokens refuses to issue a child
-- for a tombstoned family. Rows are sparse — only revoked families appear here.
CREATE TABLE refresh_token_families (
    family_id  UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason     TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX refresh_token_families_user_id_idx ON refresh_token_families (user_id);
