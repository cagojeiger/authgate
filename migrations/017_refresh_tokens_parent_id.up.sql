-- The token a refresh token was rotated from. Lets the refresh reuse grace
-- count the children of one redemption exactly: family and time alone also
-- match the tokens other sessions rotate at the same moment.
-- No foreign key: cleanup deletes parents before their children expire.
ALTER TABLE refresh_tokens
ADD COLUMN parent_id UUID;

CREATE INDEX refresh_tokens_parent_id_idx ON refresh_tokens (parent_id)
WHERE parent_id IS NOT NULL;
