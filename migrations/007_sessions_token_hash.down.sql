DROP INDEX IF EXISTS sessions_token_hash_key;

ALTER TABLE sessions DROP COLUMN IF EXISTS token_hash;
