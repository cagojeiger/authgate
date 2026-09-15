DROP INDEX IF EXISTS refresh_tokens_parent_id_idx;

ALTER TABLE refresh_tokens
DROP COLUMN parent_id;
