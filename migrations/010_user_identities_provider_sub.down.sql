DROP INDEX IF EXISTS user_identities_provider_sub_hash_key;

ALTER TABLE user_identities
    DROP CONSTRAINT IF EXISTS user_identities_provider_sub_hash_consistency,
    DROP CONSTRAINT IF EXISTS user_identities_provider_sub_enc_consistency;

ALTER TABLE user_identities
    DROP COLUMN IF EXISTS provider_sub_hash,
    DROP COLUMN IF EXISTS provider_sub_hash_key_id,
    DROP COLUMN IF EXISTS provider_sub_hash_version,
    DROP COLUMN IF EXISTS provider_sub_ciphertext,
    DROP COLUMN IF EXISTS provider_sub_nonce,
    DROP COLUMN IF EXISTS provider_sub_enc_key_id,
    DROP COLUMN IF EXISTS provider_sub_enc_version;

-- Note: provider_user_id NOT NULL is not restored here because rows written
-- after the up migration may have a NULL provider_user_id.
