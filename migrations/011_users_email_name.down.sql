DROP INDEX IF EXISTS users_email_hash_key;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_email_enc_consistency,
    DROP CONSTRAINT IF EXISTS users_email_hash_consistency,
    DROP CONSTRAINT IF EXISTS users_name_enc_consistency;

ALTER TABLE users
    DROP COLUMN IF EXISTS email_ciphertext,
    DROP COLUMN IF EXISTS email_nonce,
    DROP COLUMN IF EXISTS email_enc_key_id,
    DROP COLUMN IF EXISTS email_enc_version,
    DROP COLUMN IF EXISTS email_hash,
    DROP COLUMN IF EXISTS email_hash_key_id,
    DROP COLUMN IF EXISTS email_hash_version,
    DROP COLUMN IF EXISTS name_ciphertext,
    DROP COLUMN IF EXISTS name_nonce,
    DROP COLUMN IF EXISTS name_enc_key_id,
    DROP COLUMN IF EXISTS name_enc_version;

-- email NOT NULL은 복원하지 않는다 (up 이후 행의 email이 NULL일 수 있음).
