ALTER TABLE user_identities
    DROP COLUMN IF EXISTS provider_email,
    DROP COLUMN IF EXISTS provider_raw;
