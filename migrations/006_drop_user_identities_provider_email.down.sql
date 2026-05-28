ALTER TABLE user_identities
    ADD COLUMN IF NOT EXISTS provider_email TEXT,
    ADD COLUMN IF NOT EXISTS provider_raw JSONB;
