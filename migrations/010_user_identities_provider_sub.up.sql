-- provider subject를 평문(provider_user_id)이 아니라 lookup HMAC + AEAD ciphertext로
-- 저장한다 (ADR-002). hash는 로그인 매칭(결정적), ciphertext는 LOOKUP root 회전 시
-- rehash를 위한 복구용. 평문 provider_user_id는 백필 후 cleanup PR에서 제거한다.
ALTER TABLE user_identities
    ADD COLUMN provider_sub_hash         TEXT,
    ADD COLUMN provider_sub_hash_key_id  TEXT REFERENCES crypto_key_epochs(key_id),
    ADD COLUMN provider_sub_hash_version INTEGER,
    ADD COLUMN provider_sub_ciphertext   BYTEA,
    ADD COLUMN provider_sub_nonce        BYTEA,
    ADD COLUMN provider_sub_enc_key_id   TEXT REFERENCES crypto_key_epochs(key_id),
    ADD COLUMN provider_sub_enc_version  INTEGER;

-- 백필 전까지 기존 행은 평문만, 신규 행은 암호화만 → 평문 컬럼을 nullable로.
ALTER TABLE user_identities ALTER COLUMN provider_user_id DROP NOT NULL;

-- 동반 컬럼은 전부 NULL이거나 전부 NOT NULL (백필 전 행은 전자, 신규 행은 후자).
ALTER TABLE user_identities
    ADD CONSTRAINT user_identities_provider_sub_hash_consistency CHECK (
        (provider_sub_hash IS NULL AND provider_sub_hash_key_id IS NULL AND provider_sub_hash_version IS NULL)
        OR
        (provider_sub_hash IS NOT NULL AND provider_sub_hash_key_id IS NOT NULL AND provider_sub_hash_version IS NOT NULL)
    ),
    ADD CONSTRAINT user_identities_provider_sub_enc_consistency CHECK (
        (provider_sub_ciphertext IS NULL AND provider_sub_nonce IS NULL AND provider_sub_enc_key_id IS NULL AND provider_sub_enc_version IS NULL)
        OR
        (provider_sub_ciphertext IS NOT NULL AND provider_sub_nonce IS NOT NULL AND provider_sub_enc_key_id IS NOT NULL AND provider_sub_enc_version IS NOT NULL)
    );

-- 로그인 매칭 UNIQUE를 hash로. 기존 UNIQUE(provider, provider_user_id)는 cleanup까지 공존.
CREATE UNIQUE INDEX user_identities_provider_sub_hash_key
    ON user_identities (provider, provider_sub_hash);
