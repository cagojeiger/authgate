-- users.email / users.name을 평문 대신 AEAD ciphertext로 저장한다 (ADR-002).
-- email은 uniqueness/lookup을 위해 HMAC(email_hash)도 함께 둔다. 평문 email/name은
-- 백필 후 cleanup PR에서 제거한다.
ALTER TABLE users
    ADD COLUMN email_ciphertext   BYTEA,
    ADD COLUMN email_nonce        BYTEA,
    ADD COLUMN email_enc_key_id   TEXT REFERENCES crypto_key_epochs(key_id),
    ADD COLUMN email_enc_version  INTEGER,
    ADD COLUMN email_hash         TEXT,
    ADD COLUMN email_hash_key_id  TEXT REFERENCES crypto_key_epochs(key_id),
    ADD COLUMN email_hash_version INTEGER,
    ADD COLUMN name_ciphertext    BYTEA,
    ADD COLUMN name_nonce         BYTEA,
    ADD COLUMN name_enc_key_id    TEXT REFERENCES crypto_key_epochs(key_id),
    ADD COLUMN name_enc_version   INTEGER;

-- 백필 전 행은 평문 email, 신규 행은 암호화 email → 평문 컬럼 nullable.
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;

-- uniqueness를 email_hash로 이동. 기존 users_email_key(평문)는 cleanup까지 공존.
CREATE UNIQUE INDEX users_email_hash_key ON users (email_hash);

ALTER TABLE users
    ADD CONSTRAINT users_email_enc_consistency CHECK (
        (email_ciphertext IS NULL AND email_nonce IS NULL AND email_enc_key_id IS NULL AND email_enc_version IS NULL)
        OR
        (email_ciphertext IS NOT NULL AND email_nonce IS NOT NULL AND email_enc_key_id IS NOT NULL AND email_enc_version IS NOT NULL)
    ),
    ADD CONSTRAINT users_email_hash_consistency CHECK (
        (email_hash IS NULL AND email_hash_key_id IS NULL AND email_hash_version IS NULL)
        OR
        (email_hash IS NOT NULL AND email_hash_key_id IS NOT NULL AND email_hash_version IS NOT NULL)
    ),
    ADD CONSTRAINT users_name_enc_consistency CHECK (
        (name_ciphertext IS NULL AND name_nonce IS NULL AND name_enc_key_id IS NULL AND name_enc_version IS NULL)
        OR
        (name_ciphertext IS NOT NULL AND name_nonce IS NOT NULL AND name_enc_key_id IS NOT NULL AND name_enc_version IS NOT NULL)
    );
