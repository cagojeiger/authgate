-- account별 PII data encryption key(DEK)를 key encryption key(KEK)로 wrap한
-- metadata를 저장한다 (ADR-002). DEK 원문은 저장하지 않고, KEK material은 DB 밖에 둔다.
-- 탈퇴/강한 삭제 시 destroyed_at을 설정해 crypto-shredding한다(복호화 영구 불가).
CREATE TABLE account_encryption_keys (
    account_id   UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    wrapped_dek  BYTEA,
    kek_id       TEXT NOT NULL,
    kek_version  TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rewrapped_at TIMESTAMPTZ,
    destroyed_at TIMESTAMPTZ,
    -- 살아있는 키는 wrapped_dek가 있고, shred된 키는 wrapped_dek가 비어야 한다.
    CONSTRAINT account_encryption_keys_shred_consistency CHECK (
        (destroyed_at IS NULL AND wrapped_dek IS NOT NULL)
        OR
        (destroyed_at IS NOT NULL AND wrapped_dek IS NULL)
    )
);
