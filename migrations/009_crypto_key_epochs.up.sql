-- crypto_key_epochs: env로 주입되는 도메인 root secret의 epoch registry (ADR-002).
-- root secret 원문이나 파생 subkey는 저장하지 않고, 주입된 secret이 선언된 key_id와
-- 맞는지 검증하는 verify_tag와 rotation 상태만 저장한다.
CREATE TABLE crypto_key_epochs (
    key_id       TEXT PRIMARY KEY,
    domain       TEXT NOT NULL CHECK (domain IN ('enc', 'lookup')),
    status       TEXT NOT NULL CHECK (status IN ('active', 'verify_only', 'revoked')),
    verify_tag   TEXT NOT NULL,
    version      INTEGER NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    retired_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,

    CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$'),
    CHECK (
        (status = 'active' AND activated_at IS NOT NULL AND retired_at IS NULL AND revoked_at IS NULL)
        OR
        (status = 'verify_only' AND activated_at IS NOT NULL AND retired_at IS NOT NULL AND revoked_at IS NULL)
        OR
        (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

-- 도메인당 active epoch는 정확히 하나.
CREATE UNIQUE INDEX crypto_key_epochs_one_active_per_domain
    ON crypto_key_epochs (domain)
    WHERE status = 'active';
