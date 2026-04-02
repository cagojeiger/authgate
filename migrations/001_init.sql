-- authgate schema (Spec 007)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- users
CREATE TABLE users (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email                 TEXT NOT NULL UNIQUE,
    email_verified        BOOLEAN NOT NULL DEFAULT false,
    name                  TEXT,
    avatar_url            TEXT,
    status                TEXT NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active', 'disabled', 'pending_deletion', 'deleted')),
    deletion_requested_at TIMESTAMPTZ,
    deletion_scheduled_at TIMESTAMPTZ,
    deleted_at            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- user_identities
CREATE TABLE user_identities (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    provider_email   TEXT,
    provider_raw     JSONB,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_user_id)
);

-- sessions
CREATE TABLE sessions (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- refresh_tokens
CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash TEXT NOT NULL UNIQUE,
    family_id  UUID NOT NULL,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    resource   TEXT,
    scopes     TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- auth_requests
CREATE TABLE auth_requests (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id             TEXT NOT NULL,
    resource              TEXT,
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT[] NOT NULL DEFAULT '{}',
    state                 TEXT,
    nonce                 TEXT,
    code_challenge        TEXT,
    code_challenge_method TEXT DEFAULT 'S256',
    subject               TEXT,
    auth_time             TIMESTAMPTZ,
    done                  BOOLEAN NOT NULL DEFAULT false,
    code                  TEXT,
    expires_at            TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- device_codes
CREATE TABLE device_codes (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_code TEXT NOT NULL UNIQUE,
    user_code   TEXT NOT NULL UNIQUE,
    client_id   TEXT NOT NULL,
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    state       TEXT NOT NULL DEFAULT 'pending'
                CHECK (state IN ('pending', 'approved', 'denied', 'consumed')),
    subject     TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    auth_time   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- audit_log
CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    metadata   JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
