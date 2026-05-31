CREATE TABLE notification_outbox (
    id            BIGSERIAL PRIMARY KEY,
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type    TEXT NOT NULL,
    metadata      JSONB,
    available_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at       TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX notification_outbox_pending_idx
    ON notification_outbox (available_at, id)
    WHERE sent_at IS NULL;

CREATE TABLE notification_report_runs (
    id            BIGSERIAL PRIMARY KEY,
    report_type   TEXT NOT NULL,
    period_start  TIMESTAMPTZ NOT NULL,
    period_end    TIMESTAMPTZ NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
    sent_at       TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (report_type, period_start, period_end)
);

CREATE INDEX notification_report_runs_pending_idx
    ON notification_report_runs (report_type, period_end)
    WHERE status <> 'sent';
