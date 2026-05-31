package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/storage"
)

const (
	workerLockKey int64 = 0x617574686e6f7469 // "authnoti"
)

type Store struct {
	db    *sql.DB
	clock clock.Clock
}

type OutboxEvent struct {
	ID           int64
	UserID       string
	EventType    string
	Metadata     map[string]any
	CreatedAt    time.Time
	AttemptCount int
}

type Summary struct {
	TotalUsers        int64
	ActiveUsers       int64
	SignupCount       int64
	DeletionRequested int64
	DeletionCompleted int64
	RefreshReuse      int64
	ChannelMismatch   int64
	LoginByChannel    map[string]int64
}

func NewStore(db *sql.DB, clk clock.Clock) *Store {
	return &Store{db: db, clock: clk}
}

func (s *Store) EnqueueAuditEvent(ctx context.Context, event storage.AuditEvent) error {
	rawMetadata, err := marshalMetadata(event.Metadata)
	if err != nil {
		return err
	}
	userID := ""
	if event.UserID != nil {
		userID = *event.UserID
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO notification_outbox (user_id, event_type, metadata, available_at, created_at)
VALUES (NULLIF($1, '')::uuid, $2, $3::jsonb, $4, $4)
`, userID, event.EventType, rawMetadata, event.CreatedAt)
	return err
}

func (s *Store) WithWorkerLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	return s.withExclusiveLock(ctx, workerLockKey, fn)
}

func (s *Store) withExclusiveLock(ctx context.Context, lockKey int64, fn func(context.Context) error) (bool, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&acquired); err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}

	runErr := fn(ctx)
	var released bool
	unlockErr := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, lockKey).Scan(&released)
	if runErr != nil {
		return true, runErr
	}
	if unlockErr != nil {
		return true, unlockErr
	}
	if !released {
		return true, fmt.Errorf("notification advisory unlock failed")
	}
	return true, nil
}

func (s *Store) PendingOutboxEvents(ctx context.Context, limit int) ([]OutboxEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, COALESCE(user_id::text, ''), event_type, metadata, created_at, attempt_count
FROM notification_outbox
WHERE sent_at IS NULL AND available_at <= $1
ORDER BY id
LIMIT $2
`, s.clock.Now(), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var events []OutboxEvent
	for rows.Next() {
		var event OutboxEvent
		var rawMetadata []byte
		if err := rows.Scan(&event.ID, &event.UserID, &event.EventType, &rawMetadata, &event.CreatedAt, &event.AttemptCount); err != nil {
			return nil, err
		}
		event.Metadata, err = unmarshalMetadata(rawMetadata)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) MarkOutboxSent(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE notification_outbox
SET sent_at = $1, last_error = NULL
WHERE id = $2
`, s.clock.Now(), id)
	return err
}

func (s *Store) MarkOutboxFailed(ctx context.Context, id int64, nextAttempt time.Time, sendErr error) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE notification_outbox
SET attempt_count = attempt_count + 1,
    available_at = $1,
    last_error = $2
WHERE id = $3
`, nextAttempt, truncateError(sendErr), id)
	return err
}

func (s *Store) ClaimReportRun(ctx context.Context, reportType string, periodStart, periodEnd time.Time) (int64, bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
INSERT INTO notification_report_runs (
    report_type, period_start, period_end, status, created_at, updated_at
) VALUES ($1, $2, $3, 'pending', $4, $4)
ON CONFLICT (report_type, period_start, period_end) DO UPDATE
SET status = 'pending',
    updated_at = EXCLUDED.updated_at
WHERE notification_report_runs.status <> 'sent'
RETURNING id
`, reportType, periodStart, periodEnd, s.clock.Now()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func (s *Store) MarkReportSent(ctx context.Context, id int64) error {
	now := s.clock.Now()
	_, err := s.db.ExecContext(ctx, `
UPDATE notification_report_runs
SET status = 'sent',
    sent_at = $1,
    updated_at = $1,
    last_error = NULL
WHERE id = $2
`, now, id)
	return err
}

func (s *Store) MarkReportFailed(ctx context.Context, id int64, sendErr error) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE notification_report_runs
SET status = 'failed',
    attempt_count = attempt_count + 1,
    last_error = $1,
    updated_at = $2
WHERE id = $3
`, truncateError(sendErr), s.clock.Now(), id)
	return err
}

func (s *Store) WeeklySummary(ctx context.Context, periodStart, periodEnd time.Time) (Summary, error) {
	var summary Summary
	err := s.db.QueryRowContext(ctx, `
SELECT
    COUNT(*),
    COUNT(*) FILTER (WHERE status = 'active')
FROM users
`).Scan(&summary.TotalUsers, &summary.ActiveUsers)
	if err != nil {
		return Summary{}, err
	}

	counts, err := s.auditCounts(ctx, periodStart, periodEnd)
	if err != nil {
		return Summary{}, err
	}
	summary.SignupCount = counts["auth.signup"]
	summary.DeletionRequested = counts["auth.deletion_requested"]
	summary.DeletionCompleted = counts["auth.deletion_completed"]
	summary.RefreshReuse = counts["auth.refresh_reuse_detected"]
	summary.ChannelMismatch = counts["auth.channel_mismatch"]

	summary.LoginByChannel, err = s.loginCountsByChannel(ctx, periodStart, periodEnd)
	if err != nil {
		return Summary{}, err
	}
	return summary, nil
}

func (s *Store) auditCounts(ctx context.Context, periodStart, periodEnd time.Time) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT event_type, COUNT(*)
FROM audit_log
WHERE created_at >= $1 AND created_at < $2
  AND event_type IN (
    'auth.signup',
    'auth.deletion_requested',
    'auth.deletion_completed',
    'auth.refresh_reuse_detected',
    'auth.channel_mismatch'
  )
GROUP BY event_type
`, periodStart, periodEnd)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	counts := map[string]int64{}
	for rows.Next() {
		var eventType string
		var count int64
		if err := rows.Scan(&eventType, &count); err != nil {
			return nil, err
		}
		counts[eventType] = count
	}
	return counts, rows.Err()
}

func (s *Store) loginCountsByChannel(ctx context.Context, periodStart, periodEnd time.Time) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT COALESCE(NULLIF(metadata->>'channel', ''), 'unknown') AS channel, COUNT(*)
FROM audit_log
WHERE created_at >= $1 AND created_at < $2
  AND event_type = 'auth.login'
GROUP BY channel
`, periodStart, periodEnd)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	counts := map[string]int64{}
	for rows.Next() {
		var channel string
		var count int64
		if err := rows.Scan(&channel, &count); err != nil {
			return nil, err
		}
		counts[channel] = count
	}
	return counts, rows.Err()
}

func marshalMetadata(metadata map[string]any) ([]byte, error) {
	if len(metadata) == 0 {
		return nil, nil
	}
	return json.Marshal(metadata)
}

func unmarshalMetadata(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

func truncateError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) <= 1000 {
		return msg
	}
	return msg[:1000]
}
