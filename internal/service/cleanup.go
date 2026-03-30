package service

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

type CleanupService struct {
	db       *sql.DB
	clock    clock.Clock
	interval time.Duration
}

func NewCleanupService(db *sql.DB, clk clock.Clock, interval time.Duration) *CleanupService {
	return &CleanupService{db: db, clock: clk, interval: interval}
}

// Start runs cleanup jobs periodically until ctx is cancelled.
func (c *CleanupService) Start(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// Run once immediately
	c.runAll(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("cleanup service stopped")
			return
		case <-ticker.C:
			c.runAll(ctx)
		}
	}
}

func (c *CleanupService) runAll(ctx context.Context) {
	now := c.clock.Now()

	// 1. Token cleanup: revoked/expired refresh_tokens after 30 days
	if res, err := c.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE revoked_at IS NOT NULL AND revoked_at < $1`,
		now.Add(-30*24*time.Hour),
	); err != nil {
		slog.Error("token cleanup (revoked)", "error", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("token cleanup (revoked)", "deleted", n)
	}

	if res, err := c.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE expires_at < $1`,
		now.Add(-30*24*time.Hour),
	); err != nil {
		slog.Error("token cleanup (expired)", "error", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("token cleanup (expired)", "deleted", n)
	}

	// 2. Session cleanup: expired or revoked sessions
	if res, err := c.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at < $1 OR revoked_at IS NOT NULL`,
		now,
	); err != nil {
		slog.Error("session cleanup", "error", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("session cleanup", "deleted", n)
	}

	// 3. Temp data cleanup: auth_requests expired > 1 hour
	if res, err := c.db.ExecContext(ctx,
		`DELETE FROM auth_requests WHERE expires_at < $1`,
		now.Add(-1*time.Hour),
	); err != nil {
		slog.Error("auth_requests cleanup", "error", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("auth_requests cleanup", "deleted", n)
	}

	// 4. Temp data cleanup: device_codes expired > 1 hour
	if res, err := c.db.ExecContext(ctx,
		`DELETE FROM device_codes WHERE expires_at < $1`,
		now.Add(-1*time.Hour),
	); err != nil {
		slog.Error("device_codes cleanup", "error", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("device_codes cleanup", "deleted", n)
	}

	// 5. Onboarding cleanup: active users with NULL terms for 7+ days
	if res, err := c.db.ExecContext(ctx,
		`DELETE FROM users WHERE status = 'active'
		 AND (terms_accepted_at IS NULL OR privacy_accepted_at IS NULL)
		 AND created_at < $1`,
		now.Add(-7*24*time.Hour),
	); err != nil {
		slog.Error("onboarding cleanup", "error", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("onboarding cleanup", "deleted", n)
	}
}

// RunOnce executes all cleanup jobs once. For testing.
func (c *CleanupService) RunOnce(ctx context.Context) {
	c.runAll(ctx)
}
