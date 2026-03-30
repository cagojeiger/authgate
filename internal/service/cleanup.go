package service

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

type CleanupService struct {
	db             *sql.DB
	clock          clock.Clock
	interval       time.Duration
	deleteUserHook func(ctx context.Context, tx *sql.Tx, userID string) error
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

	// 5. Deletion cleanup: pending_deletion users past scheduled date → PII scrub
	rows, err := c.db.QueryContext(ctx,
		`SELECT id FROM users WHERE status = 'pending_deletion' AND deletion_scheduled_at < $1`, now)
	if err != nil {
		slog.Error("deletion cleanup query", "error", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var userID string
			if err := rows.Scan(&userID); err != nil {
				continue
			}
			if err := c.deleteUser(ctx, userID, now); err != nil {
				slog.Error("deletion cleanup", "user_id", userID, "error", err)
			} else {
				slog.Info("deletion cleanup", "user_id", userID)
			}
		}
	}

	// 6. Onboarding cleanup: active users with NULL terms for 7+ days
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

// deleteUser performs Spec 006 stage 3: explicit DELETE of child records + PII scrub.
// CASCADE is NOT triggered because we UPDATE (not DELETE) the users row.
func (c *CleanupService) deleteUser(ctx context.Context, userID string, now time.Time) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete child records explicitly (UPDATE doesn't trigger CASCADE)
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_identities WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if c.deleteUserHook != nil {
		if err := c.deleteUserHook(ctx, tx, userID); err != nil {
			return err
		}
	}

	// PII scrub + status transition
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET
		  email = 'deleted-' || id::text || '@deleted.invalid',
		  name = NULL, avatar_url = NULL,
		  status = 'deleted', deleted_at = $1,
		  deletion_requested_at = NULL, deletion_scheduled_at = NULL
		 WHERE id = $2 AND status = 'pending_deletion'`,
		now, userID,
	); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Audit after successful commit
	c.db.ExecContext(ctx,
		`INSERT INTO audit_log (user_id, event_type, created_at) VALUES ($1, 'auth.deletion_completed', $2)`,
		userID, now,
	)
	return nil
}

// RunOnce executes all cleanup jobs once. For testing.
func (c *CleanupService) RunOnce(ctx context.Context) {
	c.runAll(ctx)
}
