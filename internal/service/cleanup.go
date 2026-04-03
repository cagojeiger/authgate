package service

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/storage/storeq"
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
	q := storeq.New(c.db)

	// 1. Token cleanup: revoked/expired refresh_tokens after 30 days
	if n, err := q.DeleteRevokedRefreshTokensBefore(ctx, sql.NullTime{Time: now.Add(-30 * 24 * time.Hour), Valid: true}); err != nil {
		slog.Error("token cleanup (revoked)", "error", err)
	} else if n > 0 {
		slog.Info("token cleanup (revoked)", "deleted", n)
	}

	if n, err := q.DeleteExpiredRefreshTokensBefore(ctx, now.Add(-30*24*time.Hour)); err != nil {
		slog.Error("token cleanup (expired)", "error", err)
	} else if n > 0 {
		slog.Info("token cleanup (expired)", "deleted", n)
	}

	// 2. Session cleanup: expired or revoked sessions
	if n, err := q.DeleteExpiredOrRevokedSessions(ctx, now); err != nil {
		slog.Error("session cleanup", "error", err)
	} else if n > 0 {
		slog.Info("session cleanup", "deleted", n)
	}

	// 3. Temp data cleanup: auth_requests expired > 1 hour
	if n, err := q.DeleteExpiredAuthRequestsBefore(ctx, now.Add(-1*time.Hour)); err != nil {
		slog.Error("auth_requests cleanup", "error", err)
	} else if n > 0 {
		slog.Info("auth_requests cleanup", "deleted", n)
	}

	// 4. Temp data cleanup: device_codes expired > 1 hour
	if n, err := q.DeleteExpiredDeviceCodesBefore(ctx, now.Add(-1*time.Hour)); err != nil {
		slog.Error("device_codes cleanup", "error", err)
	} else if n > 0 {
		slog.Info("device_codes cleanup", "deleted", n)
	}

	// 5. Deletion cleanup: pending_deletion users past scheduled date → PII scrub
	userIDs, err := q.ListPendingDeletionUserIDsBefore(ctx, sql.NullTime{Time: now, Valid: true})
	if err != nil {
		slog.Error("deletion cleanup query", "error", err)
	} else {
		for _, userID := range userIDs {
			if err := c.deleteUser(ctx, userID, now); err != nil {
				slog.Error("deletion cleanup", "user_id", userID, "error", err)
			} else {
				slog.Info("deletion cleanup", "user_id", userID)
			}
		}
	}

	// 6. Audit log anonymization: user_id NULL after 3 years (Spec 007)
	if n, err := q.AnonymizeAuditLogBefore(ctx, now.Add(-3*365*24*time.Hour)); err != nil {
		slog.Error("audit_log anonymization", "error", err)
	} else if n > 0 {
		slog.Info("audit_log anonymization", "anonymized", n)
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
	qtx := storeq.New(tx)

	// Delete child records explicitly (UPDATE doesn't trigger CASCADE)
	if err := qtx.DeleteUserIdentitiesByUserID(ctx, userID); err != nil {
		return err
	}
	if err := qtx.DeleteSessionsByUserID(ctx, userID); err != nil {
		return err
	}
	if err := qtx.DeleteRefreshTokensByUserID(ctx, userID); err != nil {
		return err
	}
	if c.deleteUserHook != nil {
		if err := c.deleteUserHook(ctx, tx, userID); err != nil {
			return err
		}
	}

	// PII scrub + status transition (defense-in-depth: also check deletion_scheduled_at)
	if err := qtx.MarkUserDeletedByID(ctx, storeq.MarkUserDeletedByIDParams{
		DeletedAt: sql.NullTime{Time: now, Valid: true},
		UserID:    userID,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Audit after successful commit
	_ = storeq.New(c.db).InsertDeletionCompletedAudit(ctx, storeq.InsertDeletionCompletedAuditParams{
		UserID:    userID,
		CreatedAt: now,
	})
	return nil
}

// RunOnce executes all cleanup jobs once. For testing.
func (c *CleanupService) RunOnce(ctx context.Context) {
	c.runAll(ctx)
}
