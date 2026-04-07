package service

import (
	"context"
	"log/slog"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

type cleanupRunner interface {
	WithExclusiveLock(ctx context.Context, fn func(context.Context) error) (bool, error)
	DeleteRevokedRefreshTokensBefore(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteExpiredRefreshTokensBefore(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteExpiredOrRevokedSessions(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteExpiredAuthRequestsBefore(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteExpiredDeviceCodesBefore(ctx context.Context, cutoff time.Time) (int64, error)
	ListPendingDeletionUserIDsBefore(ctx context.Context, cutoff time.Time) ([]string, error)
	AnonymizeAuditLogBefore(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteUser(ctx context.Context, userID string, now time.Time, hook func(ctx context.Context, userID string) error) error
}

type CleanupService struct {
	runner         cleanupRunner
	clock          clock.Clock
	interval       time.Duration
	deleteUserHook func(ctx context.Context, userID string) error
}

func NewCleanupService(runner cleanupRunner, clk clock.Clock, interval time.Duration) *CleanupService {
	return &CleanupService{
		runner:   runner,
		clock:    clk,
		interval: interval,
	}
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
	acquired, err := c.runner.WithExclusiveLock(ctx, c.runAllLocked)
	if err != nil {
		slog.Error("cleanup run failed", "error", err)
		return
	}
	if !acquired {
		slog.Info("cleanup skipped: advisory lock not acquired")
		return
	}
}

func (c *CleanupService) runAllLocked(ctx context.Context) error {
	now := c.clock.Now()

	// 1. Token cleanup: revoked/expired refresh_tokens after 30 days
	if n, err := c.runner.DeleteRevokedRefreshTokensBefore(ctx, now.Add(-30*24*time.Hour)); err != nil {
		slog.Error("token cleanup (revoked)", "error", err)
	} else if n > 0 {
		slog.Info("token cleanup (revoked)", "deleted", n)
	}

	if n, err := c.runner.DeleteExpiredRefreshTokensBefore(ctx, now.Add(-30*24*time.Hour)); err != nil {
		slog.Error("token cleanup (expired)", "error", err)
	} else if n > 0 {
		slog.Info("token cleanup (expired)", "deleted", n)
	}

	// 2. Session cleanup: expired or revoked sessions
	if n, err := c.runner.DeleteExpiredOrRevokedSessions(ctx, now); err != nil {
		slog.Error("session cleanup", "error", err)
	} else if n > 0 {
		slog.Info("session cleanup", "deleted", n)
	}

	// 3. Temp data cleanup: auth_requests expired > 1 hour
	if n, err := c.runner.DeleteExpiredAuthRequestsBefore(ctx, now.Add(-1*time.Hour)); err != nil {
		slog.Error("auth_requests cleanup", "error", err)
	} else if n > 0 {
		slog.Info("auth_requests cleanup", "deleted", n)
	}

	// 4. Temp data cleanup: device_codes expired > 1 hour
	if n, err := c.runner.DeleteExpiredDeviceCodesBefore(ctx, now.Add(-1*time.Hour)); err != nil {
		slog.Error("device_codes cleanup", "error", err)
	} else if n > 0 {
		slog.Info("device_codes cleanup", "deleted", n)
	}

	// 5. Deletion cleanup: pending_deletion users past scheduled date → PII scrub
	userIDs, err := c.runner.ListPendingDeletionUserIDsBefore(ctx, now)
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
	if n, err := c.runner.AnonymizeAuditLogBefore(ctx, now.Add(-3*365*24*time.Hour)); err != nil {
		slog.Error("audit_log anonymization", "error", err)
	} else if n > 0 {
		slog.Info("audit_log anonymization", "anonymized", n)
	}
	return nil
}

// deleteUser performs Spec 006 stage 3: explicit DELETE of child records + PII scrub.
// CASCADE is NOT triggered because we UPDATE (not DELETE) the users row.
func (c *CleanupService) deleteUser(ctx context.Context, userID string, now time.Time) error {
	return c.runner.DeleteUser(ctx, userID, now, c.deleteUserHook)
}

// RunOnce executes all cleanup jobs once. For testing.
func (c *CleanupService) RunOnce(ctx context.Context) {
	c.runAll(ctx)
}
