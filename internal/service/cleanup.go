package service

import (
	"context"
	"errors"
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
	AnonymizeUserAuditLogBefore(ctx context.Context, cutoff time.Time) (int64, error)
	AnonymizeAdminAuditLogBefore(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteStaleRefreshTokenFamiliesBefore(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteUser(ctx context.Context, userID string, now time.Time, hook func(ctx context.Context, userID string) error) error
}

// Retention windows for data that has no statutory minimum. Each is the
// shortest period that still serves a concrete purpose, so authgate holds as
// little as the function allows.
const (
	// revokedRefreshRetention keeps a rotated-out refresh token around long
	// enough to name the exact token in a replay investigation. Detection
	// itself does not depend on it: refresh_token_families tombstones catch a
	// replay after the row is gone.
	revokedRefreshRetention = 7 * 24 * time.Hour

	// expiredRefreshRetention is short because an expired token proves
	// nothing — it can no longer be redeemed and its family tombstone, if any,
	// outlives it.
	expiredRefreshRetention = 24 * time.Hour

	// familyTombstoneMargin is added to the refresh token TTL before a
	// tombstone is dropped. Once every token that could belong to the family
	// has expired the tombstone can never match again.
	familyTombstoneMargin = 7 * 24 * time.Hour

	// defaultUserAuditPIIRetention is the fallback window for end-user
	// activity records. It is an incident-investigation horizon, not a
	// statutory one — the access-record retention duty covers operators.
	defaultUserAuditPIIRetention = 90 * 24 * time.Hour

	// defaultAdminAuditPIIRetention covers operator actions, which are the
	// statutory access records. Two years leaves headroom above the one-year
	// baseline for when the data-subject count crosses the higher threshold.
	defaultAdminAuditPIIRetention = 730 * 24 * time.Hour
)

type CleanupService struct {
	runner                 cleanupRunner
	clock                  clock.Clock
	interval               time.Duration
	auditPIIRetention      time.Duration
	adminAuditPIIRetention time.Duration
	refreshTokenTTL        time.Duration
	deleteUserHook         func(ctx context.Context, userID string) error
}

func NewCleanupService(runner cleanupRunner, clk clock.Clock, interval time.Duration) *CleanupService {
	return &CleanupService{
		runner:                 runner,
		clock:                  clk,
		interval:               interval,
		auditPIIRetention:      defaultUserAuditPIIRetention,
		adminAuditPIIRetention: defaultAdminAuditPIIRetention,
		refreshTokenTTL:        30 * 24 * time.Hour,
	}
}

// SetAuditLogPIIRetention sets how long end-user activity records keep their
// identifying columns.
func (c *CleanupService) SetAuditLogPIIRetention(retention time.Duration) {
	if retention > 0 {
		c.auditPIIRetention = retention
	}
}

// SetAdminAuditLogPIIRetention sets how long operator-action records keep their
// identifying columns. These are the statutory access records.
func (c *CleanupService) SetAdminAuditLogPIIRetention(retention time.Duration) {
	if retention > 0 {
		c.adminAuditPIIRetention = retention
	}
}

// SetRefreshTokenTTL tells cleanup how long a refresh token can live, which
// determines when a family tombstone stops being able to match anything.
func (c *CleanupService) SetRefreshTokenTTL(ttl time.Duration) {
	if ttl > 0 {
		c.refreshTokenTTL = ttl
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
	var runErr error

	// 1. Token cleanup: revoked and expired refresh tokens.
	if n, err := c.runner.DeleteRevokedRefreshTokensBefore(ctx, now.Add(-revokedRefreshRetention)); err != nil {
		runErr = errors.Join(runErr, err)
		slog.Error("token cleanup (revoked)", "error", err)
	} else if n > 0 {
		slog.Info("token cleanup (revoked)", "deleted", n)
	}

	if n, err := c.runner.DeleteExpiredRefreshTokensBefore(ctx, now.Add(-expiredRefreshRetention)); err != nil {
		runErr = errors.Join(runErr, err)
		slog.Error("token cleanup (expired)", "error", err)
	} else if n > 0 {
		slog.Info("token cleanup (expired)", "deleted", n)
	}

	// 2. Session cleanup: expired or revoked sessions
	if n, err := c.runner.DeleteExpiredOrRevokedSessions(ctx, now); err != nil {
		runErr = errors.Join(runErr, err)
		slog.Error("session cleanup", "error", err)
	} else if n > 0 {
		slog.Info("session cleanup", "deleted", n)
	}

	// 3. Temp data cleanup: auth_requests expired > 1 hour
	if n, err := c.runner.DeleteExpiredAuthRequestsBefore(ctx, now.Add(-1*time.Hour)); err != nil {
		runErr = errors.Join(runErr, err)
		slog.Error("auth_requests cleanup", "error", err)
	} else if n > 0 {
		slog.Info("auth_requests cleanup", "deleted", n)
	}

	// 4. Temp data cleanup: device_codes expired > 1 hour
	if n, err := c.runner.DeleteExpiredDeviceCodesBefore(ctx, now.Add(-1*time.Hour)); err != nil {
		runErr = errors.Join(runErr, err)
		slog.Error("device_codes cleanup", "error", err)
	} else if n > 0 {
		slog.Info("device_codes cleanup", "deleted", n)
	}

	// 5. Deletion cleanup: pending_deletion users past scheduled date → PII scrub
	userIDs, err := c.runner.ListPendingDeletionUserIDsBefore(ctx, now)
	if err != nil {
		runErr = errors.Join(runErr, err)
		slog.Error("deletion cleanup query", "error", err)
	} else {
		for _, userID := range userIDs {
			if err := c.deleteUser(ctx, userID, now); err != nil {
				runErr = errors.Join(runErr, err)
				slog.Error("deletion cleanup", "user_id", userID, "error", err)
			} else {
				slog.Info("deletion cleanup", "user_id", userID)
			}
		}
	}

	// 6. Refresh token family tombstones that can no longer match a live token.
	if n, err := c.runner.DeleteStaleRefreshTokenFamiliesBefore(ctx, now.Add(-(c.refreshTokenTTL + familyTombstoneMargin))); err != nil {
		runErr = errors.Join(runErr, err)
		slog.Error("refresh family tombstone cleanup", "error", err)
	} else if n > 0 {
		slog.Info("refresh family tombstone cleanup", "deleted", n)
	}

	// 7. Audit log PII anonymization, on two clocks: end-user activity is
	// anonymized on the shorter investigation horizon, operator actions on the
	// statutory access-record horizon.
	if n, err := c.runner.AnonymizeUserAuditLogBefore(ctx, now.Add(-c.auditPIIRetention)); err != nil {
		runErr = errors.Join(runErr, err)
		slog.Error("audit_log anonymization (user)", "error", err)
	} else if n > 0 {
		slog.Info("audit_log anonymization (user)", "anonymized", n)
	}

	if n, err := c.runner.AnonymizeAdminAuditLogBefore(ctx, now.Add(-c.adminAuditPIIRetention)); err != nil {
		runErr = errors.Join(runErr, err)
		slog.Error("audit_log anonymization (admin)", "error", err)
	} else if n > 0 {
		slog.Info("audit_log anonymization (admin)", "anonymized", n)
	}
	return runErr
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
