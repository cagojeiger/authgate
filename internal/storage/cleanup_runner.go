package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// CleanupRunner encapsulates sqlc-backed cleanup queries.
type CleanupRunner struct {
	db *sql.DB
}

const cleanupAdvisoryLockKey int64 = 0x6175746867617465 // "authgate" hex (stable process-wide lock key)

func NewCleanupRunner(db *sql.DB) *CleanupRunner {
	return &CleanupRunner{db: db}
}

func (r *CleanupRunner) WithExclusiveLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	qconn := storeq.New(conn)

	acquired, err := qconn.TryCleanupAdvisoryLock(ctx, cleanupAdvisoryLockKey)
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}

	runErr := fn(ctx)

	released, unlockErr := qconn.UnlockCleanupAdvisoryLock(ctx, cleanupAdvisoryLockKey)

	if runErr != nil {
		return true, runErr
	}
	if unlockErr != nil {
		return true, unlockErr
	}
	if !released {
		return true, fmt.Errorf("cleanup advisory unlock failed")
	}
	return true, nil
}

// cleanupBatchSize bounds each cleanup DELETE so a large backlog (e.g. after
// downtime) is drained in bounded transactions rather than one statement that
// locks a table while deleting millions of rows. Overridable in tests to
// exercise the multi-iteration batch loop without inserting 10k+ rows.
var cleanupBatchSize int32 = 10_000

// deleteInBatches calls del with the batch size repeatedly until a call returns
// fewer rows than the batch size (the table is drained), summing the total. On
// error it returns the running total alongside the error.
func deleteInBatches(ctx context.Context, del func(ctx context.Context, batch int32) (int64, error)) (int64, error) {
	var total int64
	for {
		n, err := del(ctx, cleanupBatchSize)
		total += n
		if err != nil {
			return total, err
		}
		if n < int64(cleanupBatchSize) {
			return total, nil
		}
	}
}

func (r *CleanupRunner) DeleteRevokedRefreshTokensBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	return deleteInBatches(ctx, func(ctx context.Context, batch int32) (int64, error) {
		return q.DeleteRevokedRefreshTokensBefore(ctx, storeq.DeleteRevokedRefreshTokensBeforeParams{
			Cutoff: sql.NullTime{Time: cutoff, Valid: true}, BatchSize: batch,
		})
	})
}

func (r *CleanupRunner) DeleteExpiredRefreshTokensBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	return deleteInBatches(ctx, func(ctx context.Context, batch int32) (int64, error) {
		return q.DeleteExpiredRefreshTokensBefore(ctx, storeq.DeleteExpiredRefreshTokensBeforeParams{
			Cutoff: cutoff, BatchSize: batch,
		})
	})
}

func (r *CleanupRunner) DeleteExpiredOrRevokedSessions(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	return deleteInBatches(ctx, func(ctx context.Context, batch int32) (int64, error) {
		return q.DeleteExpiredOrRevokedSessions(ctx, storeq.DeleteExpiredOrRevokedSessionsParams{
			Cutoff: cutoff, BatchSize: batch,
		})
	})
}

func (r *CleanupRunner) DeleteExpiredAuthRequestsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	return deleteInBatches(ctx, func(ctx context.Context, batch int32) (int64, error) {
		return q.DeleteExpiredAuthRequestsBefore(ctx, storeq.DeleteExpiredAuthRequestsBeforeParams{
			Cutoff: cutoff, BatchSize: batch,
		})
	})
}

func (r *CleanupRunner) DeleteExpiredDeviceCodesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	return deleteInBatches(ctx, func(ctx context.Context, batch int32) (int64, error) {
		return q.DeleteExpiredDeviceCodesBefore(ctx, storeq.DeleteExpiredDeviceCodesBeforeParams{
			Cutoff: cutoff, BatchSize: batch,
		})
	})
}

func (r *CleanupRunner) ListPendingDeletionUserIDsBefore(ctx context.Context, cutoff time.Time) ([]string, error) {
	return storeq.New(r.db).ListPendingDeletionUserIDsBefore(ctx, sql.NullTime{Time: cutoff, Valid: true})
}

func (r *CleanupRunner) AnonymizeUserAuditLogBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	return storeq.New(r.db).AnonymizeUserAuditLogBefore(ctx, cutoff)
}

func (r *CleanupRunner) AnonymizeAdminAuditLogBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	return storeq.New(r.db).AnonymizeAdminAuditLogBefore(ctx, cutoff)
}

func (r *CleanupRunner) DeleteStaleRefreshTokenFamiliesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	return deleteInBatches(ctx, func(ctx context.Context, batch int32) (int64, error) {
		return q.DeleteStaleRefreshTokenFamiliesBefore(ctx, storeq.DeleteStaleRefreshTokenFamiliesBeforeParams{
			Cutoff: cutoff, BatchSize: batch,
		})
	})
}

func (r *CleanupRunner) RedactAuditLogPIIByUserID(ctx context.Context, userID string) (int64, error) {
	return storeq.New(r.db).RedactAuditLogPIIByUserID(ctx, userID)
}

func (r *CleanupRunner) DeleteUser(
	ctx context.Context,
	userID string,
	now time.Time,
	hook func(ctx context.Context, userID string) error,
) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	qtx := storeq.New(tx)

	// #182: run the guarded parent UPDATE first so the child deletes only
	// happen for a user that is still pending_deletion and still past the
	// scheduled date. The successful UPDATE acquires a row-level lock that
	// holds for the rest of the TX, preventing a concurrent
	// browser-channel recovery from flipping the user back to active
	// while we're wiping their identities.
	rows, err := qtx.MarkUserDeletedByID(ctx, storeq.MarkUserDeletedByIDParams{
		DeletedAt: sql.NullTime{Time: now, Valid: true},
		UserID:    userID,
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		// User is no longer eligible (recovered to active, or another
		// cleanup tick already deleted them). Roll back and skip silently —
		// the runner is best-effort and idempotent across ticks.
		slog.InfoContext(ctx, "deletion cleanup skipped: user no longer eligible",
			"user_id", userID,
		)
		return nil
	}

	if err := qtx.DeleteUserIdentitiesByUserID(ctx, userID); err != nil {
		return err
	}
	if err := qtx.DeleteSessionsByUserID(ctx, userID); err != nil {
		return err
	}
	if err := qtx.DeleteRefreshTokensByUserID(ctx, userID); err != nil {
		return err
	}
	if _, err := qtx.RedactAuditLogPIIByUserID(ctx, userID); err != nil {
		return err
	}
	if hook != nil {
		if err := hook(ctx, userID); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	if err := storeq.New(r.db).InsertDeletionCompletedAudit(ctx, storeq.InsertDeletionCompletedAuditParams{
		UserID:    userID,
		Reason:    "pending_deletion_expired",
		CreatedAt: now,
	}); err != nil {
		slog.ErrorContext(ctx, "audit log: insert deletion_completed",
			"event_type", EventAuthDeletionCompleted,
			"user_id", userID,
			"error", err,
		)
	}
	return nil
}
