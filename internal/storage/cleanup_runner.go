package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// CleanupRunner encapsulates sqlc-backed cleanup queries.
type CleanupRunner struct {
	db *sql.DB
}

const cleanupAdvisoryLockKey int64 = 0x6175746867617465 // "authgate" hex (stable process-wide lock key)
const cleanupBatchSize = 1000

func NewCleanupRunner(db *sql.DB) *CleanupRunner {
	return &CleanupRunner{db: db}
}

func (r *CleanupRunner) WithExclusiveLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, cleanupAdvisoryLockKey).Scan(&acquired); err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}

	runErr := fn(ctx)

	var released bool
	unlockErr := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, cleanupAdvisoryLockKey).Scan(&released)

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

func (r *CleanupRunner) DeleteRevokedRefreshTokensBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	var total int64
	for {
		rows, err := q.DeleteRevokedRefreshTokensBatch(ctx, storeq.DeleteRevokedRefreshTokensBatchParams{
			Cutoff:    sql.NullTime{Time: cutoff, Valid: true},
			BatchSize: cleanupBatchSize,
		})
		if err != nil {
			return total, err
		}
		total += rows
		if rows < cleanupBatchSize {
			return total, nil
		}
	}
}

func (r *CleanupRunner) DeleteExpiredRefreshTokensBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	var total int64
	for {
		rows, err := q.DeleteExpiredRefreshTokensBatch(ctx, storeq.DeleteExpiredRefreshTokensBatchParams{
			Cutoff:    cutoff,
			BatchSize: cleanupBatchSize,
		})
		if err != nil {
			return total, err
		}
		total += rows
		if rows < cleanupBatchSize {
			return total, nil
		}
	}
}

func (r *CleanupRunner) DeleteExpiredOrRevokedSessions(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	var total int64
	for {
		rows, err := q.DeleteExpiredOrRevokedSessionsBatch(ctx, storeq.DeleteExpiredOrRevokedSessionsBatchParams{
			Cutoff:    cutoff,
			BatchSize: cleanupBatchSize,
		})
		if err != nil {
			return total, err
		}
		total += rows
		if rows < cleanupBatchSize {
			return total, nil
		}
	}
}

func (r *CleanupRunner) DeleteExpiredAuthRequestsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	var total int64
	for {
		rows, err := q.DeleteExpiredAuthRequestsBatch(ctx, storeq.DeleteExpiredAuthRequestsBatchParams{
			Cutoff:    cutoff,
			BatchSize: cleanupBatchSize,
		})
		if err != nil {
			return total, err
		}
		total += rows
		if rows < cleanupBatchSize {
			return total, nil
		}
	}
}

func (r *CleanupRunner) DeleteExpiredDeviceCodesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	var total int64
	for {
		rows, err := q.DeleteExpiredDeviceCodesBatch(ctx, storeq.DeleteExpiredDeviceCodesBatchParams{
			Cutoff:    cutoff,
			BatchSize: cleanupBatchSize,
		})
		if err != nil {
			return total, err
		}
		total += rows
		if rows < cleanupBatchSize {
			return total, nil
		}
	}
}

func (r *CleanupRunner) ListPendingDeletionUserIDsBefore(ctx context.Context, cutoff time.Time) ([]string, error) {
	return storeq.New(r.db).ListPendingDeletionUserIDsBefore(ctx, sql.NullTime{Time: cutoff, Valid: true})
}

func (r *CleanupRunner) AnonymizeAuditLogBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := storeq.New(r.db)
	var total int64
	for {
		rows, err := q.AnonymizeAuditLogBatch(ctx, storeq.AnonymizeAuditLogBatchParams{
			Cutoff:    cutoff,
			BatchSize: cleanupBatchSize,
		})
		if err != nil {
			return total, err
		}
		total += rows
		if rows < cleanupBatchSize {
			return total, nil
		}
	}
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
	defer tx.Rollback()
	qtx := storeq.New(tx)

	if err := qtx.DeleteUserIdentitiesByUserID(ctx, userID); err != nil {
		return err
	}
	if err := qtx.DeleteSessionsByUserID(ctx, userID); err != nil {
		return err
	}
	if err := qtx.DeleteRefreshTokensByUserID(ctx, userID); err != nil {
		return err
	}
	if hook != nil {
		if err := hook(ctx, userID); err != nil {
			return err
		}
	}

	if err := qtx.MarkUserDeletedByID(ctx, storeq.MarkUserDeletedByIDParams{
		DeletedAt: sql.NullTime{Time: now, Valid: true},
		UserID:    userID,
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	_ = storeq.New(r.db).InsertDeletionCompletedAudit(ctx, storeq.InsertDeletionCompletedAuditParams{
		UserID:    userID,
		CreatedAt: now,
	})
	return nil
}
