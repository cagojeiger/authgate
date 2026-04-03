package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// CleanupRunner encapsulates sqlc-backed cleanup queries.
type CleanupRunner struct {
	db *sql.DB
}

func NewCleanupRunner(db *sql.DB) *CleanupRunner {
	return &CleanupRunner{db: db}
}

func (r *CleanupRunner) DeleteRevokedRefreshTokensBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	return storeq.New(r.db).DeleteRevokedRefreshTokensBefore(ctx, sql.NullTime{Time: cutoff, Valid: true})
}

func (r *CleanupRunner) DeleteExpiredRefreshTokensBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	return storeq.New(r.db).DeleteExpiredRefreshTokensBefore(ctx, cutoff)
}

func (r *CleanupRunner) DeleteExpiredOrRevokedSessions(ctx context.Context, cutoff time.Time) (int64, error) {
	return storeq.New(r.db).DeleteExpiredOrRevokedSessions(ctx, cutoff)
}

func (r *CleanupRunner) DeleteExpiredAuthRequestsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	return storeq.New(r.db).DeleteExpiredAuthRequestsBefore(ctx, cutoff)
}

func (r *CleanupRunner) DeleteExpiredDeviceCodesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	return storeq.New(r.db).DeleteExpiredDeviceCodesBefore(ctx, cutoff)
}

func (r *CleanupRunner) ListPendingDeletionUserIDsBefore(ctx context.Context, cutoff time.Time) ([]string, error) {
	return storeq.New(r.db).ListPendingDeletionUserIDsBefore(ctx, sql.NullTime{Time: cutoff, Valid: true})
}

func (r *CleanupRunner) AnonymizeAuditLogBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	return storeq.New(r.db).AnonymizeAuditLogBefore(ctx, cutoff)
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
