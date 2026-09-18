package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// RecoverUser recovers a pending_deletion user to active.
// If the user is not pending_deletion, it is a no-op.
func (s *Storage) RecoverUser(ctx context.Context, userID string) error {
	return storeq.New(s.db).RecoverPendingDeletionUserByID(ctx, storeq.RecoverPendingDeletionUserByIDParams{
		UpdatedAt: s.clock.Now(),
		ID:        userID,
	})
}

// SetUserStatus sets a user's status directly. For testing and admin operations.
func (s *Storage) SetUserStatus(ctx context.Context, userID, status string) error {
	return s.setUserStatus(ctx, userID, status)
}

// RequestDeletion sets a user to pending_deletion and revokes all refresh tokens. Single TX.
// Sessions are intentionally NOT revoked here — they expire naturally (24h TTL).
// Revoking refresh tokens immediately blocks new access token issuance, which is sufficient
// per industry standard (Auth0, Okta pattern).
//
// #183: the UPDATE is gated on `status='active'` so an admin-set `disabled`
// or a cleanup-set `deleted` cannot be silently overwritten. If the gate
// rejects the row, we re-read the user inside the same TX:
//   - `pending_deletion` → idempotent success (already in target state)
//   - `disabled` / `deleted` → ErrUserAccountClosed (caller emits 403)
//   - any other state → an error
//
// Returns the live status read inside the TX when ErrUserAccountClosed is
// returned, so the caller can record the *actual* state in audit logs
// rather than the stale session-snapshot status. Empty string otherwise.
func (s *Storage) RequestDeletion(ctx context.Context, userID string) (string, error) {
	now := s.clock.Now()
	scheduledAt := now.Add(30 * 24 * time.Hour)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	qtx := storeq.New(tx)

	rows, err := markUserPendingDeletion(ctx, qtx, userID, now, scheduledAt)
	if err != nil {
		return "", err
	}

	if rows == 0 {
		current, err := s.getUserByID(ctx, tx, userID)
		if err != nil {
			return "", err
		}
		switch current.Status {
		case "pending_deletion":
			// Idempotent: already in target state. Re-running the refresh-token
			// revoke is safe (`WHERE revoked_at IS NULL`) and protects against
			// the case where the previous transition crashed between the
			// status flip and the token revoke.
			if err := revokeActiveRefreshTokensForDeletion(ctx, qtx, userID, now); err != nil {
				return "", err
			}
			return "", tx.Commit()
		case "disabled", "deleted":
			return current.Status, ErrUserAccountClosed
		default:
			return current.Status, errors.New("unexpected user status for deletion: " + current.Status)
		}
	}

	if err := revokeActiveRefreshTokensForDeletion(ctx, qtx, userID, now); err != nil {
		return "", err
	}

	return "", tx.Commit()
}

func markUserPendingDeletion(ctx context.Context, qtx *storeq.Queries, userID string, now, scheduledAt time.Time) (int64, error) {
	return qtx.MarkUserPendingDeletionByID(ctx, storeq.MarkUserPendingDeletionByIDParams{
		DeletionRequestedAt: sql.NullTime{Time: now, Valid: true},
		DeletionScheduledAt: sql.NullTime{Time: scheduledAt, Valid: true},
		ID:                  userID,
	})
}

func revokeActiveRefreshTokensForDeletion(ctx context.Context, qtx *storeq.Queries, userID string, now time.Time) error {
	return qtx.RevokeActiveRefreshTokensByUserID(ctx, storeq.RevokeActiveRefreshTokensByUserIDParams{
		RevokedAt: sql.NullTime{Time: now, Valid: true},
		UserID:    userID,
	})
}

// DisableUser sets a user's status to disabled.
func (s *Storage) DisableUser(ctx context.Context, userID string) error {
	return s.setUserStatus(ctx, userID, "disabled")
}

func (s *Storage) setUserStatus(ctx context.Context, userID, status string) error {
	return storeq.New(s.db).SetUserStatusByID(ctx, storeq.SetUserStatusByIDParams{
		Status:    status,
		UpdatedAt: s.clock.Now(),
		ID:        userID,
	})
}
