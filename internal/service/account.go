package service

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

type AccountService struct {
	db    *sql.DB
	clock clock.Clock
}

func NewAccountService(db *sql.DB, clk clock.Clock) *AccountService {
	return &AccountService{db: db, clock: clk}
}

type AccountResult struct {
	Success   bool
	Message   string
	ErrorCode int
}

// RequestDeletion handles DELETE /account — single TX: status + refresh revoke.
func (s *AccountService) RequestDeletion(ctx context.Context, userID, ipAddress, userAgent string) *AccountResult {
	now := s.clock.Now()
	scheduledAt := now.Add(30 * 24 * time.Hour)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return &AccountResult{Success: false, Message: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	defer tx.Rollback()

	// Check current status
	var status string
	err = tx.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&status)
	if err != nil {
		return &AccountResult{Success: false, Message: "user not found", ErrorCode: http.StatusNotFound}
	}

	// Idempotent: already pending_deletion
	if status == "pending_deletion" {
		tx.Commit()
		return &AccountResult{Success: true, Message: "Already pending deletion. Login within 30 days to cancel."}
	}

	if status != "active" {
		tx.Commit()
		return &AccountResult{Success: false, Message: "account_inactive", ErrorCode: http.StatusForbidden}
	}

	// Set pending_deletion + schedule
	_, err = tx.ExecContext(ctx,
		`UPDATE users SET status = 'pending_deletion', deletion_requested_at = $1, deletion_scheduled_at = $2, updated_at = $1
		 WHERE id = $3`, now, scheduledAt, userID)
	if err != nil {
		return &AccountResult{Success: false, Message: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	// Revoke all refresh tokens
	_, err = tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL`,
		now, userID)
	if err != nil {
		return &AccountResult{Success: false, Message: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	if err := tx.Commit(); err != nil {
		return &AccountResult{Success: false, Message: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	// Audit after commit
	s.db.ExecContext(ctx,
		`INSERT INTO audit_log (user_id, event_type, ip_address, user_agent, created_at) VALUES ($1, 'auth.deletion_requested', $2::inet, $3, $4)`,
		userID, nilStr(ipAddress), userAgent, now)

	return &AccountResult{Success: true, Message: "Account scheduled for deletion in 30 days. Login to cancel."}
}

func nilStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
