package service

import (
	"context"
	"errors"
	"net/http"

	"github.com/kangheeyong/authgate/internal/storage"
)

type AccountService struct {
	store AccountStore
}

type AccountStore interface {
	GetValidSession(ctx context.Context, sessionID string) (*storage.User, error)
	RequestDeletion(ctx context.Context, userID string) error
	AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
}

func NewAccountService(store AccountStore) *AccountService {
	return &AccountService{store: store}
}

type AccountResult struct {
	Success   bool
	Message   string
	ErrorCode int
}

// RequestDeletion handles DELETE /account — validates session + single TX: status + refresh revoke.
func (s *AccountService) RequestDeletion(ctx context.Context, sessionID, ipAddress, userAgent string) *AccountResult {
	if sessionID == "" {
		return &AccountResult{Success: false, Message: "unauthorized", ErrorCode: http.StatusUnauthorized}
	}

	user, err := s.store.GetValidSession(ctx, sessionID)
	if errors.Is(err, storage.ErrUserAccountClosed) {
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "browser"})
		return &AccountResult{Success: false, Message: "account_inactive", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		return &AccountResult{Success: false, Message: "invalid session", ErrorCode: http.StatusUnauthorized}
	}

	// Check access
	if CheckAccess(user.Status, "browser") == AccessDeny {
		return &AccountResult{Success: false, Message: "account_inactive", ErrorCode: http.StatusForbidden}
	}

	// Idempotent: already pending_deletion
	if user.Status == "pending_deletion" {
		return &AccountResult{Success: true, Message: "Already pending deletion. Login within 30 days to cancel."}
	}

	if err := s.store.RequestDeletion(ctx, user.ID); err != nil {
		// #183: storage rejects the conditional UPDATE when the row's status is
		// no longer 'active' (e.g. the operator disabled the user between
		// session validation and the UPDATE). Translate to the same 403
		// account_inactive surface that GetValidSession's check uses.
		if errors.Is(err, storage.ErrUserAccountClosed) {
			s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "browser", "phase": "account_deletion"})
			return &AccountResult{Success: false, Message: "account_inactive", ErrorCode: http.StatusForbidden}
		}
		return &AccountResult{Success: false, Message: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	s.store.AuditLog(ctx, &user.ID, "auth.deletion_requested", ipAddress, userAgent, nil)

	return &AccountResult{Success: true, Message: "Account scheduled for deletion in 30 days. Login to cancel."}
}
