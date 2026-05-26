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
	// RequestDeletion returns the live user status (read inside the same TX as
	// the conditional UPDATE) when err is ErrUserAccountClosed, so the caller
	// can record the actual closed-account state in audit logs rather than the
	// stale session-snapshot status. Empty string otherwise.
	RequestDeletion(ctx context.Context, userID string) (string, error)
	AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
}

type auditSessionClientContextStore interface {
	GetAuditClientContextBySessionID(ctx context.Context, userID, sessionID string) (storage.AuditClientContext, error)
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
		s.auditAccessDenied(ctx, ipAddress, userAgent, "missing_session")
		return &AccountResult{Success: false, Message: "unauthorized", ErrorCode: http.StatusUnauthorized}
	}

	user, err := s.store.GetValidSession(ctx, sessionID)
	if errors.Is(err, storage.ErrUserAccountClosed) {
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "browser"})
		return &AccountResult{Success: false, Message: "account_inactive", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		s.auditAccessDenied(ctx, ipAddress, userAgent, "invalid_session")
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

	liveStatus, err := s.store.RequestDeletion(ctx, user.ID)
	if err != nil {
		// #183: storage rejects the conditional UPDATE when the row's status is
		// no longer 'active' (e.g. the operator disabled the user between
		// session validation and the UPDATE). Translate to the same 403
		// account_inactive surface that GetValidSession's check uses, and
		// audit the *live* status returned by storage rather than the
		// session-snapshot user.Status, which may already be stale.
		if errors.Is(err, storage.ErrUserAccountClosed) {
			s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": liveStatus, "channel": "browser", "phase": "account_deletion"})
			return &AccountResult{Success: false, Message: "account_inactive", ErrorCode: http.StatusForbidden}
		}
		return &AccountResult{Success: false, Message: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	s.store.AuditLog(ctx, &user.ID, storage.EventAuthDeletionRequested, ipAddress, userAgent, s.deletionRequestedMetadata(ctx, user.ID, sessionID))

	return &AccountResult{Success: true, Message: "Account scheduled for deletion in 30 days. Login to cancel."}
}

func (s *AccountService) auditAccessDenied(ctx context.Context, ipAddress, userAgent, reason string) {
	s.store.AuditLog(ctx, nil, storage.EventAuthAccessDenied, ipAddress, userAgent, map[string]any{
		"operation":   "account.delete",
		"status_code": http.StatusUnauthorized,
		"reason":      reason,
	})
}

func (s *AccountService) deletionRequestedMetadata(ctx context.Context, userID, sessionID string) map[string]any {
	clientID := ""
	clientName := ""
	if resolver, ok := s.store.(auditSessionClientContextStore); ok {
		if clientCtx, err := resolver.GetAuditClientContextBySessionID(ctx, userID, sessionID); err == nil {
			clientID = clientCtx.ClientID
			clientName = clientCtx.ClientName
		}
	}
	return lifecycleAuditMetadata("browser", sessionID, clientID, clientName)
}
