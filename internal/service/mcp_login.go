package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

// MCPLoginService owns MCP channel login/callback orchestration.
type MCPLoginService struct {
	store       LoginStore
	mcpProvider upstream.Provider
	sessionTTL  time.Duration
}

func NewMCPLoginService(store LoginStore, mcpProvider upstream.Provider, sessionTTL time.Duration) *MCPLoginService {
	return &MCPLoginService{
		store:       store,
		mcpProvider: mcpProvider,
		sessionTTL:  sessionTTL,
	}
}

func (s *MCPLoginService) HandleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	if authRequestID == "" {
		return &LoginResult{Action: ActionError, Error: "missing authRequestID", ErrorCode: http.StatusBadRequest}
	}

	if sessionID != "" {
		user, err := s.store.GetValidSession(ctx, sessionID)
		if err == nil {
			if CheckAccess(user.Status, "mcp") != AccessAllow {
				s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status})
				return &LoginResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
			}
			if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
				return &LoginResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
			}
			return &LoginResult{Action: ActionAutoApprove, AuthRequestID: authRequestID}
		}
	}

	return &LoginResult{Action: ActionRedirectToIdP, RedirectURL: s.mcpProvider.AuthURL(authRequestID)}
}

func (s *MCPLoginService) HandleCallback(ctx context.Context, code, authRequestID, ipAddress, userAgent string) *CallbackResult {
	if code == "" || authRequestID == "" {
		return &CallbackResult{Action: ActionError, Error: "missing code or state", ErrorCode: http.StatusBadRequest}
	}

	userInfo, err := s.mcpProvider.Exchange(ctx, code)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: fmt.Sprintf("upstream_error: %v", err), ErrorCode: http.StatusInternalServerError}
	}

	providerName := s.mcpProvider.Name()
	user, err := s.store.GetUserByProviderIdentity(ctx, providerName, userInfo.Sub)
	if errors.Is(err, storage.ErrNotFound) {
		return &CallbackResult{Action: ActionError, Error: "account_not_found", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{"channel": "mcp"})

	if CheckAccess(user.Status, "mcp") != AccessAllow {
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "mcp"})
		return &CallbackResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
	}

	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}
	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	return &CallbackResult{Action: ActionAutoApprove, AuthRequestID: authRequestID, SessionID: sessionID}
}
