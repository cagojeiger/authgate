package service

import (
	"context"
	"errors"
	"log/slog"
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
		if err != nil {
			// Missing session may continue to MCP provider login; storage failures must not be hidden as unauthenticated flow.
			if !errors.Is(err, storage.ErrNotFound) {
				return &LoginResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
			}
		} else {
			return s.handleExistingMCPSession(ctx, user, authRequestID, ipAddress, userAgent)
		}
	}

	return &LoginResult{Action: ActionRedirectToIdP, RedirectURL: s.mcpProvider.AuthURL(authRequestID)}
}

func (s *MCPLoginService) handleExistingMCPSession(ctx context.Context, user *storage.User, authRequestID, ipAddress, userAgent string) *LoginResult {
	if CheckAccess(user.Status, "mcp") != AccessAllow {
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "mcp"})
		return &LoginResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
	}
	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
		return &LoginResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	return &LoginResult{Action: ActionAutoApprove, AuthRequestID: authRequestID}
}

func (s *MCPLoginService) HandleCallback(ctx context.Context, code, authRequestID, ipAddress, userAgent string) *CallbackResult {
	if code == "" || authRequestID == "" {
		return &CallbackResult{Action: ActionError, Error: "missing code or state", ErrorCode: http.StatusBadRequest}
	}

	// Fetch the stored auth request to validate resource binding before completing it.
	authReq, err := s.store.GetAuthRequestModel(ctx, authRequestID)
	if errors.Is(err, storage.ErrNotFound) {
		return &CallbackResult{Action: ActionError, Error: "auth_request_not_found", ErrorCode: http.StatusBadRequest}
	}
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	// Resource binding validation (Spec 004): MCP auth requests must have a resource set.
	// An auth request with an empty resource on the MCP path indicates a missing or tampered request.
	if authReq.Resource == "" {
		slog.WarnContext(ctx, "mcp callback: auth request has no resource — possible resource binding bypass attempt",
			"authRequestID", authRequestID,
			"ipAddress", ipAddress,
		)
		return &CallbackResult{Action: ActionError, Error: "invalid_target", ErrorCode: http.StatusBadRequest}
	}

	userInfo, err := s.mcpProvider.Exchange(ctx, code)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "upstream_error", ErrorCode: http.StatusInternalServerError}
	}

	providerName := s.mcpProvider.Name()
	user, err := s.store.GetUserByProviderIdentity(ctx, providerName, userInfo.Sub)
	// Only an actual missing identity is account_not_found; DB failures remain 500 instead of being swallowed into policy denial.
	if errors.Is(err, storage.ErrNotFound) {
		return &CallbackResult{Action: ActionError, Error: "account_not_found", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	if CheckAccess(user.Status, "mcp") != AccessAllow {
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "mcp"})
		return &CallbackResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
	}

	sessionID, err := s.store.CompleteLogin(ctx, authRequestID, user.ID, s.sessionTTL)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":    "mcp",
		"session_id": sessionID,
		"client_id":  authReq.ClientID,
	})
	return &CallbackResult{Action: ActionAutoApprove, AuthRequestID: authRequestID, SessionID: sessionID}
}
