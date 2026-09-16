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
	store        LoginStore
	providerName string
	issuer       string
	sessionTTL   time.Duration
}

// NewMCPLoginService builds the mcp login service. issuer is the public URL
// sent as the RFC 9207 iss parameter on the error responses /mcp/login returns
// to the client itself (prompt=none).
func NewMCPLoginService(store LoginStore, providerName, issuer string, sessionTTL time.Duration) *MCPLoginService {
	return &MCPLoginService{
		store:        store,
		providerName: providerName,
		issuer:       issuer,
		sessionTTL:   sessionTTL,
	}
}

func (s *MCPLoginService) HandleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	if authRequestID == "" {
		return &LoginResult{Action: ActionError, Error: "missing authRequestID", ErrorCode: http.StatusBadRequest}
	}

	authReq, result := loadLoginAuthRequest(ctx, s.store, authRequestID)
	if result != nil {
		return result
	}

	mode := loginPromptMode(authReq.Prompt)
	if mode == promptInteractive {
		return redirectToProviderSelectingAccount(authRequestID)
	}

	if sessionID != "" {
		user, err := s.store.GetValidSession(ctx, sessionID)
		if errors.Is(err, storage.ErrUserAccountClosed) || (err == nil && CheckAccess(user.Status, "mcp") != AccessAllow) {
			s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "mcp"})
			if mode == promptSilent {
				return loginRequired(ctx, s.store, "mcp", s.issuer, authReq, ipAddress, userAgent)
			}
			return &LoginResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
		}
		if err == nil {
			authTime, timeErr := s.store.SessionAuthTime(ctx, sessionID)
			if timeErr != nil {
				// The session went away underneath us. prompt=none cannot send
				// anyone upstream (Core 3.1.2.6).
				if mode == promptSilent {
					return loginRequired(ctx, s.store, "mcp", s.issuer, authReq, ipAddress, userAgent)
				}
				return &LoginResult{Action: ActionRedirectToIdP, AuthRequestID: authRequestID}
			}
			if sessionTooOldForMaxAge(authReq, authTime, time.Now()) {
				return maxAgeExceeded(ctx, s.store, "mcp", s.issuer, authReq, mode, ipAddress, userAgent)
			}
			client, errMsg, code := verifyAuthRequestChannel(ctx, s.store, authReq, "mcp", ipAddress, userAgent, &user.ID)
			if errMsg != "" {
				return &LoginResult{Action: ActionError, Error: errMsg, ErrorCode: code}
			}
			if !checkClientAccess(ctx, s.store, client, "mcp", &user.ID, storage.AccessSubject(user), false, ipAddress, userAgent) {
				return accessDeniedRedirect(s.issuer, authReq)
			}
			// mcp never recovers (CheckAccess denies pending_deletion for mcp),
			// so recovered is always false.
			return completeReusedSessionLogin(ctx, s.store, "mcp", client.Name, user, authReq, authTime, sessionID, ipAddress, userAgent, false)
		}
	}

	if mode == promptSilent {
		return loginRequired(ctx, s.store, "mcp", s.issuer, authReq, ipAddress, userAgent)
	}
	return &LoginResult{Action: ActionRedirectToIdP, AuthRequestID: authRequestID}
}

// CompleteMCPLogin finishes the MCP callback after the upstream code exchange
// has already happened inside the high-level CodeExchangeHandler (which
// verified the state cookie / PKCE before exchange). state carries the
// authRequestID; info is the resolved upstream identity.
func (s *MCPLoginService) CompleteMCPLogin(ctx context.Context, state string, info *upstream.UserInfo, ipAddress, userAgent string) *CallbackResult {
	authRequestID := state
	if authRequestID == "" || info == nil {
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

	client, errMsg, statusCode := verifyAuthRequestChannel(ctx, s.store, authReq, "mcp", ipAddress, userAgent, nil)
	if errMsg != "" {
		return &CallbackResult{Action: ActionError, Error: errMsg, ErrorCode: statusCode}
	}
	clientName := client.Name

	userInfo := info

	providerName := s.providerName
	user, err := s.store.GetUserByProviderIdentity(ctx, providerName, userInfo.Sub)
	if errors.Is(err, storage.ErrNotFound) {
		return &CallbackResult{Action: ActionError, Error: "account_not_found", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	if result := recordHostedDomain(ctx, s.store, providerName, userInfo, user); result != nil {
		return result
	}
	if CheckAccess(user.Status, "mcp") != AccessAllow {
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "mcp"})
		return &CallbackResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
	}
	if !checkExistingAccountAccess(ctx, s.store, client, "mcp", user, userInfo, ipAddress, userAgent) {
		return callbackResultFrom(accessDeniedRedirect(s.issuer, authReq))
	}

	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}
	// A fresh upstream login: the zero time makes storage record now.
	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID, time.Time{}); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":     "mcp",
		"session_id":  sessionID,
		"client_id":   authReq.ClientID,
		"client_name": clientName,
	})
	return &CallbackResult{Action: ActionAutoApprove, AuthRequestID: authRequestID, SessionID: sessionID}
}
