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

type LoginService struct {
	store           *storage.Storage
	browserProvider upstream.Provider
	mcpProvider     upstream.Provider
	sessionTTL      time.Duration
}

func NewLoginService(store *storage.Storage, browserProvider, mcpProvider upstream.Provider, sessionTTL time.Duration) *LoginService {
	if mcpProvider == nil {
		mcpProvider = browserProvider
	}
	return &LoginService{
		store:           store,
		browserProvider: browserProvider,
		mcpProvider:     mcpProvider,
		sessionTTL:      sessionTTL,
	}
}

// LoginResult describes what the handler should do after HandleLogin.
type LoginResult struct {
	Action        LoginAction
	RedirectURL   string
	AuthRequestID string
	Error         string
	ErrorCode     int
}

type LoginAction int

const (
	ActionRedirectToIdP LoginAction = iota // Redirect to upstream IdP
	ActionAutoApprove                      // Complete auth request immediately
	ActionError                            // Show error
)

// HandleLogin processes GET /login?authRequestID=xxx
func (s *LoginService) HandleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	return s.handleLogin(ctx, authRequestID, sessionID, ipAddress, userAgent, "browser")
}

// HandleMCPLogin processes GET /mcp/login?authRequestID=xxx
func (s *LoginService) HandleMCPLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	return s.handleLogin(ctx, authRequestID, sessionID, ipAddress, userAgent, "mcp")
}

func (s *LoginService) handleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string, channel string) *LoginResult {
	if authRequestID == "" {
		return &LoginResult{Action: ActionError, Error: "missing authRequestID", ErrorCode: http.StatusBadRequest}
	}

	// Check session
	if sessionID != "" {
		user, err := s.store.GetValidSession(ctx, sessionID)
		if err == nil {
			// Session exists — check login state
			return s.handleExistingSession(ctx, user, authRequestID, ipAddress, userAgent, channel)
		}
		// Session invalid/expired — fall through to IdP redirect
	}

	// No valid session — redirect to upstream IdP
	authURL := s.providerForChannel(channel).AuthURL(authRequestID)
	return &LoginResult{Action: ActionRedirectToIdP, RedirectURL: authURL}
}

func (s *LoginService) handleExistingSession(ctx context.Context, user *storage.User, authRequestID, ipAddress, userAgent string, channel string) *LoginResult {
	switch CheckAccess(user.Status, channel) {
	case AccessDeny:
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status})
		return &LoginResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}

	case AccessRecover:
		if err := s.store.RecoverUser(ctx, user.ID); err != nil {
			return &LoginResult{Action: ActionError, Error: "failed to recover account", ErrorCode: http.StatusInternalServerError}
		}
		s.store.AuditLog(ctx, &user.ID, "auth.deletion_cancelled", ipAddress, userAgent, nil)
	}

	// Active or recovered — complete auth request
	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
		return &LoginResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	return &LoginResult{Action: ActionAutoApprove, AuthRequestID: authRequestID}
}

// CallbackResult describes what the handler should do after HandleCallback.
type CallbackResult struct {
	Action        LoginAction
	RedirectURL   string
	AuthRequestID string
	SessionID     string
	Error         string
	ErrorCode     int
}

// HandleCallback processes GET /login/callback?code=xxx&state=authRequestID
func (s *LoginService) HandleCallback(ctx context.Context, code, authRequestID, ipAddress, userAgent string) *CallbackResult {
	return s.handleCallback(ctx, code, authRequestID, ipAddress, userAgent, "browser")
}

// HandleMCPCallback processes GET /mcp/callback?code=xxx&state=authRequestID
func (s *LoginService) HandleMCPCallback(ctx context.Context, code, authRequestID, ipAddress, userAgent string) *CallbackResult {
	return s.handleCallback(ctx, code, authRequestID, ipAddress, userAgent, "mcp")
}

func (s *LoginService) handleCallback(ctx context.Context, code, authRequestID, ipAddress, userAgent string, channel string) *CallbackResult {
	if code == "" || authRequestID == "" {
		return &CallbackResult{Action: ActionError, Error: "missing code or state", ErrorCode: http.StatusBadRequest}
	}

	// Exchange code for user info
	userInfo, err := s.providerForChannel(channel).Exchange(ctx, code)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: fmt.Sprintf("upstream_error: %v", err), ErrorCode: http.StatusInternalServerError}
	}

	// Look up user by provider identity
	provider := s.providerForChannel(channel)
	providerName := provider.Name()
	user, err := s.store.GetUserByProviderIdentity(ctx, providerName, userInfo.Sub)
	if errors.Is(err, storage.ErrNotFound) {
		if channel != "browser" {
			return &CallbackResult{Action: ActionError, Error: "account_not_found", ErrorCode: http.StatusForbidden}
		}
		// New user — signup
		user, err = s.store.CreateUserWithIdentity(ctx,
			userInfo.Email, userInfo.EmailVerified, userInfo.Name, userInfo.Picture,
			providerName, userInfo.Sub, userInfo.Email,
		)
		if errors.Is(err, storage.ErrEmailConflict) {
			return &CallbackResult{Action: ActionError, Error: "email_conflict", ErrorCode: http.StatusConflict}
		}
		if err != nil {
			return &CallbackResult{Action: ActionError, Error: fmt.Sprintf("signup failed: %v", err), ErrorCode: http.StatusInternalServerError}
		}
		s.store.AuditLog(ctx, &user.ID, "auth.signup", ipAddress, userAgent, nil)
	} else if err != nil {
		return &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	} else {
		s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{"channel": channel})
	}

	// Access check
	switch CheckAccess(user.Status, channel) {
	case AccessDeny:
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status})
		return &CallbackResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}

	case AccessRecover:
		if err := s.store.RecoverUser(ctx, user.ID); err != nil {
			return &CallbackResult{Action: ActionError, Error: "recovery failed", ErrorCode: http.StatusInternalServerError}
		}
		s.store.AuditLog(ctx, &user.ID, "auth.deletion_cancelled", ipAddress, userAgent, nil)
		user, err = s.store.GetUserByID(ctx, user.ID)
		if err != nil {
			return &CallbackResult{Action: ActionError, Error: "failed to read user after recovery", ErrorCode: http.StatusInternalServerError}
		}
	}

	// Create session
	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}

	// Complete auth request
	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}

	return &CallbackResult{Action: ActionAutoApprove, AuthRequestID: authRequestID, SessionID: sessionID}
}

func (s *LoginService) providerForChannel(channel string) upstream.Provider {
	if channel == "mcp" {
		return s.mcpProvider
	}
	return s.browserProvider
}

