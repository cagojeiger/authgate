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
	store           LoginStore
	browserProvider upstream.Provider
	sessionTTL      time.Duration
}

type LoginStore interface {
	GetValidSession(ctx context.Context, sessionID string) (*storage.User, error)
	AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any) error
	RecoverUser(ctx context.Context, userID string) error
	CompleteAuthRequest(ctx context.Context, authRequestID, userID string) error
	GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	CreateUserWithIdentity(ctx context.Context, email string, emailVerified bool, name, avatarURL, provider, providerUserID, providerEmail string) (*storage.User, error)
	GetUserByID(ctx context.Context, userID string) (*storage.User, error)
	CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error)
}

func NewLoginService(store LoginStore, browserProvider upstream.Provider, sessionTTL time.Duration) *LoginService {
	return &LoginService{
		store:           store,
		browserProvider: browserProvider,
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
	return s.handleLogin(ctx, authRequestID, sessionID, ipAddress, userAgent)
}

func (s *LoginService) handleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	if authRequestID == "" {
		return &LoginResult{Action: ActionError, Error: "missing authRequestID", ErrorCode: http.StatusBadRequest}
	}

	// Check session
	if sessionID != "" {
		user, err := s.store.GetValidSession(ctx, sessionID)
		if err == nil {
			// Session exists — check login state
			return s.handleExistingSession(ctx, user, authRequestID, ipAddress, userAgent)
		}
		// Session invalid/expired — fall through to IdP redirect
	}

	// No valid session — redirect to upstream IdP
	authURL := s.browserProvider.AuthURL(authRequestID)
	return &LoginResult{Action: ActionRedirectToIdP, RedirectURL: authURL}
}

func (s *LoginService) handleExistingSession(ctx context.Context, user *storage.User, authRequestID, ipAddress, userAgent string) *LoginResult {
	switch CheckAccess(user.Status, "browser") {
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
	return s.handleCallback(ctx, code, authRequestID, ipAddress, userAgent)
}

func (s *LoginService) handleCallback(ctx context.Context, code, authRequestID, ipAddress, userAgent string) *CallbackResult {
	if code == "" || authRequestID == "" {
		return &CallbackResult{Action: ActionError, Error: "missing code or state", ErrorCode: http.StatusBadRequest}
	}

	// Exchange code for user info
	userInfo, err := s.browserProvider.Exchange(ctx, code)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: fmt.Sprintf("upstream_error: %v", err), ErrorCode: http.StatusInternalServerError}
	}

	// Look up user by provider identity
	providerName := s.browserProvider.Name()
	user, err := s.store.GetUserByProviderIdentity(ctx, providerName, userInfo.Sub)
	if errors.Is(err, storage.ErrNotFound) {
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
		s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{"channel": "browser"})
	}

	// Access check
	switch CheckAccess(user.Status, "browser") {
	case AccessDeny:
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "browser"})
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
