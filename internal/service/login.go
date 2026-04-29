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
	AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
	RecoverUser(ctx context.Context, userID string) error
	CompleteAuthRequest(ctx context.Context, authRequestID, userID string) error
	GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	CreateUserWithIdentity(ctx context.Context, input storage.CreateUserWithIdentityInput) (*storage.User, error)
	GetUserByID(ctx context.Context, userID string) (*storage.User, error)
	CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error)
	GetAuthRequestModel(ctx context.Context, id string) (*storage.AuthRequestModel, error)
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

	if result := s.handleSessionLogin(ctx, authRequestID, sessionID, ipAddress, userAgent); result != nil {
		return result
	}

	return s.redirectToProvider(authRequestID)
}

func (s *LoginService) handleSessionLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	if sessionID == "" {
		return nil
	}

	user, err := s.store.GetValidSession(ctx, sessionID)
	if err != nil {
		return nil
	}

	return s.handleExistingSession(ctx, user, authRequestID, ipAddress, userAgent)
}

func (s *LoginService) handleExistingSession(ctx context.Context, user *storage.User, authRequestID, ipAddress, userAgent string) *LoginResult {
	switch CheckAccess(user.Status, "browser") {
	case AccessDeny:
		s.auditInactiveUser(ctx, user.ID, user.Status, ipAddress, userAgent)
		return &LoginResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}

	case AccessRecover:
		if err := s.recoverUser(ctx, user.ID, ipAddress, userAgent); err != nil {
			return &LoginResult{Action: ActionError, Error: "failed to recover account", ErrorCode: http.StatusInternalServerError}
		}
	}

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
		return &CallbackResult{Action: ActionError, Error: "upstream_error", ErrorCode: http.StatusInternalServerError}
	}

	user, signedUp, authReq, result := s.prepareBrowserCallbackUser(ctx, userInfo, authRequestID, ipAddress, userAgent)
	if result != nil {
		return result
	}

	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}

	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":    "browser",
		"session_id": sessionID,
		"client_id":  authReq.ClientID,
		"signup":     signedUp,
	})

	return &CallbackResult{Action: ActionAutoApprove, AuthRequestID: authRequestID, SessionID: sessionID}
}

func (s *LoginService) prepareBrowserCallbackUser(ctx context.Context, userInfo *upstream.UserInfo, authRequestID, ipAddress, userAgent string) (*storage.User, bool, *storage.AuthRequestModel, *CallbackResult) {
	providerName := s.browserProvider.Name()
	user, err := s.store.GetUserByProviderIdentity(ctx, providerName, userInfo.Sub)
	if errors.Is(err, storage.ErrNotFound) {
		authReq, result := s.getCallbackAuthRequest(ctx, authRequestID)
		if result != nil {
			return nil, false, nil, result
		}
		user, result := s.signupBrowserUser(ctx, providerName, userInfo, ipAddress, userAgent)
		return user, true, authReq, result
	}
	if err != nil {
		return nil, false, nil, &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	user, result := s.ensureBrowserAccess(ctx, user, ipAddress, userAgent)
	if result != nil {
		return nil, false, nil, result
	}
	authReq, result := s.getCallbackAuthRequest(ctx, authRequestID)
	if result != nil {
		return nil, false, nil, result
	}
	return user, false, authReq, nil
}

func (s *LoginService) getCallbackAuthRequest(ctx context.Context, authRequestID string) (*storage.AuthRequestModel, *CallbackResult) {
	authReq, err := s.store.GetAuthRequestModel(ctx, authRequestID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, &CallbackResult{Action: ActionError, Error: "auth_request_not_found", ErrorCode: http.StatusBadRequest}
	}
	if err != nil {
		return nil, &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	return authReq, nil
}

func (s *LoginService) redirectToProvider(authRequestID string) *LoginResult {
	return &LoginResult{Action: ActionRedirectToIdP, RedirectURL: s.browserProvider.AuthURL(authRequestID)}
}

func (s *LoginService) recoverUser(ctx context.Context, userID, ipAddress, userAgent string) error {
	if err := s.store.RecoverUser(ctx, userID); err != nil {
		return err
	}
	s.store.AuditLog(ctx, &userID, "auth.deletion_cancelled", ipAddress, userAgent, nil)
	return nil
}

func (s *LoginService) signupBrowserUser(ctx context.Context, providerName string, userInfo *upstream.UserInfo, ipAddress, userAgent string) (*storage.User, *CallbackResult) {
	user, err := s.store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email:          userInfo.Email,
		EmailVerified:  userInfo.EmailVerified,
		Name:           userInfo.Name,
		AvatarURL:      userInfo.Picture,
		Provider:       providerName,
		ProviderUserID: userInfo.Sub,
		ProviderEmail:  userInfo.Email,
	})
	if errors.Is(err, storage.ErrEmailConflict) {
		return nil, &CallbackResult{Action: ActionError, Error: "email_conflict", ErrorCode: http.StatusConflict}
	}
	if err != nil {
		return nil, &CallbackResult{Action: ActionError, Error: fmt.Sprintf("signup failed: %v", err), ErrorCode: http.StatusInternalServerError}
	}

	s.store.AuditLog(ctx, &user.ID, "auth.signup", ipAddress, userAgent, map[string]any{"channel": "browser"})
	return user, nil
}

func (s *LoginService) ensureBrowserAccess(ctx context.Context, user *storage.User, ipAddress, userAgent string) (*storage.User, *CallbackResult) {
	switch CheckAccess(user.Status, "browser") {
	case AccessDeny:
		s.auditInactiveUser(ctx, user.ID, user.Status, ipAddress, userAgent)
		return nil, &CallbackResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
	case AccessRecover:
		if err := s.recoverUser(ctx, user.ID, ipAddress, userAgent); err != nil {
			return nil, &CallbackResult{Action: ActionError, Error: "recovery failed", ErrorCode: http.StatusInternalServerError}
		}

		recoveredUser, err := s.store.GetUserByID(ctx, user.ID)
		if err != nil {
			return nil, &CallbackResult{Action: ActionError, Error: "failed to read user after recovery", ErrorCode: http.StatusInternalServerError}
		}
		return recoveredUser, nil
	default:
		return user, nil
	}
}

func (s *LoginService) auditInactiveUser(ctx context.Context, userID, status, ipAddress, userAgent string) {
	s.store.AuditLog(ctx, &userID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": status, "channel": "browser"})
}
