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
	store        LoginStore
	providerName string
	sessionTTL   time.Duration
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
	GetClientLoginChannel(ctx context.Context, clientID string) (string, error)
	ResolveClient(ctx context.Context, clientID string) (*storage.ClientModel, error)
}

// verifyAuthRequestChannel ensures the auth_request's client uses the expected
// login_channel. On mismatch it audits an auth.channel_mismatch event and
// returns an error message + HTTP status suitable for a *LoginResult or
// *CallbackResult. Lookup errors return ("internal_error", 500); a clean match
// returns ("", 0).
func verifyAuthRequestChannel(ctx context.Context, store LoginStore, authReq *storage.AuthRequestModel, expected, ipAddress, userAgent string, userID *string) (string, int) {
	channel, err := store.GetClientLoginChannel(ctx, authReq.ClientID)
	if err != nil {
		return "internal_error", http.StatusInternalServerError
	}
	if channel != expected {
		store.AuditLog(ctx, userID, storage.EventAuthChannelMismatch, ipAddress, userAgent, map[string]any{
			"expected_channel": expected,
			"actual_channel":   channel,
			"client_id":        authReq.ClientID,
			"client_name":      resolveClientName(ctx, store, authReq.ClientID),
		})
		return "channel_mismatch", http.StatusBadRequest
	}
	return "", 0
}

func NewLoginService(store LoginStore, providerName string, sessionTTL time.Duration) *LoginService {
	return &LoginService{
		store:        store,
		providerName: providerName,
		sessionTTL:   sessionTTL,
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
	if errors.Is(err, storage.ErrUserAccountClosed) {
		s.auditInactiveUser(ctx, user.ID, user.Status, ipAddress, userAgent)
		return &LoginResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		return nil
	}

	return s.handleExistingSession(ctx, user, authRequestID, sessionID, ipAddress, userAgent)
}

func (s *LoginService) handleExistingSession(ctx context.Context, user *storage.User, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	recovered := false
	switch CheckAccess(user.Status, "browser") {
	case AccessDeny:
		s.auditInactiveUser(ctx, user.ID, user.Status, ipAddress, userAgent)
		return &LoginResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}

	case AccessRecover:
		if err := s.recoverUser(ctx, user.ID); err != nil {
			return &LoginResult{Action: ActionError, Error: "failed to recover account", ErrorCode: http.StatusInternalServerError}
		}
		recovered = true
	}

	authReq, err := s.store.GetAuthRequestModel(ctx, authRequestID)
	if errors.Is(err, storage.ErrNotFound) {
		return &LoginResult{Action: ActionError, Error: "auth_request_not_found", ErrorCode: http.StatusBadRequest}
	}
	if err != nil {
		return &LoginResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	if errMsg, code := verifyAuthRequestChannel(ctx, s.store, authReq, "browser", ipAddress, userAgent, &user.ID); errMsg != "" {
		return &LoginResult{Action: ActionError, Error: errMsg, ErrorCode: code}
	}
	if recovered {
		s.auditDeletionCancelled(ctx, user.ID, sessionID, authReq, ipAddress, userAgent)
	}

	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
		return &LoginResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":        "browser",
		"session_id":     sessionID,
		"client_id":      authReq.ClientID,
		"client_name":    resolveClientName(ctx, s.store, authReq.ClientID),
		"reused_session": true,
	})
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

// CompleteBrowserLogin finishes the browser callback after the upstream code
// exchange has already happened inside the high-level CodeExchangeHandler
// (which verified the state cookie / PKCE before exchange). state carries the
// authRequestID; info is the resolved upstream identity.
func (s *LoginService) CompleteBrowserLogin(ctx context.Context, state string, info *upstream.UserInfo, ipAddress, userAgent string) *CallbackResult {
	return s.completeBrowserLogin(ctx, state, info, ipAddress, userAgent)
}

func (s *LoginService) completeBrowserLogin(ctx context.Context, authRequestID string, userInfo *upstream.UserInfo, ipAddress, userAgent string) *CallbackResult {
	if authRequestID == "" || userInfo == nil {
		return &CallbackResult{Action: ActionError, Error: "missing code or state", ErrorCode: http.StatusBadRequest}
	}

	// The state-cookie check inside CodeExchangeHandler already gated this
	// request before the upstream exchange, so the anti-amplification ordering
	// is satisfied. We still resolve the local auth_request and verify its
	// channel binding before completing it.
	authReq, result := s.getCallbackAuthRequest(ctx, authRequestID)
	if result != nil {
		return result
	}
	if errMsg, statusCode := verifyAuthRequestChannel(ctx, s.store, authReq, "browser", ipAddress, userAgent, nil); errMsg != "" {
		return &CallbackResult{Action: ActionError, Error: errMsg, ErrorCode: statusCode}
	}

	user, signedUp, recovered, result := s.prepareBrowserCallbackUser(ctx, userInfo, authReq, ipAddress, userAgent)
	if result != nil {
		return result
	}

	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}
	if recovered {
		s.auditDeletionCancelled(ctx, user.ID, sessionID, authReq, ipAddress, userAgent)
	}

	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":     "browser",
		"session_id":  sessionID,
		"client_id":   authReq.ClientID,
		"client_name": resolveClientName(ctx, s.store, authReq.ClientID),
		"signup":      signedUp,
	})

	return &CallbackResult{Action: ActionAutoApprove, AuthRequestID: authRequestID, SessionID: sessionID}
}

// prepareBrowserCallbackUser performs the user-lookup or signup half of the
// browser callback flow. The caller passes the already-fetched authReq so that
// the signup audit row and the subsequent auth.login row reference the same
// request context — duplicate getCallbackAuthRequest calls would otherwise
// race against expiration/cleanup between fetch and audit (Codex review NIT
// on PR #218).
func (s *LoginService) prepareBrowserCallbackUser(ctx context.Context, userInfo *upstream.UserInfo, authReq *storage.AuthRequestModel, ipAddress, userAgent string) (*storage.User, bool, bool, *CallbackResult) {
	providerName := s.providerName
	user, err := s.store.GetUserByProviderIdentity(ctx, providerName, userInfo.Sub)
	if errors.Is(err, storage.ErrNotFound) {
		user, result := s.signupBrowserUser(ctx, providerName, userInfo, authReq, ipAddress, userAgent)
		return user, true, false, result
	}
	if err != nil {
		return nil, false, false, &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	user, recovered, result := s.ensureBrowserAccess(ctx, user, ipAddress, userAgent)
	if result != nil {
		return nil, false, false, result
	}
	return user, false, recovered, nil
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
	return &LoginResult{Action: ActionRedirectToIdP, AuthRequestID: authRequestID}
}

func (s *LoginService) recoverUser(ctx context.Context, userID string) error {
	return s.store.RecoverUser(ctx, userID)
}

func (s *LoginService) signupBrowserUser(ctx context.Context, providerName string, userInfo *upstream.UserInfo, authReq *storage.AuthRequestModel, ipAddress, userAgent string) (*storage.User, *CallbackResult) {
	user, err := s.store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email:          userInfo.Email,
		EmailVerified:  userInfo.EmailVerified,
		Name:           userInfo.Name,
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

	// audit-011 (#204): signup always happens inside an auth_request, so the
	// originating client_id / client_name must be carried on the audit row.
	s.store.AuditLog(ctx, &user.ID, "auth.signup", ipAddress, userAgent, map[string]any{
		"channel":     "browser",
		"client_id":   authReq.ClientID,
		"client_name": resolveClientName(ctx, s.store, authReq.ClientID),
	})
	return user, nil
}

func (s *LoginService) ensureBrowserAccess(ctx context.Context, user *storage.User, ipAddress, userAgent string) (*storage.User, bool, *CallbackResult) {
	switch CheckAccess(user.Status, "browser") {
	case AccessDeny:
		s.auditInactiveUser(ctx, user.ID, user.Status, ipAddress, userAgent)
		return nil, false, &CallbackResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
	case AccessRecover:
		if err := s.recoverUser(ctx, user.ID); err != nil {
			return nil, false, &CallbackResult{Action: ActionError, Error: "recovery failed", ErrorCode: http.StatusInternalServerError}
		}

		recoveredUser, err := s.store.GetUserByID(ctx, user.ID)
		if err != nil {
			return nil, false, &CallbackResult{Action: ActionError, Error: "failed to read user after recovery", ErrorCode: http.StatusInternalServerError}
		}
		return recoveredUser, true, nil
	default:
		return user, false, nil
	}
}

func (s *LoginService) auditDeletionCancelled(ctx context.Context, userID, sessionID string, authReq *storage.AuthRequestModel, ipAddress, userAgent string) {
	s.store.AuditLog(ctx, &userID, storage.EventAuthDeletionCancelled, ipAddress, userAgent, lifecycleAuditMetadata(
		"browser",
		sessionID,
		authReq.ClientID,
		resolveClientName(ctx, s.store, authReq.ClientID),
	))
}

func (s *LoginService) auditInactiveUser(ctx context.Context, userID, status, ipAddress, userAgent string) {
	s.store.AuditLog(ctx, &userID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": status, "channel": "browser"})
}
