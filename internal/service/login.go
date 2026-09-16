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
	issuer       string
	sessionTTL   time.Duration
}

type LoginStore interface {
	GetValidSession(ctx context.Context, sessionID string) (*storage.User, error)
	AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
	RecoverUser(ctx context.Context, userID string) error
	CompleteAuthRequest(ctx context.Context, authRequestID, userID string, authTime time.Time) error
	// SessionAuthTime is when the session's owner last authenticated upstream.
	SessionAuthTime(ctx context.Context, sessionID string) (time.Time, error)
	GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	CreateUserWithIdentity(ctx context.Context, input storage.CreateUserWithIdentityInput) (*storage.User, error)
	GetUserByID(ctx context.Context, userID string) (*storage.User, error)
	CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error)
	GetAuthRequestModel(ctx context.Context, id string) (*storage.AuthRequestModel, error)
	ResolveClient(ctx context.Context, clientID string) (*storage.ClientModel, error)
	SetIdentityHostedDomain(ctx context.Context, provider, providerUserID, hostedDomain string) error
}

// verifyAuthRequestChannel ensures the auth_request's client uses the expected
// login_channel. On mismatch it audits an auth.channel_mismatch event and
// returns an error message + HTTP status suitable for a *LoginResult or
// *CallbackResult. Lookup errors return ("internal_error", 500); a clean match
// returns ("", 0).
// It resolves the client once and returns it so the caller's access-policy
// check and success audit can reuse it instead of resolving a second time — for
// MCP clients a resolve may trigger an outbound CIMD fetch, so collapsing the
// lookups avoids a duplicate fetch per login (#302 M2). The client is non-nil
// whenever errMsg is empty.
func verifyAuthRequestChannel(ctx context.Context, store LoginStore, authReq *storage.AuthRequestModel, expected, ipAddress, userAgent string, userID *string) (client *storage.ClientModel, errMsg string, statusCode int) {
	client, err := store.ResolveClient(ctx, authReq.ClientID)
	if err != nil || client == nil {
		return nil, "internal_error", http.StatusInternalServerError
	}
	if client.LoginChannel != expected {
		store.AuditLog(ctx, userID, storage.EventAuthChannelMismatch, ipAddress, userAgent, map[string]any{
			"expected_channel": expected,
			"actual_channel":   client.LoginChannel,
			"client_id":        authReq.ClientID,
			"client_name":      client.Name,
		})
		return client, "channel_mismatch", http.StatusBadRequest
	}
	return client, "", 0
}

// NewLoginService builds the browser login service. issuer is the public URL
// sent as the RFC 9207 iss parameter on the error responses /login returns to
// the client itself (prompt=none).
func NewLoginService(store LoginStore, providerName, issuer string, sessionTTL time.Duration) *LoginService {
	return &LoginService{
		store:        store,
		providerName: providerName,
		issuer:       issuer,
		sessionTTL:   sessionTTL,
	}
}

// LoginResult describes what the handler should do after HandleLogin.
type LoginResult struct {
	Action        LoginAction
	RedirectURL   string
	AuthRequestID string
	// UpstreamPrompt is the prompt to send to the upstream IdP with
	// ActionRedirectToIdP; empty sends none.
	UpstreamPrompt string
	Error          string
	ErrorCode      int
}

type LoginAction int

const (
	ActionRedirectToIdP    LoginAction = iota // Redirect to upstream IdP
	ActionAutoApprove                         // Complete auth request immediately
	ActionError                               // Show error
	ActionRedirectToClient                    // Redirect to RedirectURL, an authorization error response for the client
)

// HandleLogin processes GET /login?authRequestID=xxx
func (s *LoginService) HandleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	return s.handleLogin(ctx, authRequestID, sessionID, ipAddress, userAgent)
}

func (s *LoginService) handleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
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

	if result := s.handleSessionLogin(ctx, authReq, mode, sessionID, ipAddress, userAgent); result != nil {
		return result
	}

	if mode == promptSilent {
		return loginRequired(ctx, s.store, "browser", s.issuer, authReq, ipAddress, userAgent)
	}
	return s.redirectToProvider(authRequestID)
}

func (s *LoginService) handleSessionLogin(ctx context.Context, authReq *storage.AuthRequestModel, mode promptMode, sessionID, ipAddress, userAgent string) *LoginResult {
	if sessionID == "" {
		return nil
	}

	user, err := s.store.GetValidSession(ctx, sessionID)
	if errors.Is(err, storage.ErrUserAccountClosed) {
		s.auditInactiveUser(ctx, user.ID, user.Status, ipAddress, userAgent)
		return s.accountInactive(ctx, authReq, mode, ipAddress, userAgent)
	}
	if err != nil {
		return nil
	}

	authTime, err := s.store.SessionAuthTime(ctx, sessionID)
	if err != nil {
		return nil // the session went away underneath us: sign in again
	}
	if sessionTooOldForMaxAge(authReq, authTime, time.Now()) {
		return maxAgeExceeded(ctx, s.store, "browser", s.issuer, authReq, mode, ipAddress, userAgent)
	}

	return s.handleExistingSession(ctx, user, authReq, authTime, mode, sessionID, ipAddress, userAgent)
}

// accountInactive answers a login whose session belongs to an account that
// may not sign in: an error page, or login_required to the client when the
// request forbids interaction.
func (s *LoginService) accountInactive(ctx context.Context, authReq *storage.AuthRequestModel, mode promptMode, ipAddress, userAgent string) *LoginResult {
	if mode == promptSilent {
		return loginRequired(ctx, s.store, "browser", s.issuer, authReq, ipAddress, userAgent)
	}
	return &LoginResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
}

// completeReusedSessionLogin runs the shared tail of a session-reuse login for
// the browser and mcp channels (device flow has a different shape — it shows an
// approval page instead of auto-completing). The caller has already resolved
// the session, run CheckAccess, verified the channel binding, checked the
// client's access policy, and performed any channel-specific recovery;
// `recovered` is only ever true for the browser channel, which is the only one
// whose CheckAccess returns AccessRecover. This audits a deletion-cancelled
// recovery when applicable, completes the request, and writes the auth.login
// audit — identically across channels except for the channel label.
func completeReusedSessionLogin(ctx context.Context, store LoginStore, channel, clientName string, user *storage.User, authReq *storage.AuthRequestModel, authTime time.Time, sessionID, ipAddress, userAgent string, recovered bool) *LoginResult {
	authRequestID := authReq.ID
	if recovered {
		store.AuditLog(ctx, &user.ID, storage.EventAuthDeletionCancelled, ipAddress, userAgent, lifecycleAuditMetadata(
			channel, sessionID, authReq.ClientID, clientName,
		))
	}

	// auth_time is when this session's owner authenticated upstream, not now:
	// reusing a session does not re-authenticate anyone (OIDC Core 2).
	if err := store.CompleteAuthRequest(ctx, authRequestID, user.ID, authTime); err != nil {
		return &LoginResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":        channel,
		"session_id":     sessionID,
		"client_id":      authReq.ClientID,
		"client_name":    clientName,
		"reused_session": true,
	})
	return &LoginResult{Action: ActionAutoApprove, AuthRequestID: authRequestID}
}

// handleExistingSession decides a login that has a usable session. The order
// keeps each refusal to one meaningful audit row: an account that may not sign
// in at all is reported as inactive before the client is even considered; a
// request on the wrong channel gets channel_mismatch; only then does the
// client's access policy run, and it runs before recovery so a refused login
// never cancels the account's pending deletion as a side effect.
func (s *LoginService) handleExistingSession(ctx context.Context, user *storage.User, authReq *storage.AuthRequestModel, authTime time.Time, mode promptMode, sessionID, ipAddress, userAgent string) *LoginResult {
	access := CheckAccess(user.Status, "browser")
	if access == AccessDeny {
		s.auditInactiveUser(ctx, user.ID, user.Status, ipAddress, userAgent)
		return s.accountInactive(ctx, authReq, mode, ipAddress, userAgent)
	}

	client, errMsg, code := verifyAuthRequestChannel(ctx, s.store, authReq, "browser", ipAddress, userAgent, &user.ID)
	if errMsg != "" {
		return &LoginResult{Action: ActionError, Error: errMsg, ErrorCode: code}
	}
	if !checkClientAccess(ctx, s.store, client, "browser", &user.ID, storage.AccessSubject(user), false, ipAddress, userAgent) {
		return accessDeniedRedirect(s.issuer, authReq)
	}

	recovered := false
	if access == AccessRecover {
		// Recovering cancels the user's pending deletion. That must follow an
		// interaction the user started, not a background prompt=none check a
		// relying party may run on every page load.
		if mode == promptSilent {
			s.auditInactiveUser(ctx, user.ID, user.Status, ipAddress, userAgent)
			return authorizationErrorRedirect(s.issuer, authReq, "login_required")
		}
		if err := s.recoverUser(ctx, user.ID); err != nil {
			return &LoginResult{Action: ActionError, Error: "failed to recover account", ErrorCode: http.StatusInternalServerError}
		}
		recovered = true
	}

	return completeReusedSessionLogin(ctx, s.store, "browser", client.Name, user, authReq, authTime, sessionID, ipAddress, userAgent, recovered)
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
	client, errMsg, statusCode := verifyAuthRequestChannel(ctx, s.store, authReq, "browser", ipAddress, userAgent, nil)
	if errMsg != "" {
		return &CallbackResult{Action: ActionError, Error: errMsg, ErrorCode: statusCode}
	}
	clientName := client.Name

	user, signedUp, recovered, result := s.prepareBrowserCallbackUser(ctx, userInfo, authReq, client, ipAddress, userAgent)
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

	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID, time.Time{}); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}
	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":     "browser",
		"session_id":  sessionID,
		"client_id":   authReq.ClientID,
		"client_name": clientName,
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
//
// The client's access policy runs before signup, so a refused person never gets
// an account, and for an existing account after the inactive check and before
// recovery, so a refused login neither masks a disabled account nor cancels a
// pending deletion. Both evaluate what the IdP just asserted, not the email
// stored at signup, which nothing updates.
func (s *LoginService) prepareBrowserCallbackUser(ctx context.Context, userInfo *upstream.UserInfo, authReq *storage.AuthRequestModel, client *storage.ClientModel, ipAddress, userAgent string) (*storage.User, bool, bool, *CallbackResult) {
	providerName := s.providerName
	user, err := s.store.GetUserByProviderIdentity(ctx, providerName, userInfo.Sub)
	if errors.Is(err, storage.ErrNotFound) {
		if !checkClientAccess(ctx, s.store, client, "browser", nil, accessSubjectFromUpstream(userInfo), true, ipAddress, userAgent) {
			return nil, false, false, callbackResultFrom(accessDeniedRedirect(s.issuer, authReq))
		}
		user, result := s.signupBrowserUser(ctx, providerName, userInfo, authReq, ipAddress, userAgent)
		return user, true, false, result
	}
	if err != nil {
		return nil, false, false, &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	if result := recordHostedDomain(ctx, s.store, providerName, userInfo, user); result != nil {
		return nil, false, false, result
	}

	if CheckAccess(user.Status, "browser") != AccessDeny &&
		!checkExistingAccountAccess(ctx, s.store, client, "browser", user, userInfo, ipAddress, userAgent) {
		return nil, false, false, callbackResultFrom(accessDeniedRedirect(s.issuer, authReq))
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
		HostedDomain:   userInfo.HostedDomain,
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
