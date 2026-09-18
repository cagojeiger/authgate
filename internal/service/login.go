package service

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/kangheeyong/authgate/internal/storage"
)

type LoginService struct {
	store        LoginStore
	providerName string
	issuer       string
	sessionTTL   time.Duration
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

// HandleLogin processes GET /login?authRequestID=xxx
func (s *LoginService) HandleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
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
	return &LoginResult{Action: ActionRedirectToIdP, AuthRequestID: authRequestID}
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
		if err := s.store.RecoverUser(ctx, user.ID); err != nil {
			return &LoginResult{Action: ActionError, Error: "failed to recover account", ErrorCode: http.StatusInternalServerError}
		}
		recovered = true
	}

	return completeReusedSessionLogin(ctx, s.store, "browser", client.Name, user, authReq, authTime, sessionID, ipAddress, userAgent, recovered)
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
