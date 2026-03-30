package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/kangheeyong/authgate/internal/guard"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type LoginService struct {
	store          *storage.Storage
	provider       upstream.Provider
	termsVersion   string
	privacyVersion string
	sessionTTL     time.Duration
}

func NewLoginService(store *storage.Storage, provider upstream.Provider, termsVersion, privacyVersion string, sessionTTL time.Duration) *LoginService {
	return &LoginService{
		store:          store,
		provider:       provider,
		termsVersion:   termsVersion,
		privacyVersion: privacyVersion,
		sessionTTL:     sessionTTL,
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
	ActionRedirectToIdP  LoginAction = iota // Redirect to upstream IdP
	ActionShowTerms                         // Render terms page
	ActionAutoApprove                       // Complete auth request immediately
	ActionError                             // Show error
)

// HandleLogin processes GET /login?authRequestID=xxx
func (s *LoginService) HandleLogin(ctx context.Context, authRequestID, sessionID string) *LoginResult {
	if authRequestID == "" {
		return &LoginResult{Action: ActionError, Error: "missing authRequestID", ErrorCode: http.StatusBadRequest}
	}

	// Check session
	if sessionID != "" {
		user, err := s.store.GetValidSession(ctx, sessionID)
		if err == nil {
			// Session exists — check login state
			return s.handleExistingSession(ctx, user, authRequestID)
		}
		// Session invalid/expired — fall through to IdP redirect
	}

	// No valid session — redirect to upstream IdP
	authURL := s.provider.AuthURL(authRequestID)
	return &LoginResult{Action: ActionRedirectToIdP, RedirectURL: authURL}
}

func (s *LoginService) handleExistingSession(ctx context.Context, user *storage.User, authRequestID string) *LoginResult {
	ui := userToGuardInfo(user, s.termsVersion, s.privacyVersion)
	state := guard.DeriveLoginState(ui, s.termsVersion, s.privacyVersion)

	switch state {
	case guard.OnboardingComplete:
		// Auto-approve: complete auth request
		if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
			return &LoginResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
		}
		return &LoginResult{Action: ActionAutoApprove, AuthRequestID: authRequestID}

	case guard.InitialOnboardingIncomplete, guard.ReconsentRequired:
		return &LoginResult{Action: ActionShowTerms, AuthRequestID: authRequestID}

	case guard.RecoverableBrowserOnly:
		// Recover from pending_deletion
		if err := s.store.RecoverUser(ctx, user.ID); err != nil {
			return &LoginResult{Action: ActionError, Error: "failed to recover account", ErrorCode: http.StatusInternalServerError}
		}
		s.store.AuditLog(ctx, &user.ID, "auth.deletion_cancelled", "", "", nil)
		// Re-fetch user after recovery (avoid stale state)
		recoveredUser, err := s.store.GetValidSession(ctx, "")
		if err != nil {
			// Session lookup may not work here — update in-memory instead
			user.Status = "active"
		} else {
			user = recoveredUser
		}
		// Re-check with fresh state (no recursion)
		freshUI := userToGuardInfo(user, s.termsVersion, s.privacyVersion)
		freshState := guard.DeriveLoginState(freshUI, s.termsVersion, s.privacyVersion)
		if freshState == guard.OnboardingComplete {
			if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
				return &LoginResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
			}
			return &LoginResult{Action: ActionAutoApprove, AuthRequestID: authRequestID}
		}
		return &LoginResult{Action: ActionShowTerms, AuthRequestID: authRequestID}

	default: // Inactive
		return &LoginResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
	}
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
	if code == "" || authRequestID == "" {
		return &CallbackResult{Action: ActionError, Error: "missing code or state", ErrorCode: http.StatusBadRequest}
	}

	// Exchange code for user info
	userInfo, err := s.provider.Exchange(ctx, code)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: fmt.Sprintf("upstream_error: %v", err), ErrorCode: http.StatusInternalServerError}
	}

	// Look up user by provider identity
	user, err := s.store.GetUserByProviderIdentity(ctx, "google", userInfo.Sub)
	if errors.Is(err, storage.ErrNotFound) {
		// New user — signup (Spec 001)
		user, err = s.store.CreateUserWithIdentity(ctx,
			userInfo.Email, userInfo.EmailVerified, userInfo.Name, userInfo.Picture,
			"google", userInfo.Sub, userInfo.Email,
		)
		if err != nil {
			return &CallbackResult{Action: ActionError, Error: fmt.Sprintf("signup failed: %v", err), ErrorCode: http.StatusInternalServerError}
		}
		s.store.AuditLog(ctx, &user.ID, "auth.signup", ipAddress, userAgent, nil)
	} else if err != nil {
		return &CallbackResult{Action: ActionError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	} else {
		s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{"channel": "browser"})
	}

	// Guard check (DeriveLoginState + GuardLoginChannel)
	ui := userToGuardInfo(user, s.termsVersion, s.privacyVersion)
	result := guard.GuardLoginChannel(ui, guard.ChannelBrowser, s.termsVersion, s.privacyVersion)

	switch result {
	case guard.AccountInactive:
		return &CallbackResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}

	case guard.RecoverThenContinue:
		if err := s.store.RecoverUser(ctx, user.ID); err != nil {
			return &CallbackResult{Action: ActionError, Error: "recovery failed", ErrorCode: http.StatusInternalServerError}
		}
		s.store.AuditLog(ctx, &user.ID, "auth.deletion_cancelled", ipAddress, userAgent, nil)
		// Update in-memory state after recovery
		user.Status = "active"
		ui = userToGuardInfo(user, s.termsVersion, s.privacyVersion)
		// Fall through to create session
	}

	// Create session
	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}

	// Check if terms needed (using fresh ui after possible recovery)
	state := guard.DeriveLoginState(ui, s.termsVersion, s.privacyVersion)
	if state == guard.InitialOnboardingIncomplete || state == guard.ReconsentRequired {
		return &CallbackResult{Action: ActionShowTerms, AuthRequestID: authRequestID, SessionID: sessionID}
	}

	// Complete auth request
	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}

	return &CallbackResult{Action: ActionAutoApprove, AuthRequestID: authRequestID, SessionID: sessionID}
}

// HandleTermsSubmit processes POST /login/terms
func (s *LoginService) HandleTermsSubmit(ctx context.Context, authRequestID, sessionID string, termsAgree, ageConfirm bool, ipAddress, userAgent string) *CallbackResult {
	if !termsAgree || !ageConfirm {
		return &CallbackResult{Action: ActionShowTerms, AuthRequestID: authRequestID, SessionID: sessionID, Error: "Please accept all terms and confirm your age."}
	}

	if sessionID == "" {
		return &CallbackResult{Action: ActionError, Error: "no session", ErrorCode: http.StatusUnauthorized}
	}

	user, err := s.store.GetValidSession(ctx, sessionID)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "invalid session", ErrorCode: http.StatusUnauthorized}
	}

	// Accept terms
	if err := s.store.AcceptTerms(ctx, user.ID, s.termsVersion, s.privacyVersion); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to accept terms", ErrorCode: http.StatusInternalServerError}
	}

	s.store.AuditLog(ctx, &user.ID, "auth.terms_accepted", ipAddress, userAgent, map[string]any{
		"terms_version":   s.termsVersion,
		"privacy_version": s.privacyVersion,
	})

	// Complete auth request
	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}

	return &CallbackResult{Action: ActionAutoApprove, AuthRequestID: authRequestID, SessionID: sessionID}
}

func userToGuardInfo(user *storage.User, termsVersion, privacyVersion string) *guard.UserInfo {
	ui := &guard.UserInfo{
		Status:            user.Status,
		TermsAcceptedAt:   user.TermsAcceptedAt,
		PrivacyAcceptedAt: user.PrivacyAcceptedAt,
	}
	if user.TermsVersion != nil {
		ui.TermsVersion = *user.TermsVersion
	}
	if user.PrivacyVersion != nil {
		ui.PrivacyVersion = *user.PrivacyVersion
	}
	return ui
}
