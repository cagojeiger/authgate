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
	browserProvider upstream.Provider
	mcpProvider     upstream.Provider
	termsVersion   string
	privacyVersion string
	sessionTTL     time.Duration
}

func NewLoginService(store *storage.Storage, browserProvider, mcpProvider upstream.Provider, termsVersion, privacyVersion string, sessionTTL time.Duration) *LoginService {
	if mcpProvider == nil {
		mcpProvider = browserProvider
	}
	return &LoginService{
		store:           store,
		browserProvider: browserProvider,
		mcpProvider:     mcpProvider,
		termsVersion:    termsVersion,
		privacyVersion:  privacyVersion,
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
	ActionRedirectToIdP  LoginAction = iota // Redirect to upstream IdP
	ActionShowTerms                         // Render terms page
	ActionAutoApprove                       // Complete auth request immediately
	ActionError                             // Show error
)

// HandleLogin processes GET /login?authRequestID=xxx
func (s *LoginService) HandleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	return s.handleLogin(ctx, authRequestID, sessionID, ipAddress, userAgent, guard.ChannelBrowser)
}

// HandleMCPLogin processes GET /mcp/login?authRequestID=xxx
func (s *LoginService) HandleMCPLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string) *LoginResult {
	return s.handleLogin(ctx, authRequestID, sessionID, ipAddress, userAgent, guard.ChannelMCP)
}

func (s *LoginService) handleLogin(ctx context.Context, authRequestID, sessionID, ipAddress, userAgent string, channel guard.Channel) *LoginResult {
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

func (s *LoginService) handleExistingSession(ctx context.Context, user *storage.User, authRequestID, ipAddress, userAgent string, channel guard.Channel) *LoginResult {
	ui := userToGuardInfo(user, s.termsVersion, s.privacyVersion)
	result := guard.GuardLoginChannel(ui, channel, s.termsVersion, s.privacyVersion)

	switch result {
	case guard.Allow:
		// Auto-approve: complete auth request
		if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
			return &LoginResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
		}
		return &LoginResult{Action: ActionAutoApprove, AuthRequestID: authRequestID}

	case guard.ShowTerms:
		return &LoginResult{Action: ActionShowTerms, AuthRequestID: authRequestID}

	case guard.RecoverThenContinue:
		// Recover from pending_deletion
		if err := s.store.RecoverUser(ctx, user.ID); err != nil {
			return &LoginResult{Action: ActionError, Error: "failed to recover account", ErrorCode: http.StatusInternalServerError}
		}
		s.store.AuditLog(ctx, &user.ID, "auth.deletion_cancelled", ipAddress, userAgent, nil)
		// DB re-read after recovery for fresh state
		freshUser, err := s.store.GetUserByID(ctx, user.ID)
		if err != nil {
			return &LoginResult{Action: ActionError, Error: "failed to read user after recovery", ErrorCode: http.StatusInternalServerError}
		}
		freshUI := userToGuardInfo(freshUser, s.termsVersion, s.privacyVersion)
		freshState := guard.DeriveLoginState(freshUI, s.termsVersion, s.privacyVersion)
		if freshState == guard.OnboardingComplete {
			if err := s.store.CompleteAuthRequest(ctx, authRequestID, freshUser.ID); err != nil {
				return &LoginResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
			}
			return &LoginResult{Action: ActionAutoApprove, AuthRequestID: authRequestID}
		}
		return &LoginResult{Action: ActionShowTerms, AuthRequestID: authRequestID}

	case guard.SignupRequired:
		return &LoginResult{Action: ActionError, Error: "signup_required", ErrorCode: http.StatusForbidden}

	default:
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status})
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
	return s.handleCallback(ctx, code, authRequestID, ipAddress, userAgent, guard.ChannelBrowser)
}

// HandleMCPCallback processes GET /mcp/callback?code=xxx&state=authRequestID
func (s *LoginService) HandleMCPCallback(ctx context.Context, code, authRequestID, ipAddress, userAgent string) *CallbackResult {
	return s.handleCallback(ctx, code, authRequestID, ipAddress, userAgent, guard.ChannelMCP)
}

func (s *LoginService) handleCallback(ctx context.Context, code, authRequestID, ipAddress, userAgent string, channel guard.Channel) *CallbackResult {
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
		if channel != guard.ChannelBrowser {
			return &CallbackResult{Action: ActionError, Error: "signup_required", ErrorCode: http.StatusForbidden}
		}
		// New user — signup (Spec 001)
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
		s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{"channel": channelName(channel)})
	}

	// Guard check (DeriveLoginState + GuardLoginChannel)
	ui := userToGuardInfo(user, s.termsVersion, s.privacyVersion)
	result := guard.GuardLoginChannel(ui, channel, s.termsVersion, s.privacyVersion)

	switch result {
	case guard.AccountInactive:
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status})
		return &CallbackResult{Action: ActionError, Error: "account_inactive", ErrorCode: http.StatusForbidden}

	case guard.RecoverThenContinue:
		if err := s.store.RecoverUser(ctx, user.ID); err != nil {
			return &CallbackResult{Action: ActionError, Error: "recovery failed", ErrorCode: http.StatusInternalServerError}
		}
		s.store.AuditLog(ctx, &user.ID, "auth.deletion_cancelled", ipAddress, userAgent, nil)
		// DB re-read after recovery for fresh state
		user, err = s.store.GetUserByID(ctx, user.ID)
		if err != nil {
			return &CallbackResult{Action: ActionError, Error: "failed to read user after recovery", ErrorCode: http.StatusInternalServerError}
		}
		ui = userToGuardInfo(user, s.termsVersion, s.privacyVersion)
		// Fall through to create session

	case guard.SignupRequired:
		return &CallbackResult{Action: ActionError, Error: "signup_required", ErrorCode: http.StatusForbidden}
	}

	// Create session
	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &CallbackResult{Action: ActionError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}

	// Check if terms needed (using fresh ui after possible recovery)
	state := guard.DeriveLoginState(ui, s.termsVersion, s.privacyVersion)
	if channel == guard.ChannelBrowser && (state == guard.InitialOnboardingIncomplete || state == guard.ReconsentRequired) {
		return &CallbackResult{Action: ActionShowTerms, AuthRequestID: authRequestID, SessionID: sessionID}
	}

	// Complete auth request
	if err := s.store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
		return &CallbackResult{Action: ActionError, Error: "failed to complete auth request", ErrorCode: http.StatusInternalServerError}
	}

	return &CallbackResult{Action: ActionAutoApprove, AuthRequestID: authRequestID, SessionID: sessionID}
}

func (s *LoginService) providerForChannel(channel guard.Channel) upstream.Provider {
	if channel == guard.ChannelMCP {
		return s.mcpProvider
	}
	return s.browserProvider
}

func channelName(channel guard.Channel) string {
	switch channel {
	case guard.ChannelMCP:
		return "mcp"
	case guard.ChannelDevice:
		return "device"
	default:
		return "browser"
	}
}

// HandleTermsSubmit processes POST /login/terms
func (s *LoginService) HandleTermsSubmit(ctx context.Context, authRequestID, sessionID string, termsAgree, privacyAgree, ageConfirm bool, ipAddress, userAgent string) *CallbackResult {
	if !termsAgree || !privacyAgree || !ageConfirm {
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
