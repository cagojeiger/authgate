package service

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/kangheeyong/authgate/internal/guard"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type DeviceService struct {
	store          *storage.Storage
	provider       upstream.Provider
	termsVersion   string
	privacyVersion string
	sessionTTL     time.Duration
	publicURL      string
}

func NewDeviceService(store *storage.Storage, provider upstream.Provider, termsVersion, privacyVersion, publicURL string, sessionTTL time.Duration) *DeviceService {
	return &DeviceService{
		store:          store,
		provider:       provider,
		termsVersion:   termsVersion,
		privacyVersion: privacyVersion,
		publicURL:      publicURL,
		sessionTTL:     sessionTTL,
	}
}

type DevicePageResult struct {
	Action    DeviceAction
	UserCode  string
	CSRFToken string
	Error     string
	ErrorCode int
}

type DeviceAction int

const (
	DeviceShowEntry   DeviceAction = iota // Show user_code input form
	DeviceShowApprove                     // Show approve/deny buttons
	DeviceShowResult                      // Show success/failure result
	DeviceRedirectIdP                     // Redirect to IdP for login
	DeviceRedirectBack                    // Redirect back to /device?user_code=X after callback
	DeviceError                           // Show error page
)

// HandleDevicePage handles GET /device and GET /device?user_code=XXXX
func (s *DeviceService) HandleDevicePage(ctx context.Context, userCode, sessionID string) *DevicePageResult {
	// No user_code → show entry form
	if userCode == "" {
		return &DevicePageResult{Action: DeviceShowEntry}
	}

	// Validate user_code
	dc, err := s.store.GetDeviceCodeByUserCode(ctx, userCode)
	if errors.Is(err, storage.ErrNotFound) {
		return &DevicePageResult{Action: DeviceShowEntry, Error: "Invalid code. Please check and try again."}
	}
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	now := time.Now()
	if now.After(dc.ExpiresAt) {
		return &DevicePageResult{Action: DeviceShowEntry, Error: "This code has expired. Please request a new one."}
	}

	if dc.State != "pending" {
		return &DevicePageResult{Action: DeviceShowEntry, Error: "This code has already been used."}
	}

	// Check session
	if sessionID == "" {
		// No session → redirect to IdP, state=user_code
		authURL := s.provider.AuthURL(userCode)
		return &DevicePageResult{Action: DeviceRedirectIdP, UserCode: authURL}
	}

	// Session exists → check user state
	user, err := s.store.GetValidSession(ctx, sessionID)
	if errors.Is(err, storage.ErrNotFound) {
		authURL := s.provider.AuthURL(userCode)
		return &DevicePageResult{Action: DeviceRedirectIdP, UserCode: authURL}
	}
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	// DeriveLoginState + GuardLoginChannel (device channel)
	ui := userToGuardInfo(user, s.termsVersion, s.privacyVersion)
	result := guard.GuardLoginChannel(ui, guard.ChannelDevice, s.termsVersion, s.privacyVersion)

	switch result {
	case guard.Allow:
		return &DevicePageResult{Action: DeviceShowApprove, UserCode: userCode}
	case guard.SignupRequired:
		return &DevicePageResult{Action: DeviceError, Error: "signup_required: please complete signup in browser first", ErrorCode: http.StatusForbidden}
	default:
		return &DevicePageResult{Action: DeviceError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
	}
}

// HandleDeviceCallback handles GET /device/auth/callback?code=xxx&state=user_code
func (s *DeviceService) HandleDeviceCallback(ctx context.Context, code, userCode, ipAddress, userAgent string) *DevicePageResult {
	if code == "" || userCode == "" {
		return &DevicePageResult{Action: DeviceError, Error: "invalid_request", ErrorCode: http.StatusBadRequest}
	}

	// Exchange code for user info
	userInfo, err := s.provider.Exchange(ctx, code)
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "upstream_error", ErrorCode: http.StatusInternalServerError}
	}

	// Look up user
	user, err := s.store.GetUserByProviderIdentity(ctx, "google", userInfo.Sub)
	if errors.Is(err, storage.ErrNotFound) {
		return &DevicePageResult{Action: DeviceError, Error: "signup_required: please sign up via browser first", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	// DeriveLoginState check (device channel)
	ui := userToGuardInfo(user, s.termsVersion, s.privacyVersion)
	result := guard.GuardLoginChannel(ui, guard.ChannelDevice, s.termsVersion, s.privacyVersion)
	if result != guard.Allow {
		return &DevicePageResult{Action: DeviceError, Error: "signup_required", ErrorCode: http.StatusForbidden}
	}

	// Create session
	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}

	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{"channel": "device"})

	// Redirect back to /device?user_code=X with session
	_ = sessionID // session cookie set by handler
	return &DevicePageResult{Action: DeviceRedirectBack, UserCode: userCode}
}

type DeviceApproveResult struct {
	Success   bool
	Message   string
	SessionID string
	ErrorCode int
}

// HandleDeviceApprove handles POST /device/approve
func (s *DeviceService) HandleDeviceApprove(ctx context.Context, userCode, action, sessionID, ipAddress, userAgent string) *DeviceApproveResult {
	if sessionID == "" {
		return &DeviceApproveResult{Success: false, Message: "no session", ErrorCode: http.StatusUnauthorized}
	}

	user, err := s.store.GetValidSession(ctx, sessionID)
	if err != nil {
		return &DeviceApproveResult{Success: false, Message: "invalid session", ErrorCode: http.StatusUnauthorized}
	}

	// Guard re-check at approve time
	ui := userToGuardInfo(user, s.termsVersion, s.privacyVersion)
	result := guard.GuardLoginChannel(ui, guard.ChannelDevice, s.termsVersion, s.privacyVersion)
	if result != guard.Allow {
		return &DeviceApproveResult{Success: false, Message: "signup_required", ErrorCode: http.StatusForbidden}
	}

	if action == "deny" {
		s.store.DenyDeviceCode(ctx, userCode)
		s.store.AuditLog(ctx, &user.ID, "auth.device_denied", ipAddress, userAgent, nil)
		return &DeviceApproveResult{Success: false, Message: "You denied the authorization request. You can close this window."}
	}

	// Approve
	if err := s.store.ApproveDeviceCode(ctx, userCode, user.ID); err != nil {
		return &DeviceApproveResult{Success: false, Message: "Device code expired or already processed.", ErrorCode: http.StatusBadRequest}
	}

	s.store.AuditLog(ctx, &user.ID, "auth.device_approved", ipAddress, userAgent, nil)
	return &DeviceApproveResult{Success: true, Message: "You have successfully authorized the CLI application. You can close this window."}
}
