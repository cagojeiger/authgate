package service

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type DeviceService struct {
	store      DeviceStore
	provider   upstream.Provider
	sessionTTL time.Duration
	publicURL  string
	clock      clock.Clock
}

type DeviceStore interface {
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*storage.DeviceCodeModel, error)
	GetValidSession(ctx context.Context, sessionID string) (*storage.User, error)
	AuditLog(ctx context.Context, userID *string, eventType, ipAddress, userAgent string, metadata map[string]any)
	GetUserByProviderIdentity(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error)
	DenyDeviceCode(ctx context.Context, userCode string) error
	ApproveDeviceCode(ctx context.Context, userCode, subject string) error
	ResolveClient(ctx context.Context, clientID string) (*storage.ClientModel, error)
}

func NewDeviceService(store DeviceStore, provider upstream.Provider, publicURL string, sessionTTL time.Duration, clk clock.Clock) *DeviceService {
	return &DeviceService{
		store:      store,
		provider:   provider,
		publicURL:  publicURL,
		sessionTTL: sessionTTL,
		clock:      clk,
	}
}

type DevicePageResult struct {
	Action    DeviceAction
	UserCode  string
	SessionID string
	CSRFToken string
	Error     string
	ErrorCode int
}

type DeviceAction int

const (
	DeviceShowEntry    DeviceAction = iota // Show user_code input form
	DeviceShowApprove                      // Show approve/deny buttons
	DeviceShowResult                       // Show success/failure result
	DeviceRedirectIdP                      // Redirect to IdP for login
	DeviceRedirectBack                     // Redirect back to /device?user_code=X after callback
	DeviceError                            // Show error page
)

// HandleDevicePage handles GET /device and GET /device?user_code=XXXX
func (s *DeviceService) HandleDevicePage(ctx context.Context, userCode, sessionID string) *DevicePageResult {
	if userCode == "" {
		return &DevicePageResult{Action: DeviceShowEntry}
	}

	if result := s.validateDevicePage(ctx, userCode); result != nil {
		return result
	}

	if sessionID == "" {
		return s.redirectDeviceToProvider(userCode)
	}

	user, err := s.store.GetValidSession(ctx, sessionID)
	if errors.Is(err, storage.ErrNotFound) {
		return s.redirectDeviceToProvider(userCode)
	}
	if errors.Is(err, storage.ErrUserAccountClosed) {
		// Storage flagged a terminal status; ensureDeviceSessionAccess
		// performs the audit + 403 response.
		return s.ensureDeviceSessionAccess(ctx, user)
	}
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	if result := s.ensureDeviceSessionAccess(ctx, user); result != nil {
		return result
	}

	return &DevicePageResult{Action: DeviceShowApprove, UserCode: userCode}
}

// HandleDeviceCallback handles GET /device/auth/callback?code=xxx&state=user_code
func (s *DeviceService) HandleDeviceCallback(ctx context.Context, code, userCode, ipAddress, userAgent string) *DevicePageResult {
	if code == "" || userCode == "" {
		return &DevicePageResult{Action: DeviceError, Error: "invalid_request", ErrorCode: http.StatusBadRequest}
	}

	// #186: validate the local user_code state BEFORE calling provider.Exchange.
	// Without this gate an attacker can drive arbitrary callbacks at the
	// upstream IdP token endpoint (amplification + quota burn) without ever
	// holding a valid user_code. The browser callback got the same fix in
	// #171; this matches that ordering invariant for RFC 8628 §3.3/§3.5.
	deviceCode, err := s.store.GetDeviceCodeByUserCode(ctx, userCode)
	if errors.Is(err, storage.ErrNotFound) {
		return &DevicePageResult{Action: DeviceError, Error: "invalid_request", ErrorCode: http.StatusBadRequest}
	}
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	if s.clock.Now().After(deviceCode.ExpiresAt) {
		return &DevicePageResult{Action: DeviceError, Error: "invalid_request", ErrorCode: http.StatusBadRequest}
	}
	// Only `pending` user_codes are eligible for callback consumption.
	// `approved`/`consumed`/`denied` already finished their lifecycle and
	// must not silently re-bind a freshly-IdP-authenticated subject; the
	// device-flow client is expected to start a new device-authorization.
	if deviceCode.State != "pending" {
		return &DevicePageResult{Action: DeviceError, Error: "invalid_request", ErrorCode: http.StatusBadRequest}
	}

	// Exchange code for user info
	userInfo, err := s.provider.Exchange(ctx, code)
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "upstream_error", ErrorCode: http.StatusInternalServerError}
	}

	user, result := s.findDeviceCallbackUser(ctx, userInfo.Sub)
	if result != nil {
		return result
	}
	if result := s.ensureDeviceCallbackAccess(ctx, user, ipAddress, userAgent); result != nil {
		return result
	}

	sessionID, err := s.store.CreateSession(ctx, user.ID, s.sessionTTL)
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "session creation failed", ErrorCode: http.StatusInternalServerError}
	}

	s.store.AuditLog(ctx, &user.ID, "auth.login", ipAddress, userAgent, map[string]any{
		"channel":     "device",
		"session_id":  sessionID,
		"client_id":   deviceCode.ClientID,
		"client_name": resolveClientName(ctx, s.store, deviceCode.ClientID),
	})

	return &DevicePageResult{Action: DeviceRedirectBack, UserCode: userCode, SessionID: sessionID}
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
	if errors.Is(err, storage.ErrUserAccountClosed) {
		s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "device"})
		return &DeviceApproveResult{Success: false, Message: "account_inactive", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		return &DeviceApproveResult{Success: false, Message: "invalid session", ErrorCode: http.StatusUnauthorized}
	}

	if CheckAccess(user.Status, "device") != AccessAllow {
		return &DeviceApproveResult{Success: false, Message: "account_inactive", ErrorCode: http.StatusForbidden}
	}

	switch action {
	case "approve":
		return s.approveDeviceCode(ctx, userCode, user.ID, ipAddress, userAgent)
	case "deny":
		s.denyDeviceCode(ctx, userCode, user.ID, ipAddress, userAgent)
		return &DeviceApproveResult{Success: false, Message: "You denied the authorization request. You can close this window."}
	default:
		// Reject any other form value to keep the device-consent surface
		// strict. A blank-or-typo "action" must not silently fall through to
		// approve and generate an auth.device_approved audit row (#205).
		return &DeviceApproveResult{Success: false, Message: "invalid action", ErrorCode: http.StatusBadRequest}
	}
}

func (s *DeviceService) validateDevicePage(ctx context.Context, userCode string) *DevicePageResult {
	dc, err := s.store.GetDeviceCodeByUserCode(ctx, userCode)
	if errors.Is(err, storage.ErrNotFound) {
		return &DevicePageResult{Action: DeviceShowEntry, Error: "Invalid code. Please check and try again."}
	}
	if err != nil {
		return &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}

	now := s.clock.Now()
	if now.After(dc.ExpiresAt) {
		return &DevicePageResult{Action: DeviceShowEntry, Error: "This code has expired. Please request a new one."}
	}
	if dc.State != "pending" {
		return &DevicePageResult{Action: DeviceShowEntry, Error: "This code has already been used."}
	}

	return nil
}

func (s *DeviceService) redirectDeviceToProvider(userCode string) *DevicePageResult {
	return &DevicePageResult{Action: DeviceRedirectIdP, UserCode: s.provider.AuthURL(userCode)}
}

func (s *DeviceService) ensureDeviceSessionAccess(ctx context.Context, user *storage.User) *DevicePageResult {
	if CheckAccess(user.Status, "device") == AccessAllow {
		return nil
	}

	info := clientinfo.FromContext(ctx)
	s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", info.IP, info.UserAgent, map[string]any{"status": user.Status, "channel": "device"})
	return &DevicePageResult{Action: DeviceError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
}

func (s *DeviceService) findDeviceCallbackUser(ctx context.Context, providerUserID string) (*storage.User, *DevicePageResult) {
	user, err := s.store.GetUserByProviderIdentity(ctx, s.provider.Name(), providerUserID)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, &DevicePageResult{Action: DeviceError, Error: "account_not_found: please sign up via browser first", ErrorCode: http.StatusForbidden}
	}
	if err != nil {
		return nil, &DevicePageResult{Action: DeviceError, Error: "internal_error", ErrorCode: http.StatusInternalServerError}
	}
	return user, nil
}

func (s *DeviceService) ensureDeviceCallbackAccess(ctx context.Context, user *storage.User, ipAddress, userAgent string) *DevicePageResult {
	if CheckAccess(user.Status, "device") == AccessAllow {
		return nil
	}

	s.store.AuditLog(ctx, &user.ID, "auth.inactive_user", ipAddress, userAgent, map[string]any{"status": user.Status, "channel": "device"})
	return &DevicePageResult{Action: DeviceError, Error: "account_inactive", ErrorCode: http.StatusForbidden}
}

func (s *DeviceService) denyDeviceCode(ctx context.Context, userCode, userID, ipAddress, userAgent string) {
	dc, metadata, err := s.loadDeviceAuditContext(ctx, userCode)
	if err != nil {
		slog.WarnContext(ctx, "device deny: skipping audit (context lookup failed)",
			"user_id", userID,
			"error", err,
		)
		return
	}
	// DenyDeviceCodeByUserCode is `:exec` (no rows-affected check available),
	// so guard against issuing audit when the row is already terminal — the
	// underlying UPDATE would no-op and we must not record auth.device_denied
	// for a code that was already approved/denied/consumed (#205).
	if dc.State != "pending" {
		slog.WarnContext(ctx, "device deny: skipping audit (state not pending)",
			"user_id", userID,
			"state", dc.State,
		)
		return
	}
	if err := s.store.DenyDeviceCode(ctx, userCode); err != nil {
		slog.WarnContext(ctx, "device deny: skipping audit (mutation failed)",
			"user_id", userID,
			"error", err,
		)
		return
	}
	s.store.AuditLog(ctx, &userID, "auth.device_denied", ipAddress, userAgent, metadata)
}

func (s *DeviceService) approveDeviceCode(ctx context.Context, userCode, userID, ipAddress, userAgent string) *DeviceApproveResult {
	_, metadata, err := s.loadDeviceAuditContext(ctx, userCode)
	if err != nil {
		// audit-011 requires client_id on the auth.device_approved row, so a
		// failed lookup must abort the mutation+audit pair rather than emit a
		// metadataless row (#205). Surface the same user-facing message as a
		// stale code so the consent page does not leak the lookup failure.
		slog.WarnContext(ctx, "device approve: aborting (context lookup failed)",
			"user_id", userID,
			"error", err,
		)
		return &DeviceApproveResult{Success: false, Message: "Device code expired or already processed.", ErrorCode: http.StatusBadRequest}
	}
	if err := s.store.ApproveDeviceCode(ctx, userCode, userID); err != nil {
		return &DeviceApproveResult{Success: false, Message: "Device code expired or already processed.", ErrorCode: http.StatusBadRequest}
	}

	s.store.AuditLog(ctx, &userID, "auth.device_approved", ipAddress, userAgent, metadata)
	return &DeviceApproveResult{Success: true, Message: "You have successfully authorized the CLI application. You can close this window."}
}

// loadDeviceAuditContext loads the device_code and resolves its client so the
// auth.device_approved / auth.device_denied audit rows can identify which
// CLI/client was acted upon (audit-011, #205). It returns the device_code
// (callers may inspect State for additional guards) alongside a metadata map
// suitable for AuditLog. A non-nil error means the row should not be audited
// — audit-011 requires client_id, so we prefer skipping the audit (with a
// warn log) over emitting a row with no client identification.
func (s *DeviceService) loadDeviceAuditContext(ctx context.Context, userCode string) (*storage.DeviceCodeModel, map[string]any, error) {
	dc, err := s.store.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		return nil, nil, err
	}
	if dc == nil {
		return nil, nil, storage.ErrNotFound
	}
	md := map[string]any{"client_id": dc.ClientID}
	if c, err := s.store.ResolveClient(ctx, dc.ClientID); err == nil && c != nil {
		md["client_name"] = c.Name
	}
	return dc, md, nil
}
