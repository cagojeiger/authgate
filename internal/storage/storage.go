package storage

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrEmailConflict = errors.New("email_conflict")

	// ErrUserAccountClosed is returned when a user lookup succeeds but the
	// account is in a terminal state (`disabled` or `deleted`). The user is
	// returned alongside the error so callers can emit the right audit
	// metadata (channel, IP, UA) before rejecting. `pending_deletion` is
	// passed through without an error because the channel × status policy
	// in service.CheckAccess permits browser-channel recovery.
	//
	// Defense-in-depth for #157: any new caller that does
	// `if err != nil { return err }` after a session/bearer lookup will
	// correctly reject closed accounts without needing to remember the
	// status check itself.
	ErrUserAccountClosed = errors.New("user account is closed")
)

// StateChecker validates that a user is still eligible for token issuance.
// It is applied on both authorization_code and refresh_token grant lookups.
// Injected from main.go — storage never imports service or guard packages.
type StateChecker func(user *User) error

// ClientResolutionPolicy resolves a client profile for client_id.
// It is invoked by storage methods that zitadel calls directly.
type ClientResolutionPolicy interface {
	ResolveClient(ctx context.Context, clientID string) (*ClientModel, error)
}

// ResourceBindingPolicy validates resource binding across authorize/token flows.
// Default policy preserves current behavior for browser/mcp resource checks.
type ResourceBindingPolicy interface {
	ValidateAuthorizeRequest(ctx context.Context, client *ClientModel, requestResource string) error
	ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error
}

// AuditFailureRecorder receives an event whenever an audit-log write fails so
// the silent best-effort policy in AuditLog (#208) is still observable via
// metrics/alerts. main.go wires telemetry.SecurityRecorder; tests can plug a
// fake recorder. Stages: "marshal" or "insert".
type AuditFailureRecorder interface {
	RecordWriteFailure(stage string)
}

// AuditEventRecorder receives an event after an audit-log row is successfully
// persisted. main.go wires telemetry.SecurityRecorder so security-sensitive
// event bursts are visible from /metrics.
type AuditEventRecorder interface {
	RecordEvent(eventType, channel string)
}

type noopAuditFailureRecorder struct{}

func (noopAuditFailureRecorder) RecordWriteFailure(string) {}

type noopAuditEventRecorder struct{}

func (noopAuditEventRecorder) RecordEvent(string, string) {}

type Storage struct {
	db              *sql.DB
	clock           clock.Clock
	idgen           idgen.IDGenerator
	stateChecker    StateChecker
	signingKey      *rsa.PrivateKey
	signingKeyID    string
	previousKey     *rsa.PrivateKey
	previousKeyID   string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	// devicePollInterval is the minimum gap between successive device-flow
	// token polls before the AS responds with `slow_down` (RFC 8628 §3.5).
	// Defaults to 5s in New() to match the value advertised in
	// `op.DeviceAuthorizationConfig.PollInterval`.
	devicePollInterval time.Duration
	clients            sync.Map // map[string]*ClientModel (client_id → client)
	clientPolicy       ClientResolutionPolicy
	resourcePolicy     ResourceBindingPolicy
	// issuer is the expected `iss` claim for bearer-token validation on
	// console APIs. Wired from cfg.PublicURL via SetIssuer at startup; empty
	// string falls back to clock-only validation for backward compatibility
	// with tests that construct Storage without explicit issuer plumbing.
	issuer string
	// auditFailureRec receives a signal whenever AuditLog fails to marshal
	// or insert. Defaults to a no-op in New() so call sites never need a nil
	// guard; main.go installs telemetry.SecurityRecorder at startup.
	auditFailureRec AuditFailureRecorder
	// auditEventRec receives a signal after a successful AuditLog insert.
	// Defaults to a no-op for tests that construct Storage directly.
	auditEventRec AuditEventRecorder
}

func New(db *sql.DB, clk clock.Clock, gen idgen.IDGenerator, checker StateChecker, accessTTL, refreshTTL time.Duration) *Storage {
	s := &Storage{
		db:                 db,
		clock:              clk,
		idgen:              gen,
		stateChecker:       checker,
		accessTokenTTL:     accessTTL,
		refreshTokenTTL:    refreshTTL,
		devicePollInterval: 5 * time.Second,
		auditFailureRec:    noopAuditFailureRecorder{},
		auditEventRec:      noopAuditEventRecorder{},
	}
	s.clientPolicy = NewCoreClientResolutionPolicy(s)
	s.resourcePolicy = NewCoreResourceBindingPolicy()
	return s
}

// SetDevicePollInterval overrides the device-flow poll interval used for
// `slow_down` enforcement. main.go calls this with the same value advertised
// in op.DeviceAuthorizationConfig.PollInterval so a single config flow drives
// both the response shape and the server-side throttle.
func (s *Storage) SetDevicePollInterval(d time.Duration) {
	s.devicePollInterval = d
}

// SetAuditFailureRecorder installs a metric recorder that AuditLog invokes
// when a write fails. main.go wires telemetry.SecurityRecorder. Passing nil
// resets to the no-op recorder so the call site contract holds either way.
func (s *Storage) SetAuditFailureRecorder(r AuditFailureRecorder) {
	if r == nil {
		s.auditFailureRec = noopAuditFailureRecorder{}
		return
	}
	s.auditFailureRec = r
}

// SetAuditEventRecorder installs a metric recorder that AuditLog invokes after
// a successful row insert. Passing nil resets to the no-op recorder.
func (s *Storage) SetAuditEventRecorder(r AuditEventRecorder) {
	if r == nil {
		s.auditEventRec = noopAuditEventRecorder{}
		return
	}
	s.auditEventRec = r
}

// SetSigningKey sets the current RSA signing key used for JWT issuance.
func (s *Storage) SetSigningKey(key *rsa.PrivateKey, keyID string) {
	s.signingKey = key
	s.signingKeyID = keyID
}

// SetPreviousKey sets the previous signing key for 2-slot rotation.
// JWKS will return both keys; JWTs are signed with the current key only.
func (s *Storage) SetPreviousKey(key *rsa.PrivateKey, keyID string) {
	s.previousKey = key
	s.previousKeyID = keyID
}

// SetIssuer pins the expected `iss` claim used during bearer-token
// validation. Should be called once at startup with cfg.PublicURL. Empty
// string disables the check (only useful in tests that construct Storage
// without going through main.go).
func (s *Storage) SetIssuer(issuer string) {
	s.issuer = issuer
}

// DB returns the underlying *sql.DB. For testing only.
func (s *Storage) DB() *sql.DB { return s.db }

// hashToken returns SHA-256 hex hash of a token string.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
