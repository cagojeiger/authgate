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
	"github.com/kangheeyong/authgate/internal/crypto"
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
	// keys holds the PII at-rest crypto subkeys (ADR-002). nil until SetKeys is
	// called at startup; while nil, encryption is inert and authgate runs
	// unchanged. The first encrypting consumer (PR2) requires it in production.
	keys *crypto.Keys
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

// DB returns the underlying *sql.DB. For testing only.
func (s *Storage) DB() *sql.DB { return s.db }

// hashToken returns SHA-256 hex hash of a token string.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
