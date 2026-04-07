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
	clients         sync.Map // map[string]*ClientModel (client_id → client)
	clientPolicy    ClientResolutionPolicy
	resourcePolicy  ResourceBindingPolicy
}

func New(db *sql.DB, clk clock.Clock, gen idgen.IDGenerator, checker StateChecker, accessTTL, refreshTTL time.Duration) *Storage {
	s := &Storage{
		db:              db,
		clock:           clk,
		idgen:           gen,
		stateChecker:    checker,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}
	s.clientPolicy = NewCoreClientResolutionPolicy(s)
	s.resourcePolicy = NewCoreResourceBindingPolicy()
	return s
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
