//go:build integration

package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/crypto"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
	"github.com/kangheeyong/authgate/internal/upstream"
)

// newTestStore builds a Storage with PII encryption configured. Keys are
// mandatory after the plaintext-PII cleanup (ADR-002), so every service test
// store must have them wired.
func newTestStore(t *testing.T, db *sql.DB, clk clock.Clock, gen idgen.IDGenerator, checker storage.StateChecker) *storage.Storage {
	t.Helper()
	store := storage.New(db, clk, gen, checker, 15*time.Minute, 30*24*time.Hour)
	mk := func(b byte) []byte {
		s := make([]byte, crypto.KeySize)
		for i := range s {
			s[i] = b
		}
		return s
	}
	enc, err := crypto.NewRoot(crypto.DomainEnc, "enc-test-1", mk(0x31))
	if err != nil {
		t.Fatalf("enc root: %v", err)
	}
	lookup, err := crypto.NewRoot(crypto.DomainLookup, "lkp-test-1", mk(0x32))
	if err != nil {
		t.Fatalf("lookup root: %v", err)
	}
	keys, err := crypto.NewKeys(enc, lookup)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	store.SetKeys(keys)
	if err := store.EnsureCryptoEpochs(context.Background()); err != nil {
		t.Fatalf("ensure epochs: %v", err)
	}
	return store
}

type gapFixture struct {
	LoginSvc    *LoginService
	MCPLoginSvc *MCPLoginService
	DeviceSvc   *DeviceService
	Store       *storage.Storage
	DB          *sql.DB
	Clock       *clock.FixedClock
	// FakeUser is the upstream identity the high-level provider would deliver to
	// the Complete* callbacks; tests pass it directly now that the service layer
	// no longer performs the upstream exchange itself.
	FakeUser *upstream.UserInfo
}

// setupBrowserExtTest creates a LoginService with a fixed sub for browser extended tests.
func setupBrowserExtTest(t *testing.T) (*LoginService, *storage.Storage, *upstream.UserInfo) {
	t.Helper()
	return setupLoginServiceWithSub(t, "browser-ext-sub", "browser-ext@test.com")
}

// setupMCPExtTest creates an MCPLoginService with a configurable sub for MCP tests.
func setupMCPExtTest(t *testing.T, sub string) (*MCPLoginService, *storage.Storage, *upstream.UserInfo) {
	t.Helper()
	return setupMCPLoginServiceWithSub(t, sub, sub+"@test.com")
}

// setupDeviceExtTest creates a DeviceService with a configurable sub.
func setupDeviceExtTest(t *testing.T, sub string) (*DeviceService, *storage.Storage, clock.Clock, *upstream.UserInfo) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := newTestStore(t, db, clk, gen, noopChecker)
	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: sub, Email: sub + "@test.com", EmailVerified: true, Name: "Device Ext"},
	}
	svc := NewDeviceService(store, fakeProvider.Name(), "http://localhost:8080", 24*time.Hour, clk)
	return svc, store, clk, fakeProvider.User
}

// setupGapTest creates all services for cross-service gap tests.
func setupGapTest(t *testing.T) *gapFixture {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := newTestStore(t, db, clk, gen, noopChecker)
	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: "gap-sub", Email: "gap@test.com", EmailVerified: true, Name: "Gap User"},
	}
	loginSvc := NewLoginService(store, fakeProvider.Name(), 24*time.Hour)
	mcpLoginSvc := NewMCPLoginService(store, fakeProvider.Name(), 24*time.Hour)
	deviceSvc := NewDeviceService(store, fakeProvider.Name(), "http://localhost:8080", 24*time.Hour, clk)
	return &gapFixture{
		LoginSvc:    loginSvc,
		MCPLoginSvc: mcpLoginSvc,
		DeviceSvc:   deviceSvc,
		Store:       store,
		DB:          db,
		Clock:       clk,
		FakeUser:    fakeProvider.User,
	}
}

// setupLoginServiceWithSub creates a LoginService with a specific upstream sub/email.
func setupLoginServiceWithSub(t *testing.T, sub, email string) (*LoginService, *storage.Storage, *upstream.UserInfo) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := newTestStore(t, db, clk, gen, noopChecker)
	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: sub, Email: email, EmailVerified: true, Name: "Test User"},
	}
	svc := NewLoginService(store, fakeProvider.Name(), 24*time.Hour)
	return svc, store, fakeProvider.User
}

// setupMCPLoginServiceWithSub creates an MCPLoginService with a specific upstream sub/email.
func setupMCPLoginServiceWithSub(t *testing.T, sub, email string) (*MCPLoginService, *storage.Storage, *upstream.UserInfo) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := newTestStore(t, db, clk, gen, noopChecker)
	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: sub, Email: email, EmailVerified: true, Name: "Test User"},
	}
	svc := NewMCPLoginService(store, fakeProvider.Name(), 24*time.Hour)
	return svc, store, fakeProvider.User
}
