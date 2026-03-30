//go:build integration

package storage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/testutil"
)

func testStorage(t *testing.T) *Storage {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *User) error { return nil }
	return New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)
}

func TestCreateUserWithIdentity_Atomic(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	user, err := s.CreateUserWithIdentity(ctx, "atomic@test.com", true, "Test", "", "google", "atomic-sub-1", "atomic@test.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if user.Status != "active" {
		t.Errorf("status = %q, want active", user.Status)
	}

	// Verify both user and identity exist
	found, err := s.GetUserByProviderIdentity(ctx, "google", "atomic-sub-1")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if found.ID != user.ID {
		t.Errorf("found.ID = %q, want %q", found.ID, user.ID)
	}

	// Duplicate email should fail
	_, err = s.CreateUserWithIdentity(ctx, "atomic@test.com", true, "Test2", "", "google", "atomic-sub-2", "dup@test.com")
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestGetUserByProviderIdentity_NotFound(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	_, err := s.GetUserByProviderIdentity(ctx, "google", "nonexistent-sub")
	if err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestRefreshTokenRotation_Atomicity(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	// Setup: create user + accept terms
	user, err := s.CreateUserWithIdentity(ctx, "refresh@test.com", true, "Test", "", "google", "refresh-sub", "r@test.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	s.AcceptTerms(ctx, user.ID, "2026-03-28", "2026-03-28")

	// Insert refresh token directly
	token := "test-refresh-token-atomicity"
	tokenHash := hashToken(token)
	now := s.clock.Now()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, uuid_generate_v4(), $2, 'test-client', '{openid}', $3, $4)`,
		tokenHash, user.ID, now.Add(30*24*time.Hour), now,
	)
	if err != nil {
		t.Fatalf("insert token: %v", err)
	}

	// Concurrent rotation: 2 goroutines try to use the same token
	var wg sync.WaitGroup
	results := make(chan error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.TokenRequestByRefreshToken(ctx, token)
			results <- err
		}()
	}

	wg.Wait()
	close(results)

	successCount := 0
	failCount := 0
	for err := range results {
		if err == nil {
			successCount++
		} else {
			failCount++
		}
	}

	if successCount != 1 {
		t.Errorf("concurrent rotation: %d succeeded, want exactly 1", successCount)
	}
	if failCount != 1 {
		t.Errorf("concurrent rotation: %d failed, want exactly 1", failCount)
	}
}

func TestTokenTTL_UsesConfigValues(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}

	customAccessTTL := 5 * time.Minute
	customRefreshTTL := 7 * 24 * time.Hour

	s := New(db, clk, gen, nil, customAccessTTL, customRefreshTTL)

	_, expiration, err := s.CreateAccessToken(context.Background(), &AuthRequestModel{Subject: ptrStr("user-1")})
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}

	expectedExp := clk.Now().Add(customAccessTTL)
	if !expiration.Equal(expectedExp) {
		t.Errorf("access token expiration = %v, want %v (5min from now)", expiration, expectedExp)
	}
}

func TestAcceptTerms(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	user, err := s.CreateUserWithIdentity(ctx, "terms@test.com", true, "Test", "", "google", "terms-sub", "t@test.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Before accepting: terms fields should be nil
	found, _ := s.GetUserByProviderIdentity(ctx, "google", "terms-sub")
	if found.TermsAcceptedAt != nil {
		t.Error("terms_accepted_at should be nil before accepting")
	}

	// Accept terms
	err = s.AcceptTerms(ctx, user.ID, "2026-03-28", "2026-03-28")
	if err != nil {
		t.Fatalf("accept terms: %v", err)
	}

	// After accepting
	found, _ = s.GetUserByProviderIdentity(ctx, "google", "terms-sub")
	if found.TermsAcceptedAt == nil {
		t.Error("terms_accepted_at should not be nil after accepting")
	}
	if found.TermsVersion == nil || *found.TermsVersion != "2026-03-28" {
		t.Errorf("terms_version = %v, want 2026-03-28", found.TermsVersion)
	}
}

func TestSession_CreateAndValidate(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	user, err := s.CreateUserWithIdentity(ctx, "session@test.com", true, "Test", "", "google", "session-sub", "s@test.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	sessionID, err := s.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Valid session
	found, err := s.GetValidSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if found.ID != user.ID {
		t.Errorf("session user = %q, want %q", found.ID, user.ID)
	}

	// Invalid session (valid UUID format but doesn't exist)
	_, err = s.GetValidSession(ctx, "00000000-0000-0000-0000-000000000000")
	if err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func ptrStr(s string) *string { return &s }
