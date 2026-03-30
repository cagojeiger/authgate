//go:build integration

package storage

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://authgate:authgate@localhost:5432/authgate?sslmode=disable"
	}
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("db not available: %v", err)
	}
	return db
}

func testStorage(t *testing.T) *Storage {
	t.Helper()
	db := testDB(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{} // Use real UUIDs to avoid PK collisions across test runs
	noopChecker := func(user *User) error { return nil }
	return New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)
}

func TestCreateUserWithIdentity_Atomic(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	// Clean up
	s.db.ExecContext(ctx, "DELETE FROM user_identities WHERE provider_user_id = 'integ-sub-1'")
	s.db.ExecContext(ctx, "DELETE FROM users WHERE email = 'integ-atomic@test.com'")

	// Success case
	user, err := s.CreateUserWithIdentity(ctx, "integ-atomic@test.com", true, "Test", "", "google", "integ-sub-1", "integ@test.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if user.Status != "active" {
		t.Errorf("status = %q, want active", user.Status)
	}

	// Verify both user and identity exist
	found, err := s.GetUserByProviderIdentity(ctx, "google", "integ-sub-1")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if found.ID != user.ID {
		t.Errorf("found.ID = %q, want %q", found.ID, user.ID)
	}

	// Duplicate should fail (email unique)
	_, err = s.CreateUserWithIdentity(ctx, "integ-atomic@test.com", true, "Test2", "", "google", "integ-sub-2", "integ2@test.com")
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}

	// Clean up
	s.db.ExecContext(ctx, "DELETE FROM user_identities WHERE provider_user_id = 'integ-sub-1'")
	s.db.ExecContext(ctx, "DELETE FROM users WHERE email = 'integ-atomic@test.com'")
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

	// Setup: create user + client + refresh token
	s.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE client_id = 'integ-refresh-client'")
	s.db.ExecContext(ctx, "DELETE FROM user_identities WHERE provider_user_id = 'integ-refresh-sub'")
	s.db.ExecContext(ctx, "DELETE FROM users WHERE email = 'integ-refresh@test.com'")

	user, err := s.CreateUserWithIdentity(ctx, "integ-refresh@test.com", true, "Test", "", "google", "integ-refresh-sub", "r@test.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Accept terms so state checker passes
	s.AcceptTerms(ctx, user.ID, "2026-03-28", "2026-03-28")

	// Insert a refresh token directly
	token := "test-refresh-token-123"
	tokenHash := hashToken(token)
	now := s.clock.Now()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, uuid_generate_v4(), $2, 'integ-refresh-client', '{openid}', $3, $4)`,
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

	// Clean up
	s.db.ExecContext(ctx, "DELETE FROM refresh_tokens WHERE client_id = 'integ-refresh-client'")
	s.db.ExecContext(ctx, "DELETE FROM user_identities WHERE provider_user_id = 'integ-refresh-sub'")
	s.db.ExecContext(ctx, "DELETE FROM users WHERE email = 'integ-refresh@test.com'")
}

func TestTokenTTL_UsesConfigValues(t *testing.T) {
	db := testDB(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC)}
	gen := &idgen.SequentialGenerator{}

	customAccessTTL := 5 * time.Minute
	customRefreshTTL := 7 * 24 * time.Hour

	s := New(db, clk, gen, nil, customAccessTTL, customRefreshTTL)

	// Verify access token TTL
	_, expiration, err := s.CreateAccessToken(context.Background(), &AuthRequestModel{Subject: ptrStr("user-1")})
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}

	expectedExp := clk.Now().Add(customAccessTTL)
	if !expiration.Equal(expectedExp) {
		t.Errorf("access token expiration = %v, want %v (5min from now)", expiration, expectedExp)
	}
}

func ptrStr(s string) *string { return &s }
