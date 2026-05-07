//go:build integration

package storage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/testutil"
)

func testStorage(t *testing.T) *Storage {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *User) error { return nil }
	return New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)
}

func TestCreateUserWithIdentity_Atomic(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "atomic@test.com", EmailVerified: true, Name: "Test", AvatarURL: "", Provider: "google", ProviderUserID: "atomic-sub-1", ProviderEmail: "atomic@test.com"})
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
	_, err = s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "atomic@test.com", EmailVerified: true, Name: "Test2", AvatarURL: "", Provider: "google", ProviderUserID: "atomic-sub-2", ProviderEmail: "dup@test.com"})
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

	// Setup: create user
	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "refresh@test.com", EmailVerified: true, Name: "Test", AvatarURL: "", Provider: "google", ProviderUserID: "refresh-sub", ProviderEmail: "r@test.com"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	_ = user

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
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 12, 0, 0, 0, time.UTC)}
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

func TestSession_CreateAndValidate(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "session@test.com", EmailVerified: true, Name: "Test", AvatarURL: "", Provider: "google", ProviderUserID: "session-sub", ProviderEmail: "s@test.com"})
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

// TestSession_StatusFilter covers #157: GetValidSession must reject sessions
// belonging to users in terminal states (`disabled`, `deleted`) at the
// storage layer with ErrUserAccountClosed, while still passing through
// `active` and `pending_deletion` so the channel × status policy in
// service.CheckAccess can handle browser-channel recovery.
func TestSession_StatusFilter(t *testing.T) {
	cases := []struct {
		name     string
		status   string
		wantErr  error
		wantUser bool
	}{
		{name: "active user passes through", status: "active", wantErr: nil, wantUser: true},
		{name: "pending_deletion passes through", status: "pending_deletion", wantErr: nil, wantUser: true},
		{name: "disabled user is rejected", status: "disabled", wantErr: ErrUserAccountClosed, wantUser: true},
		{name: "deleted user is rejected", status: "deleted", wantErr: ErrUserAccountClosed, wantUser: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testStorage(t)
			ctx := context.Background()

			user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
				Email: tc.name + "@test.com", EmailVerified: true, Name: "Test", AvatarURL: "",
				Provider: "google", ProviderUserID: "filter-" + tc.name, ProviderEmail: tc.name + "@test.com",
			})
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			if tc.status != "active" {
				if err := s.SetUserStatus(ctx, user.ID, tc.status); err != nil {
					t.Fatalf("set status %q: %v", tc.status, err)
				}
			}

			sessionID, err := s.CreateSession(ctx, user.ID, 24*time.Hour)
			if err != nil {
				t.Fatalf("create session: %v", err)
			}

			got, err := s.GetValidSession(ctx, sessionID)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantUser && got == nil {
				t.Fatalf("user = nil, want non-nil so caller can audit")
			}
			if got != nil && got.Status != tc.status {
				t.Errorf("status = %q, want %q", got.Status, tc.status)
			}
		})
	}
}

// TestValidateBearerTokenWithClientID_StatusFilter covers #161: the bearer
// validation path must reject `disabled` / `deleted` accounts at the
// storage layer with ErrUserAccountClosed (and pass through `active` /
// `pending_deletion` so service.CheckAccess can apply channel-aware
// policy).
func TestValidateBearerTokenWithClientID_StatusFilter(t *testing.T) {
	cases := []struct {
		name    string
		status  string
		wantErr error
	}{
		{name: "active passes through", status: "active", wantErr: nil},
		{name: "pending_deletion passes through", status: "pending_deletion", wantErr: nil},
		{name: "disabled is rejected", status: "disabled", wantErr: ErrUserAccountClosed},
		{name: "deleted is rejected", status: "deleted", wantErr: ErrUserAccountClosed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testStorage(t)
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("rsa key: %v", err)
			}
			s.SetSigningKey(key, "kid-1")
			s.SetIssuer("https://test.authgate")

			ctx := context.Background()
			user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
				Email: tc.name + "@bearer.test", EmailVerified: true, Name: "Bearer", AvatarURL: "",
				Provider: "google", ProviderUserID: "bearer-" + tc.name, ProviderEmail: tc.name + "@bearer.test",
			})
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			if tc.status != "active" {
				if err := s.SetUserStatus(ctx, user.ID, tc.status); err != nil {
					t.Fatalf("set status %q: %v", tc.status, err)
				}
			}

			now := s.clock.Now()
			token := signTestToken(t, key, josejwt.Claims{
				Issuer:   "https://test.authgate",
				Subject:  user.ID,
				Audience: josejwt.Audience{"client-a"},
				IssuedAt: josejwt.NewNumericDate(now),
				Expiry:   josejwt.NewNumericDate(now.Add(15 * time.Minute)),
			})

			got, gotClientID, err := s.ValidateBearerTokenWithClientID(ctx, "Bearer "+token)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got == nil {
				t.Fatalf("user = nil, want non-nil so caller can audit")
			}
			if gotClientID != "client-a" {
				t.Errorf("client_id = %q, want client-a", gotClientID)
			}
			if got.Status != tc.status {
				t.Errorf("status = %q, want %q", got.Status, tc.status)
			}
		})
	}
}
