//go:build integration

package storage

import (
	"context"
	"database/sql"
	"errors"
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
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *User) error { return nil }
	return New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)
}

func TestCreateUserWithIdentity_Atomic(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "atomic@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "atomic-sub-1", ProviderEmail: "atomic@test.com"})
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
	_, err = s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "atomic@test.com", EmailVerified: true, Name: "Test2", Provider: "google", ProviderUserID: "atomic-sub-2", ProviderEmail: "dup@test.com"})
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
	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "refresh@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "refresh-sub", ProviderEmail: "r@test.com"})
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

	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "session@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "session-sub", ProviderEmail: "s@test.com"})
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
				Email: tc.name + "@test.com", EmailVerified: true, Name: "Test",
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

// #183: RequestDeletion must NOT overwrite a closed-account status. The
// browser-channel recovery path treats `pending_deletion` as recoverable, so
// if `disabled` (operator suspension) silently became `pending_deletion`
// because the conditional UPDATE was missing, the user could log back in and
// reach `active` again — bypassing the suspension entirely.
//
// This test exercises the storage invariant directly (bypassing
// GetValidSession's status filter) to model the operator-side race: a user
// has a valid session, then gets disabled in between session validation and
// the storage UPDATE.
func TestRequestDeletion_RejectsClosedAccount(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name           string
		flipStatus     string
		wantErr        error
		wantFinalState string
	}{
		{"disabled", "disabled", ErrUserAccountClosed, "disabled"},
		{"deleted", "deleted", ErrUserAccountClosed, "deleted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testStorage(t)
			user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
				Email: "del-" + tc.flipStatus + "@test.com", EmailVerified: true, Name: "Del " + tc.flipStatus,
				Provider: "google", ProviderUserID: "del-sub-" + tc.flipStatus, ProviderEmail: "del-" + tc.flipStatus + "@test.com",
			})
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			if err := s.SetUserStatus(ctx, user.ID, tc.flipStatus); err != nil {
				t.Fatalf("flip status: %v", err)
			}

			liveStatus, err := s.RequestDeletion(ctx, user.ID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("RequestDeletion err = %v, want %v", err, tc.wantErr)
			}
			if liveStatus != tc.wantFinalState {
				t.Errorf("liveStatus = %q, want %q (caller must see actual closed-account state for audit)", liveStatus, tc.wantFinalState)
			}

			got, err := s.GetUserByID(ctx, user.ID)
			if err != nil {
				t.Fatalf("re-read user: %v", err)
			}
			if got.Status != tc.wantFinalState {
				t.Errorf("status after rejected deletion = %q, want %q (closed-account suspension lost)", got.Status, tc.wantFinalState)
			}
		})
	}
}

// #183 (companion): pending_deletion must remain idempotent — calling
// RequestDeletion again returns nil and does not error, since the user is
// already in the target state. Critically, the UPDATE must NOT bump
// deletion_requested_at on retry because that would extend the 30-day
// recovery window every time a client retries — a vulnerability of its
// own (the user could keep the account in indefinite "pending" by
// hammering DELETE /account).
func TestRequestDeletion_PendingDeletionIsIdempotent(t *testing.T) {
	ctx := context.Background()
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *User) error { return nil }
	db := testutil.SetupPostgres(t)
	s := New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "del-idem@test.com", EmailVerified: true, Name: "Del Idem",
		Provider: "google", ProviderUserID: "del-idem-sub", ProviderEmail: "del-idem@test.com",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := s.RequestDeletion(ctx, user.ID); err != nil {
		t.Fatalf("first RequestDeletion: %v", err)
	}

	got1, _ := s.GetUserByID(ctx, user.ID)
	if got1.Status != "pending_deletion" {
		t.Fatalf("first call status = %q, want pending_deletion", got1.Status)
	}
	var firstReq, firstSched sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT deletion_requested_at, deletion_scheduled_at FROM users WHERE id = $1`, user.ID).Scan(&firstReq, &firstSched); err != nil {
		t.Fatalf("read first deletion timestamps: %v", err)
	}

	// Advance clock so a buggy double-bump would be observable.
	clk.T = clk.T.Add(48 * time.Hour)

	if _, err := s.RequestDeletion(ctx, user.ID); err != nil {
		t.Fatalf("second RequestDeletion: %v", err)
	}
	got2, _ := s.GetUserByID(ctx, user.ID)
	if got2.Status != "pending_deletion" {
		t.Errorf("second call status = %q, want pending_deletion", got2.Status)
	}

	var secondReq, secondSched sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT deletion_requested_at, deletion_scheduled_at FROM users WHERE id = $1`, user.ID).Scan(&secondReq, &secondSched); err != nil {
		t.Fatalf("read second deletion timestamps: %v", err)
	}
	if !secondReq.Time.Equal(firstReq.Time) {
		t.Errorf("deletion_requested_at bumped on retry: first=%v second=%v (recovery window must not extend)", firstReq.Time, secondReq.Time)
	}
	if !secondSched.Time.Equal(firstSched.Time) {
		t.Errorf("deletion_scheduled_at bumped on retry: first=%v second=%v", firstSched.Time, secondSched.Time)
	}
}
