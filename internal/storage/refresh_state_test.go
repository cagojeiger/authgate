//go:build integration

package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/guard"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/testutil"
)

// refresh-007: revoked token → family revoke + invalid_grant
func TestRefreshReuseDetection_FamilyRevoke(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *User) error { return nil }
	store := New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "reuse@test.com", true, "Test", "", "google", "reuse-sub", "ru@test.com")
	store.AcceptTerms(ctx, user.ID, "2026-03-28", "2026-03-28")

	// Insert two tokens in the same family
	now := clk.Now()
	familyID := gen.NewUUID()
	token1 := "reuse-token-1"
	token2 := "reuse-token-2"
	hash1 := hashToken(token1)
	hash2 := hashToken(token2)

	db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, revoked_at, used_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test', '{openid}', $4, $5, $5, $6)`,
		hash1, familyID, user.ID, now.Add(30*24*time.Hour), now, now) // token1: already used/revoked

	db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test', '{openid}', $4, $5)`,
		hash2, familyID, user.ID, now.Add(30*24*time.Hour), now) // token2: current valid

	// Attempt to reuse token1 (already used)
	_, err := store.TokenRequestByRefreshToken(ctx, token1)
	if err == nil {
		t.Fatal("expected error for reused token")
	}

	// token2 should now also be revoked (family revoke)
	var revokedAt *time.Time
	db.QueryRowContext(ctx, `SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1`, hash2).Scan(&revokedAt)
	if revokedAt == nil {
		t.Error("token2 should be revoked after family revoke (reuse detection)")
	}
}

func TestRefreshStateCheck_AllStates(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	ctx := context.Background()

	const termsV = "2026-03-28"
	const privacyV = "2026-03-28"

	// StateChecker that uses real guard logic
	checker := func(user *User) error {
		ui := &guard.UserInfo{
			Status:            user.Status,
			TermsAcceptedAt:   user.TermsAcceptedAt,
			PrivacyAcceptedAt: user.PrivacyAcceptedAt,
		}
		if user.TermsVersion != nil {
			ui.TermsVersion = *user.TermsVersion
		}
		if user.PrivacyVersion != nil {
			ui.PrivacyVersion = *user.PrivacyVersion
		}
		state := guard.DeriveLoginState(ui, termsV, privacyV)
		if state != guard.OnboardingComplete {
			return fmt.Errorf("login state: %s", state)
		}
		return nil
	}

	store := New(db, clk, gen, checker, 15*time.Minute, 30*24*time.Hour)

	tests := []struct {
		name       string
		setup      func(userID string) // modify user after creation
		wantError  bool
		wantState  string
	}{
		{
			name: "onboarding_complete - allow",
			setup: func(id string) {
				store.AcceptTerms(ctx, id, termsV, privacyV)
			},
			wantError: false,
		},
		{
			name:      "initial_onboarding_incomplete - reject",
			setup:     func(id string) {}, // no terms accepted
			wantError: true,
			wantState: "initial_onboarding_incomplete",
		},
		{
			name: "reconsent_required - reject",
			setup: func(id string) {
				store.AcceptTerms(ctx, id, "old-version", "old-version")
			},
			wantError: true,
			wantState: "reconsent_required",
		},
		{
			name: "recoverable_browser_only - reject",
			setup: func(id string) {
				store.AcceptTerms(ctx, id, termsV, privacyV)
				store.SetUserStatus(ctx, id, "pending_deletion")
			},
			wantError: true,
			wantState: "recoverable_browser_only",
		},
		{
			name: "inactive (disabled) - reject",
			setup: func(id string) {
				store.AcceptTerms(ctx, id, termsV, privacyV)
				store.SetUserStatus(ctx, id, "disabled")
			},
			wantError: true,
			wantState: "inactive",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := fmt.Sprintf("refresh-state-%d@test.com", i)
			sub := fmt.Sprintf("refresh-state-sub-%d", i)

			user, err := store.CreateUserWithIdentity(ctx, email, true, "Test", "", "google", sub, email)
			if err != nil {
				t.Fatalf("create user: %v", err)
			}

			tt.setup(user.ID)

			// Insert a refresh token
			token := fmt.Sprintf("refresh-state-token-%d", i)
			tokenHash := hashToken(token)
			now := clk.Now()
			_, err = db.ExecContext(ctx,
				`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
				 VALUES (uuid_generate_v4(), $1, uuid_generate_v4(), $2, 'test-client', '{openid}', $3, $4)`,
				tokenHash, user.ID, now.Add(30*24*time.Hour), now,
			)
			if err != nil {
				t.Fatalf("insert token: %v", err)
			}

			_, err = store.TokenRequestByRefreshToken(ctx, token)
			if tt.wantError && err == nil {
				t.Errorf("expected error for %s, got nil", tt.wantState)
			}
			if !tt.wantError && err != nil {
				t.Errorf("expected success, got error: %v", err)
			}
		})
	}
}

func TestAuthCodeStateCheck_AllStates(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	ctx := context.Background()

	const termsV = "2026-03-28"
	const privacyV = "2026-03-28"

	checker := func(user *User) error {
		ui := &guard.UserInfo{
			Status:            user.Status,
			TermsAcceptedAt:   user.TermsAcceptedAt,
			PrivacyAcceptedAt: user.PrivacyAcceptedAt,
		}
		if user.TermsVersion != nil {
			ui.TermsVersion = *user.TermsVersion
		}
		if user.PrivacyVersion != nil {
			ui.PrivacyVersion = *user.PrivacyVersion
		}
		state := guard.DeriveLoginState(ui, termsV, privacyV)
		if state != guard.OnboardingComplete {
			return fmt.Errorf("login state: %s", state)
		}
		return nil
	}

	store := New(db, clk, gen, checker, 15*time.Minute, 30*24*time.Hour)

	tests := []struct {
		name      string
		setup     func(userID string)
		wantError bool
		wantState string
	}{
		{
			name: "onboarding_complete - allow",
			setup: func(id string) {
				store.AcceptTerms(ctx, id, termsV, privacyV)
			},
			wantError: false,
		},
		{
			name:      "initial_onboarding_incomplete - reject",
			setup:     func(id string) {},
			wantError: true,
			wantState: "initial_onboarding_incomplete",
		},
		{
			name: "reconsent_required - reject",
			setup: func(id string) {
				store.AcceptTerms(ctx, id, "old-version", "old-version")
			},
			wantError: true,
			wantState: "reconsent_required",
		},
		{
			name: "recoverable_browser_only - reject",
			setup: func(id string) {
				store.AcceptTerms(ctx, id, termsV, privacyV)
				store.SetUserStatus(ctx, id, "pending_deletion")
			},
			wantError: true,
			wantState: "recoverable_browser_only",
		},
		{
			name: "inactive (disabled) - reject",
			setup: func(id string) {
				store.AcceptTerms(ctx, id, termsV, privacyV)
				store.SetUserStatus(ctx, id, "disabled")
			},
			wantError: true,
			wantState: "inactive",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := fmt.Sprintf("authcode-state-%d@test.com", i)
			sub := fmt.Sprintf("authcode-state-sub-%d", i)

			user, err := store.CreateUserWithIdentity(ctx, email, true, "Test", "", "google", sub, email)
			if err != nil {
				t.Fatalf("create user: %v", err)
			}

			tt.setup(user.ID)

			authRequestID, err := store.CreateTestAuthRequest(ctx, fmt.Sprintf("authcode-%d", i))
			if err != nil {
				t.Fatalf("create auth request: %v", err)
			}
			if err := store.CompleteAuthRequest(ctx, authRequestID, user.ID); err != nil {
				t.Fatalf("complete auth request: %v", err)
			}
			code := fmt.Sprintf("authcode-state-code-%d", i)
			if err := store.SaveAuthCode(ctx, authRequestID, code); err != nil {
				t.Fatalf("save auth code: %v", err)
			}

			_, err = store.AuthRequestByCode(ctx, code)
			if tt.wantError && err == nil {
				t.Errorf("expected error for %s, got nil", tt.wantState)
			}
			if !tt.wantError && err != nil {
				t.Errorf("expected success, got error: %v", err)
			}
			if tt.wantError && err != nil && err.Error() != "login state: "+tt.wantState && !containsInvalidGrant(err.Error()) {
				t.Errorf("expected invalid_grant-style error for %s, got %v", tt.wantState, err)
			}
		})
	}
}

func containsInvalidGrant(msg string) bool {
	return strings.Contains(msg, "invalid_grant")
}
