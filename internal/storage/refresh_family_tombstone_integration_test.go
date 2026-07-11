//go:build integration

package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/testutil"
)

func newTombstoneStore(t *testing.T) (*Storage, *clock.FixedClock, idgen.CryptoGenerator) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	store := withTestKeys(t, New(db, clk, gen, func(*User) error { return nil }, 15*time.Minute, 30*24*time.Hour))
	return store, clk, gen
}

// Reuse detection must tombstone the family, not only flip existing rows.
func TestRefreshFamily_TombstonedOnReuse(t *testing.T) {
	store, clk, gen := newTombstoneStore(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "tombstone-reuse@test.com", EmailVerified: true, Name: "T", Provider: "google", ProviderUserID: "tombstone-reuse-sub",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := clk.Now()
	familyID := gen.NewUUID()
	reusedToken := "tombstone-reused-token"
	if _, err := store.DB().ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, revoked_at, used_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5, $5, $5)`,
		store.Keys().RefreshHash(reusedToken), familyID, user.ID, now.Add(30*24*time.Hour), now,
	); err != nil {
		t.Fatalf("insert reused token: %v", err)
	}

	if _, err := store.TokenRequestByRefreshToken(ctx, reusedToken); err == nil {
		t.Fatal("expected invalid refresh token error on reuse")
	}

	var reason string
	if err := store.DB().QueryRowContext(ctx,
		`SELECT reason FROM refresh_token_families WHERE family_id = $1`, familyID,
	).Scan(&reason); err != nil {
		t.Fatalf("expected tombstone row for family: %v", err)
	}
	if reason != "reuse_detected" {
		t.Errorf("tombstone reason = %q, want reuse_detected", reason)
	}
}

// A tombstoned family must refuse to issue a new child token even when a valid
// (not-yet-used) parent token is presented for rotation — this is the race the
// tombstone closes (row-level family revoke alone would miss the new child).
func TestRefreshFamily_TombstoneBlocksChildIssue(t *testing.T) {
	store, clk, gen := newTombstoneStore(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "tombstone-block@test.com", EmailVerified: true, Name: "B", Provider: "google", ProviderUserID: "tombstone-block-sub",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := clk.Now()
	familyID := gen.NewUUID()
	currentToken := "tombstone-current-token"
	if _, err := store.DB().ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5)`,
		store.Keys().RefreshHash(currentToken), familyID, user.ID, now.Add(30*24*time.Hour), now,
	); err != nil {
		t.Fatalf("insert current token: %v", err)
	}

	// Family gets tombstoned (as reuse detection would do).
	if _, err := store.DB().ExecContext(ctx,
		`INSERT INTO refresh_token_families (family_id, user_id, reason) VALUES ($1, $2, 'reuse_detected')`,
		familyID, user.ID,
	); err != nil {
		t.Fatalf("tombstone family: %v", err)
	}

	req := &RefreshTokenModel{UserID: user.ID, ClientID: "test-client", Scopes: StringArray{"openid"}}
	_, _, _, err = store.CreateAccessAndRefreshTokens(ctx, req, currentToken)
	if !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("rotation into tombstoned family err = %v, want ErrInvalidRefreshToken", err)
	}
}

// Rotation into a healthy (non-tombstoned) family must still succeed.
func TestRefreshFamily_HealthyFamilyRotates(t *testing.T) {
	store, clk, gen := newTombstoneStore(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "tombstone-healthy@test.com", EmailVerified: true, Name: "H", Provider: "google", ProviderUserID: "tombstone-healthy-sub",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := clk.Now()
	familyID := gen.NewUUID()
	currentToken := "tombstone-healthy-token"
	if _, err := store.DB().ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5)`,
		store.Keys().RefreshHash(currentToken), familyID, user.ID, now.Add(30*24*time.Hour), now,
	); err != nil {
		t.Fatalf("insert current token: %v", err)
	}

	req := &RefreshTokenModel{UserID: user.ID, ClientID: "test-client", Scopes: StringArray{"openid"}}
	if _, newRefresh, _, err := store.CreateAccessAndRefreshTokens(ctx, req, currentToken); err != nil || newRefresh == "" {
		t.Fatalf("healthy rotation failed: token=%q err=%v", newRefresh, err)
	}
}
