//go:build integration

package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clock"
)

const testReuseGrace = 5 * time.Second

type graceFixture struct {
	store    *Storage
	clk      *clock.FixedClock
	userID   string
	familyID string
	first    string // the family's first token
}

// newGraceFixture creates a user with one live refresh token and redeems it
// once through the real rotation path, so the first token is exactly what a
// concurrent sibling request would present a moment later.
func newGraceFixture(t *testing.T, grace time.Duration) (*graceFixture, string) {
	t.Helper()
	store, clk, gen := newTombstoneStore(t)
	store.SetRefreshReuseGrace(grace)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "grace-" + gen.NewUUID() + "@test.com", EmailVerified: true, Name: "G", Provider: "google", ProviderUserID: "grace-" + gen.NewUUID(),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	f := &graceFixture{store: store, clk: clk, userID: user.ID, familyID: gen.NewUUID(), first: "grace-first-token"}
	if _, err := store.DB().ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5)`,
		store.Keys().RefreshHash(f.first), f.familyID, user.ID, clk.Now().Add(30*24*time.Hour), clk.Now(),
	); err != nil {
		t.Fatalf("insert first token: %v", err)
	}

	child, err := f.redeem(t, f.first)
	if err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	return f, child
}

// redeem runs both halves of a refresh grant the way zitadel/oidc does.
func (f *graceFixture) redeem(t *testing.T, token string) (string, error) {
	t.Helper()
	ctx := context.Background()
	rt, err := f.store.TokenRequestByRefreshToken(ctx, token)
	if err != nil {
		return "", err
	}
	_, next, _, err := f.store.CreateAccessAndRefreshTokens(ctx, rt, token)
	return next, err
}

func (f *graceFixture) count(t *testing.T, query string) int {
	t.Helper()
	var n int
	if err := f.store.DB().QueryRowContext(context.Background(), query, f.familyID).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n
}

func (f *graceFixture) tombstoned(t *testing.T) bool {
	return f.count(t, `SELECT count(*) FROM refresh_token_families WHERE family_id = $1`) > 0
}

func (f *graceFixture) liveTokens(t *testing.T) int {
	return f.count(t, `SELECT count(*) FROM refresh_tokens WHERE family_id = $1 AND revoked_at IS NULL`)
}

func (f *graceFixture) reuseAudits(t *testing.T) int {
	return f.count(t, `SELECT count(*) FROM audit_log WHERE metadata->>'family_id' = $1::text AND event_type = 'auth.refresh_reuse_detected'`)
}

// The 2026-09-11 incident: a second session presents the token a sibling just
// redeemed. Inside the grace both sessions keep a working token.
func TestRefreshReuseGrace_SiblingRedemptionIssuesIntoSameFamily(t *testing.T) {
	f, child := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(2 * time.Second)

	sibling, err := f.redeem(t, f.first)
	if err != nil {
		t.Fatalf("redemption inside the grace was refused: %v", err)
	}
	if sibling == "" || sibling == child {
		t.Fatalf("expected a distinct sibling token, got %q (child %q)", sibling, child)
	}
	if f.tombstoned(t) {
		t.Fatal("family was tombstoned for a redemption inside the grace")
	}
	if got := f.liveTokens(t); got != 2 {
		t.Fatalf("live tokens = %d, want 2 (child and sibling)", got)
	}
	if got := f.reuseAudits(t); got != 0 {
		t.Fatalf("reuse audit rows = %d, want 0", got)
	}
	// Both sessions can keep rotating.
	for name, token := range map[string]string{"child": child, "sibling": sibling} {
		if _, err := f.redeem(t, token); err != nil {
			t.Fatalf("%s token no longer rotates: %v", name, err)
		}
	}
}

// Past the grace a redeemed token is a replay again.
func TestRefreshReuseGrace_AfterWindowDetectsReuse(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(testReuseGrace + time.Second)

	if _, err := f.redeem(t, f.first); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken", err)
	}
	if !f.tombstoned(t) {
		t.Fatal("expected reuse detection to tombstone the family")
	}
	if got := f.liveTokens(t); got != 0 {
		t.Fatalf("live tokens = %d, want 0", got)
	}
}

// A token revoked through /oauth/revoke was never redeemed, so it gets no grace
// even a moment after the revocation.
func TestRefreshReuseGrace_RevokedTokenGetsNoGrace(t *testing.T) {
	f, child := newGraceFixture(t, testReuseGrace)
	ctx := context.Background()

	if oerr := f.store.RevokeToken(ctx, child, f.userID, "test-client"); oerr != nil {
		t.Fatalf("revoke: %v", oerr)
	}
	f.clk.T = f.clk.T.Add(time.Second)

	if _, err := f.redeem(t, child); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken for a revoked token", err)
	}
	if !f.tombstoned(t) {
		t.Fatal("expected reuse detection for a revoked token presented again")
	}
}

// One redemption can yield at most refreshReuseGraceMaxIssued tokens. Past the
// cap the request is refused, but the family the other sessions use survives.
func TestRefreshReuseGrace_CapRefusesWithoutRevokingFamily(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	f.clk.T = f.clk.T.Add(time.Second)

	for i := 1; i < refreshReuseGraceMaxIssued; i++ {
		if _, err := f.redeem(t, f.first); err != nil {
			t.Fatalf("grace redemption %d refused: %v", i, err)
		}
	}
	if _, err := f.redeem(t, f.first); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken past the cap", err)
	}
	if f.tombstoned(t) {
		t.Fatal("reaching the cap must not tombstone the family")
	}
	if got := f.liveTokens(t); got != refreshReuseGraceMaxIssued {
		t.Fatalf("live tokens = %d, want %d", got, refreshReuseGraceMaxIssued)
	}
}

// Once reuse detection has revoked the family, the grace cannot revive it.
func TestRefreshReuseGrace_TombstonedFamilyGetsNoGrace(t *testing.T) {
	f, _ := newGraceFixture(t, testReuseGrace)
	ctx := context.Background()
	if _, err := f.store.DB().ExecContext(ctx,
		`INSERT INTO refresh_token_families (family_id, user_id, reason, revoked_at) VALUES ($1, $2, 'reuse_detected', $3)`,
		f.familyID, f.userID, f.clk.Now(),
	); err != nil {
		t.Fatalf("tombstone family: %v", err)
	}
	f.clk.T = f.clk.T.Add(time.Second)

	if _, err := f.redeem(t, f.first); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken for a tombstoned family", err)
	}
	if got := f.liveTokens(t); got != 0 {
		t.Fatalf("live tokens = %d, want 0", got)
	}
}

// With the grace disabled, the sibling redemption is reuse, as before.
func TestRefreshReuseGrace_DisabledDetectsReuse(t *testing.T) {
	f, _ := newGraceFixture(t, 0)
	f.clk.T = f.clk.T.Add(time.Second)

	if _, err := f.redeem(t, f.first); !errors.Is(err, op.ErrInvalidRefreshToken) {
		t.Fatalf("err = %v, want ErrInvalidRefreshToken with the grace disabled", err)
	}
	if !f.tombstoned(t) {
		t.Fatal("expected reuse detection with the grace disabled")
	}
}
