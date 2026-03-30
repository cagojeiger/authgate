//go:build integration

package service

import (
	"context"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
	"github.com/kangheeyong/authgate/internal/upstream"
)

func setupMCPExtTest(t *testing.T, sub string) (*LoginService, *storage.Storage) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)
	fakeProvider := &upstream.FakeProvider{
		User: &upstream.UserInfo{Sub: sub, Email: sub + "@test.com", EmailVerified: true, Name: "MCP Ext"},
	}
	svc := NewLoginService(store, fakeProvider, termsV, privacyV, 24*time.Hour)
	return svc, store
}

// mcp-003: initial_onboarding_incomplete → MCP callback → signup_required (via ShowTerms in browser path)
func TestMCP003_InitialIncomplete_ShowTerms(t *testing.T) {
	svc, _ := setupMCPExtTest(t, "mcp-003-sub")
	ctx := context.Background()

	// New user (not in DB) → signup → initial_onboarding_incomplete → ShowTerms
	result := svc.HandleCallback(ctx, "fake-code", "req-mcp-003", "127.0.0.1", "mcp-client")
	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (new user via MCP path)", result.Action)
	}
}

// mcp-004: reconsent_required → MCP callback → ShowTerms (browser path handles reconsent)
func TestMCP004_Reconsent_ShowTerms(t *testing.T) {
	svc, store := setupMCPExtTest(t, "mcp-004-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-reconsent@test.com", true, "Test", "", "google", "mcp-004-sub", "mr@test.com")
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version")

	result := svc.HandleCallback(ctx, "fake-code", "req-mcp-004", "127.0.0.1", "mcp-client")
	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (reconsent via MCP)", result.Action)
	}
}

// mcp-005: recoverable_browser_only → MCP callback → recovery then continue
func TestMCP005_Recoverable_RecoveryAndTermsOrApprove(t *testing.T) {
	svc, store := setupMCPExtTest(t, "mcp-005-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-recover@test.com", true, "Test", "", "google", "mcp-005-sub", "mrc@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	arID, _ := store.CreateTestAuthRequest(ctx, "mcp-005")
	result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-client")

	// Browser path recovers pending_deletion → since terms are done, auto-approve
	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (recovered via browser path)", result.Action)
	}
}
