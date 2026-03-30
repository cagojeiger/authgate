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

// MCP uses dedicated login/callback paths and applies MCP channel policy.
// These tests verify the MCP channel guard works correctly.

func setupMCPTest(t *testing.T) (*LoginService, *storage.Storage) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{
		User: &upstream.UserInfo{Sub: "mcp-sub-123", Email: "mcp@test.com", EmailVerified: true, Name: "MCP User"},
	}

	svc := NewLoginService(store, fakeProvider, fakeProvider, termsV, privacyV, 24*time.Hour)
	return svc, store
}

func TestMCP_CompleteUser_AutoApprove(t *testing.T) {
	svc, store := setupMCPTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-ok@test.com", true, "MCP", "", "google", "mcp-sub-123", "mcp@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	arID, _ := store.CreateTestAuthRequest(ctx, "mcp-ok")

	result := svc.HandleMCPCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-client")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (MCP complete user)", result.Action)
	}
}

func TestMCP_NewUser_SignupRequired(t *testing.T) {
	svc, _ := setupMCPTest(t)
	ctx := context.Background()

	result := svc.HandleMCPCallback(ctx, "fake-code", "req-mcp-new", "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error (MCP new user)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

func TestMCP_DisabledUser_Rejected(t *testing.T) {
	svc, store := setupMCPTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-dis@test.com", true, "MCP", "", "google", "mcp-sub-123", "mcp@test.com")
	store.DisableUser(ctx, user.ID)

	result := svc.HandleMCPCallback(ctx, "fake-code", "req-mcp-dis", "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error (disabled user)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}
// mcp-003: initial_onboarding_incomplete → MCP callback → signup_required
func TestMCP003_InitialIncomplete_Rejected(t *testing.T) {
	svc, store := setupMCPExtTest(t, "mcp-003-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-incomplete@test.com", true, "Test", "", "google", "mcp-003-sub", "mi@test.com")
	_ = user

	result := svc.HandleMCPCallback(ctx, "fake-code", "req-mcp-003", "127.0.0.1", "mcp-client")
	if result.Action != ActionError {
		t.Errorf("action = %v, want Error (initial incomplete via MCP)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// mcp-004: reconsent_required → MCP callback → signup_required
func TestMCP004_Reconsent_Rejected(t *testing.T) {
	svc, store := setupMCPExtTest(t, "mcp-004-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-reconsent@test.com", true, "Test", "", "google", "mcp-004-sub", "mr@test.com")
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version")

	result := svc.HandleMCPCallback(ctx, "fake-code", "req-mcp-004", "127.0.0.1", "mcp-client")
	if result.Action != ActionError {
		t.Errorf("action = %v, want Error (reconsent via MCP)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// mcp-005: recoverable_browser_only → MCP callback → account_inactive
func TestMCP005_Recoverable_Rejected(t *testing.T) {
	svc, store := setupMCPExtTest(t, "mcp-005-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-recover@test.com", true, "Test", "", "google", "mcp-005-sub", "mrc@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	arID, _ := store.CreateTestAuthRequest(ctx, "mcp-005")
	result := svc.HandleMCPCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error (recoverable via MCP)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}
