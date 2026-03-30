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

// MCP uses the same code path as browser login (Spec 004).
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

	svc := NewLoginService(store, fakeProvider, termsV, privacyV, 24*time.Hour)
	return svc, store
}

func TestMCP_CompleteUser_AutoApprove(t *testing.T) {
	svc, store := setupMCPTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-ok@test.com", true, "MCP", "", "google", "mcp-sub-123", "mcp@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	arID, _ := store.CreateTestAuthRequest(ctx, "mcp-ok")

	// MCP uses /login/callback — same as browser
	result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-client")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (MCP complete user)", result.Action)
	}
}

func TestMCP_IncompleteUser_ShowTerms(t *testing.T) {
	svc, _ := setupMCPTest(t)
	ctx := context.Background()

	// New user via MCP callback — should show terms (browser path)
	result := svc.HandleCallback(ctx, "fake-code", "req-mcp-new", "127.0.0.1", "mcp-client")

	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (MCP new user)", result.Action)
	}
}

func TestMCP_DisabledUser_Rejected(t *testing.T) {
	svc, store := setupMCPTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-dis@test.com", true, "MCP", "", "google", "mcp-sub-123", "mcp@test.com")
	store.DisableUser(ctx, user.ID)

	result := svc.HandleCallback(ctx, "fake-code", "req-mcp-dis", "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error (disabled user)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}
