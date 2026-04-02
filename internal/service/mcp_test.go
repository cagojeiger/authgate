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
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: "mcp-sub-123", Email: "mcp@test.com", EmailVerified: true, Name: "MCP User"},
	}

	svc := NewLoginService(store, fakeProvider, fakeProvider, 24*time.Hour)
	return svc, store
}

func TestMCP_CompleteUser_AutoApprove(t *testing.T) {
	svc, store := setupMCPTest(t)
	ctx := context.Background()

	store.CreateUserWithIdentity(ctx, "mcp-ok@test.com", true, "MCP", "", "google", "mcp-sub-123", "mcp@test.com")
	arID, _ := store.CreateTestAuthRequest(ctx, "mcp-ok")

	result := svc.HandleMCPCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-client")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (MCP active user)", result.Action)
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

// mcp-005: recoverable_browser_only → MCP callback → account_inactive
func TestMCP005_Recoverable_Rejected(t *testing.T) {
	svc, store := setupMCPExtTest(t, "mcp-005-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-recover@test.com", true, "Test", "", "google", "mcp-005-sub", "mrc@test.com")
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

// channel-005: pending_deletion + mcp(login with session) -> account_inactive
func TestMCPLogin_PendingDeletionSession_Rejected(t *testing.T) {
	svc, store := setupMCPTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-login-pending@test.com", true, "MCP Pending", "", "google", "mcp-login-pending-sub", "mcp-login-pending@test.com")
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	_ = store.SetUserStatus(ctx, user.ID, "pending_deletion")
	arID, _ := store.CreateTestAuthRequest(ctx, "mcp-login-pending")

	result := svc.HandleMCPLogin(ctx, arID, sessionID, "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// channel-005: deleted + mcp(login with session) -> account_inactive
func TestMCPLogin_DeletedSession_Rejected(t *testing.T) {
	svc, store := setupMCPTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-login-deleted@test.com", true, "MCP Deleted", "", "google", "mcp-login-deleted-sub", "mcp-login-deleted@test.com")
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	_ = store.SetUserStatus(ctx, user.ID, "deleted")
	arID, _ := store.CreateTestAuthRequest(ctx, "mcp-login-deleted")

	result := svc.HandleMCPLogin(ctx, arID, sessionID, "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// mcp-004: deleted user callback -> account_inactive
func TestMCP_DeletedUser_Rejected(t *testing.T) {
	svc, store := setupMCPExtTest(t, "mcp-deleted-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "mcp-deleted@test.com", true, "MCP", "", "google", "mcp-deleted-sub", "mcp-deleted@test.com")
	_ = store.SetUserStatus(ctx, user.ID, "deleted")
	arID, _ := store.CreateTestAuthRequest(ctx, "mcp-deleted")

	result := svc.HandleMCPCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error (deleted user)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}
