//go:build integration

package service

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
	"github.com/kangheeyong/authgate/internal/upstream"
)

func setupAccountTest(t *testing.T) (*AccountService, *LoginService, *storage.Storage, *sql.DB, *clock.FixedClock) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: "acct-sub-123", Email: "acct@test.com", EmailVerified: true, Name: "Acct User"},
	}

	accountSvc := NewAccountService(store)
	loginSvc := NewLoginService(store, fakeProvider, fakeProvider, 24*time.Hour)
	return accountSvc, loginSvc, store, db, clk
}

// Helper: create user + session, return sessionID for deletion tests
func createUserWithSession(t *testing.T, store *storage.Storage, email, sub string) (string, string) {
	t.Helper()
	ctx := context.Background()
	user, err := store.CreateUserWithIdentity(ctx, email, true, "Test", "", "google", sub, email)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, err := store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return user.ID, sessionID
}

func TestDeleteAccount_Success(t *testing.T) {
	accountSvc, _, store, db, _ := setupAccountTest(t)
	ctx := context.Background()

	userID, sessionID := createUserWithSession(t, store, "delete@test.com", "del-sub")

	result := accountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}

	var status string
	db.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, userID).Scan(&status)
	if status != "pending_deletion" {
		t.Errorf("status = %q, want pending_deletion", status)
	}
}

func TestDeleteAccount_Idempotent(t *testing.T) {
	accountSvc, _, store, _, _ := setupAccountTest(t)
	ctx := context.Background()

	_, sessionID := createUserWithSession(t, store, "idempotent@test.com", "idem-sub")

	accountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
	result := accountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
	if !result.Success {
		t.Errorf("expected idempotent success, got: %s", result.Message)
	}
}

func TestDeleteAccount_InactiveUser_Rejected(t *testing.T) {
	tests := []struct {
		name   string
		status string
	}{
		{name: "disabled", status: "disabled"},
		{name: "deleted", status: "deleted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accountSvc, _, store, _, _ := setupAccountTest(t)
			ctx := context.Background()

			_, sessionID := createUserWithSession(t, store, tt.name+"-del@test.com", tt.name+"-del-sub")
			user, _ := store.GetValidSession(ctx, sessionID)
			_ = store.SetUserStatus(ctx, user.ID, tt.status)

			result := accountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
			if result.Success {
				t.Fatalf("expected failure for %s user", tt.status)
			}
			if result.ErrorCode != 403 {
				t.Fatalf("errorCode = %d, want 403", result.ErrorCode)
			}
		})
	}
}

func TestDeleteAccount_NoSession(t *testing.T) {
	accountSvc, _, _, _, _ := setupAccountTest(t)
	ctx := context.Background()

	result := accountSvc.RequestDeletion(ctx, "", "127.0.0.1", "test")
	if result.Success {
		t.Error("expected failure without session")
	}
	if result.ErrorCode != 401 {
		t.Errorf("errorCode = %d, want 401", result.ErrorCode)
	}
}

// E2E 4: 탈퇴 후 복구
func TestE2E_DeleteThenRecover(t *testing.T) {
	accountSvc, loginSvc, store, db, _ := setupAccountTest(t)
	ctx := context.Background()

	_, sessionID := createUserWithSession(t, store, "e2e4@test.com", "acct-sub-123")
	user, _ := store.GetValidSession(ctx, sessionID)

	accountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")

	var status string
	db.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "pending_deletion" {
		t.Fatalf("status = %q, want pending_deletion", status)
	}

	arID, _ := store.CreateTestAuthRequest(ctx, "e2e4-recovery")
	result := loginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (recovered)", result.Action)
	}

	db.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "active" {
		t.Errorf("status after recovery = %q, want active", status)
	}
}

// E2E 5: 탈퇴 후 삭제 → 재가입
func TestE2E_DeleteThenReregister(t *testing.T) {
	accountSvc, loginSvc, store, db, clk := setupAccountTest(t)
	ctx := context.Background()

	userID, sessionID := createUserWithSession(t, store, "e2e5@test.com", "acct-sub-123")

	accountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")

	db.ExecContext(ctx, `UPDATE users SET deletion_scheduled_at = $1 WHERE id = $2`,
		clk.Now().Add(-1*time.Hour), userID)

	cleanupSvc := NewCleanupService(db, clk, time.Hour)
	cleanupSvc.RunOnce(ctx)

	var dbStatus, email string
	db.QueryRowContext(ctx, `SELECT status, email FROM users WHERE id = $1`, userID).Scan(&dbStatus, &email)
	if dbStatus != "deleted" {
		t.Fatalf("status = %q, want deleted", dbStatus)
	}
	if email == "e2e5@test.com" {
		t.Error("email should be scrubbed")
	}

	arID, _ := store.CreateTestAuthRequest(ctx, "e2e5-reregister")
	result := loginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (new signup after deletion)", result.Action)
	}
	if result.SessionID == "" {
		t.Error("new session should be created for re-registered user")
	}
}

// account-004: pending_deletion + Device/MCP → account_inactive
func TestAccount004_PendingDeletion_DeviceRejected(t *testing.T) {
	_, deviceSvc, _, store, _, _ := setupGapTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "pd-device@test.com", true, "Test", "", "google", "gap-sub", "pd@test.com")
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	result := deviceSvc.HandleDeviceCallback(ctx, "fake-code", "PD-CODE", "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (pending_deletion on device)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// account-004b: pending_deletion + MCP login → account_inactive
func TestAccount004b_PendingDeletion_MCPRejected(t *testing.T) {
	loginSvc, _, _, store, _, _ := setupGapTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "pd-mcp@test.com", true, "Test", "", "google", "gap-sub", "pdm@test.com")
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	arID, _ := store.CreateTestAuthRequest(ctx, "pd-mcp")
	result := loginSvc.HandleMCPCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error (pending_deletion via MCP)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}
