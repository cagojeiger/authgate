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

type accountFixture struct {
	AccountSvc *AccountService
	LoginSvc   *LoginService
	Store      *storage.Storage
	DB         *sql.DB
	Clock      *clock.FixedClock
}

func setupAccountTest(t *testing.T) *accountFixture {
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
	loginSvc := NewLoginService(store, fakeProvider, 24*time.Hour)
	return &accountFixture{
		AccountSvc: accountSvc,
		LoginSvc:   loginSvc,
		Store:      store,
		DB:         db,
		Clock:      clk,
	}
}

// Helper: create user + session, return sessionID for deletion tests
func createUserWithSession(t *testing.T, store *storage.Storage, email, sub string) (string, string) {
	t.Helper()
	ctx := context.Background()
	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: email, EmailVerified: true, Name: "Test", AvatarURL: "", Provider: "google", ProviderUserID: sub, ProviderEmail: email})
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
	fx := setupAccountTest(t)
	ctx := context.Background()

	userID, sessionID := createUserWithSession(t, fx.Store, "delete@test.com", "del-sub")

	result := fx.AccountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}

	var status string
	fx.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, userID).Scan(&status)
	if status != "pending_deletion" {
		t.Errorf("status = %q, want pending_deletion", status)
	}
}

func TestDeleteAccount_Idempotent(t *testing.T) {
	fx := setupAccountTest(t)
	ctx := context.Background()

	_, sessionID := createUserWithSession(t, fx.Store, "idempotent@test.com", "idem-sub")

	fx.AccountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
	result := fx.AccountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
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
			fx := setupAccountTest(t)
			ctx := context.Background()

			_, sessionID := createUserWithSession(t, fx.Store, tt.name+"-del@test.com", tt.name+"-del-sub")
			user, _ := fx.Store.GetValidSession(ctx, sessionID)
			_ = fx.Store.SetUserStatus(ctx, user.ID, tt.status)

			result := fx.AccountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
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
	fx := setupAccountTest(t)
	ctx := context.Background()

	result := fx.AccountSvc.RequestDeletion(ctx, "", "127.0.0.1", "test")
	if result.Success {
		t.Error("expected failure without session")
	}
	if result.ErrorCode != 401 {
		t.Errorf("errorCode = %d, want 401", result.ErrorCode)
	}
}

// E2E 4: 탈퇴 후 복구
func TestE2E_DeleteThenRecover(t *testing.T) {
	fx := setupAccountTest(t)
	ctx := context.Background()

	_, sessionID := createUserWithSession(t, fx.Store, "e2e4@test.com", "acct-sub-123")
	user, _ := fx.Store.GetValidSession(ctx, sessionID)

	fx.AccountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")

	var status string
	fx.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "pending_deletion" {
		t.Fatalf("status = %q, want pending_deletion", status)
	}

	arID, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e4-recovery")
	result := fx.LoginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (recovered)", result.Action)
	}

	fx.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "active" {
		t.Errorf("status after recovery = %q, want active", status)
	}
}

// E2E 5: 탈퇴 후 삭제 → 재가입
func TestE2E_DeleteThenReregister(t *testing.T) {
	fx := setupAccountTest(t)
	ctx := context.Background()

	userID, sessionID := createUserWithSession(t, fx.Store, "e2e5@test.com", "acct-sub-123")

	fx.AccountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")

	fx.DB.ExecContext(ctx, `UPDATE users SET deletion_scheduled_at = $1 WHERE id = $2`,
		fx.Clock.Now().Add(-1*time.Hour), userID)

	cleanupSvc := NewCleanupService(storage.NewCleanupRunner(fx.DB), fx.Clock, time.Hour)
	cleanupSvc.RunOnce(ctx)

	var dbStatus, email string
	fx.DB.QueryRowContext(ctx, `SELECT status, email FROM users WHERE id = $1`, userID).Scan(&dbStatus, &email)
	if dbStatus != "deleted" {
		t.Fatalf("status = %q, want deleted", dbStatus)
	}
	if email == "e2e5@test.com" {
		t.Error("email should be scrubbed")
	}

	arID, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e5-reregister")
	result := fx.LoginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (new signup after deletion)", result.Action)
	}
	if result.SessionID == "" {
		t.Error("new session should be created for re-registered user")
	}
}

// account-004: pending_deletion + Device/MCP → account_inactive
func TestAccount004_PendingDeletion_DeviceRejected(t *testing.T) {
	fx := setupGapTest(t)
	ctx := context.Background()

	user, _ := fx.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "pd-device@test.com", EmailVerified: true, Name: "Test", AvatarURL: "", Provider: "google", ProviderUserID: "gap-sub", ProviderEmail: "pd@test.com"})
	fx.Store.SetUserStatus(ctx, user.ID, "pending_deletion")

	result := fx.DeviceSvc.HandleDeviceCallback(ctx, "fake-code", "PD-CODE", "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (pending_deletion on device)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// account-004b: pending_deletion + MCP login → account_inactive
func TestAccount004b_PendingDeletion_MCPRejected(t *testing.T) {
	fx := setupGapTest(t)
	ctx := context.Background()

	user, _ := fx.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "pd-mcp@test.com", EmailVerified: true, Name: "Test", AvatarURL: "", Provider: "google", ProviderUserID: "gap-sub", ProviderEmail: "pdm@test.com"})
	fx.Store.SetUserStatus(ctx, user.ID, "pending_deletion")

	arID, _ := fx.Store.CreateTestAuthRequestWithResource(ctx, "pd-mcp", "http://localhost/mcp")
	result := fx.MCPLoginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error (pending_deletion via MCP)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}
