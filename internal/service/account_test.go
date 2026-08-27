//go:build integration

package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type accountFixture struct {
	LoginSvc *LoginService
	Store    *storage.Storage
	DB       *sql.DB
	Clock    *clock.FixedClock
	FakeUser *upstream.UserInfo
}

func setupAccountTest(t *testing.T) *accountFixture {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := newTestStore(t, db, clk, gen, noopChecker)

	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: "acct-sub-123", Email: "acct@test.com", EmailVerified: true, Name: "Acct User"},
	}

	loginSvc := NewLoginService(store, fakeProvider.Name(), 24*time.Hour, nil)
	return &accountFixture{
		LoginSvc: loginSvc,
		Store:    store,
		DB:       db,
		Clock:    clk,
		FakeUser: fakeProvider.User,
	}
}

// Helper: create user + session, return sessionID for deletion tests
func createUserWithSession(t *testing.T, store *storage.Storage, email, sub string) (string, string) {
	t.Helper()
	ctx := context.Background()
	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: email, EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: sub})
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

	userID, _ := createUserWithSession(t, fx.Store, "delete@test.com", "del-sub")

	if _, err := fx.Store.RequestDeletion(ctx, userID); err != nil {
		t.Fatalf("expected success, got: %v", err)
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

	userID, _ := createUserWithSession(t, fx.Store, "idempotent@test.com", "idem-sub")

	if _, err := fx.Store.RequestDeletion(ctx, userID); err != nil {
		t.Fatalf("first request: %v", err)
	}

	// 이미 pending_deletion 인 계정에 대한 재요청은 성공으로 수렴한다.
	if _, err := fx.Store.RequestDeletion(ctx, userID); err != nil {
		t.Errorf("expected idempotent success, got: %v", err)
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

			userID, _ := createUserWithSession(t, fx.Store, tt.name+"-del@test.com", tt.name+"-del-sub")
			_ = fx.Store.SetUserStatus(ctx, userID, tt.status)

			liveStatus, err := fx.Store.RequestDeletion(ctx, userID)
			if !errors.Is(err, storage.ErrUserAccountClosed) {
				t.Fatalf("err = %v, want ErrUserAccountClosed for %s user", err, tt.status)
			}
			if liveStatus != tt.status {
				t.Fatalf("liveStatus = %q, want %q", liveStatus, tt.status)
			}
		})
	}
}

// E2E 4: 탈퇴 후 복구
func TestE2E_DeleteThenRecover(t *testing.T) {
	fx := setupAccountTest(t)
	ctx := context.Background()

	userID, _ := createUserWithSession(t, fx.Store, "e2e4@test.com", "acct-sub-123")

	if _, err := fx.Store.RequestDeletion(ctx, userID); err != nil {
		t.Fatalf("request deletion: %v", err)
	}

	var status string
	fx.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, userID).Scan(&status)
	if status != "pending_deletion" {
		t.Fatalf("status = %q, want pending_deletion", status)
	}

	arID, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e4-recovery")
	result := fx.LoginSvc.CompleteBrowserLogin(ctx, arID, fx.FakeUser, "127.0.0.1", "test")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (recovered)", result.Action)
	}

	fx.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, userID).Scan(&status)
	if status != "active" {
		t.Errorf("status after recovery = %q, want active", status)
	}
}

// E2E 5: 탈퇴 후 삭제 → 재가입
func TestE2E_DeleteThenReregister(t *testing.T) {
	fx := setupAccountTest(t)
	ctx := context.Background()

	userID, _ := createUserWithSession(t, fx.Store, "e2e5@test.com", "acct-sub-123")

	if _, err := fx.Store.RequestDeletion(ctx, userID); err != nil {
		t.Fatalf("request deletion: %v", err)
	}

	fx.DB.ExecContext(ctx, `UPDATE users SET deletion_scheduled_at = $1 WHERE id = $2`,
		fx.Clock.Now().Add(-1*time.Hour), userID)

	cleanupSvc := NewCleanupService(storage.NewCleanupRunner(fx.DB), fx.Clock, time.Hour)
	cleanupSvc.RunOnce(ctx)

	var dbStatus string
	var emailCipher []byte
	fx.DB.QueryRowContext(ctx, `SELECT status, email_ciphertext FROM users WHERE id = $1`, userID).Scan(&dbStatus, &emailCipher)
	if dbStatus != "deleted" {
		t.Fatalf("status = %q, want deleted", dbStatus)
	}
	if emailCipher != nil {
		t.Error("email ciphertext should be scrubbed (NULL) after deletion")
	}

	arID, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e5-reregister")
	result := fx.LoginSvc.CompleteBrowserLogin(ctx, arID, fx.FakeUser, "127.0.0.1", "test")

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

	user, _ := fx.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "pd-device@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "gap-sub"})
	fx.Store.SetUserStatus(ctx, user.ID, "pending_deletion")
	insertDeviceCode(t, fx.Store, "PD-CODE", fx.Clock)

	result := fx.DeviceSvc.CompleteDeviceLogin(ctx, "PD-CODE", fx.FakeUser, "127.0.0.1", "test")
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

	user, _ := fx.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "pd-mcp@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "gap-sub"})
	fx.Store.SetUserStatus(ctx, user.ID, "pending_deletion")

	arID, _ := fx.Store.CreateTestAuthRequestWithResource(ctx, "pd-mcp", "http://localhost/mcp")
	result := fx.MCPLoginSvc.CompleteMCPLogin(ctx, arID, fx.FakeUser, "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error (pending_deletion via MCP)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}
