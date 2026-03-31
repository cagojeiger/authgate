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

func setupLoginService(t *testing.T) (*LoginService, *storage.Storage) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{
			Sub:           "google-sub-123",
			Email:         "test@example.com",
			EmailVerified: true,
			Name:          "Test User",
			Picture:       "https://example.com/photo.jpg",
		},
	}

	svc := NewLoginService(store, fakeProvider, fakeProvider, 24*time.Hour)
	return svc, store
}

func TestHandleLogin_NoSession_RedirectsToIdP(t *testing.T) {
	svc, _ := setupLoginService(t)

	result := svc.HandleLogin(context.Background(), "req-123", "", "127.0.0.1", "test")

	if result.Action != ActionRedirectToIdP {
		t.Errorf("action = %v, want RedirectToIdP", result.Action)
	}
	if result.RedirectURL == "" {
		t.Error("redirect URL should not be empty")
	}
}

func TestHandleLogin_MissingAuthRequestID_Error(t *testing.T) {
	svc, _ := setupLoginService(t)

	result := svc.HandleLogin(context.Background(), "", "", "", "")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error", result.Action)
	}
}

func TestHandleCallback_NewUser_Signup_AutoApprove(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	arID, err := store.CreateTestAuthRequest(ctx, "new-user")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test-agent")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (new user is immediately active)", result.Action)
	}
	if result.SessionID == "" {
		t.Error("session should be created")
	}
	if result.AuthRequestID != arID {
		t.Errorf("authRequestID = %q, want %q", result.AuthRequestID, arID)
	}
}

func TestHandleCallback_ExistingUser_AutoApprove(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	// Pre-create user
	_, err := store.CreateUserWithIdentity(ctx, "existing@example.com", true, "Existing", "", "google", "google-sub-123", "existing@example.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create auth request for CompleteAuthRequest to succeed
	arID, err := store.CreateTestAuthRequest(ctx, "existing")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test-agent")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove", result.Action)
	}
	if result.SessionID == "" {
		t.Error("session should be created")
	}
}

func TestHandleCallback_PendingDeletion_RecoveryAutoApprove(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	// Create user, then set to pending_deletion
	user, err := store.CreateUserWithIdentity(ctx, "pending@example.com", true, "Pending", "", "google", "google-sub-123", "pending@example.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	arID, err := store.CreateTestAuthRequest(ctx, "pending-recovery")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test-agent")

	// Should recover and auto-approve
	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (recovered)", result.Action)
	}
	if result.SessionID == "" {
		t.Error("session should be created after recovery")
	}
}

func TestHandleCallback_InactiveUser_Error(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	// Create disabled user
	user, _ := store.CreateUserWithIdentity(ctx, "disabled@example.com", true, "Disabled", "", "google", "google-sub-123", "disabled@example.com")
	store.DisableUser(ctx, user.ID)

	result := svc.HandleCallback(ctx, "fake-code", "req-disabled", "127.0.0.1", "test-agent")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// browser-007 / E2E 6: 복구 후 auth_request 완료 실패 → 재시도 멱등성
func TestBrowser007_RecoveryRetryIdempotent(t *testing.T) {
	loginSvc, _, _, store, _, _ := setupGapTest(t)
	ctx := context.Background()

	// Create user, then set to pending_deletion
	user, _ := store.CreateUserWithIdentity(ctx, "retry@test.com", true, "Test", "", "google", "gap-sub", "r@test.com")
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	// First attempt: recovery succeeds, but use an invalid authRequestID so CompleteAuthRequest fails
	result1 := loginSvc.HandleCallback(ctx, "fake-code", "invalid-ar-id", "127.0.0.1", "browser")
	// Recovery happened (user is now active), but auth_request completion may fail
	// The important thing: user is recovered

	// Verify user is active (recovery persisted even if auth_request failed)
	var status string
	store.DB().QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "active" {
		t.Fatalf("user should be active after recovery, got %q", status)
	}

	// Second attempt: retry login → should succeed normally (idempotent)
	arID, _ := store.CreateTestAuthRequest(ctx, "retry")
	result2 := loginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "browser")
	if result2.Action != ActionAutoApprove {
		t.Errorf("retry action = %v, want AutoApprove (recovery already done)", result2.Action)
	}

	_ = result1 // first result may be error, that's OK
}
