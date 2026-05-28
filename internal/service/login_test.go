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

func setupLoginService(t *testing.T) (*LoginService, *storage.Storage, *upstream.UserInfo) {
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
		},
	}

	svc := NewLoginService(store, fakeProvider.Name(), 24*time.Hour)
	return svc, store, fakeProvider.User
}

func TestHandleLogin_NoSession_RedirectsToIdP(t *testing.T) {
	svc, _, _ := setupLoginService(t)

	result := svc.HandleLogin(context.Background(), "req-123", "", "127.0.0.1", "test")

	if result.Action != ActionRedirectToIdP {
		t.Errorf("action = %v, want RedirectToIdP", result.Action)
	}
	// The redirect now carries the authRequestID as the state value; the handler
	// builds the actual IdP URL via provider.Redirect (high-level AuthURLHandler).
	if result.AuthRequestID != "req-123" {
		t.Errorf("authRequestID = %q, want req-123", result.AuthRequestID)
	}
}

func TestHandleLogin_MissingAuthRequestID_Error(t *testing.T) {
	svc, _, _ := setupLoginService(t)

	result := svc.HandleLogin(context.Background(), "", "", "", "")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error", result.Action)
	}
}

func TestHandleCallback_NewUser_Signup_AutoApprove(t *testing.T) {
	svc, store, fakeUser := setupLoginService(t)
	ctx := context.Background()

	arID, err := store.CreateTestAuthRequest(ctx, "new-user")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.CompleteBrowserLogin(ctx, arID, fakeUser, "127.0.0.1", "test-agent")

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
	svc, store, fakeUser := setupLoginService(t)
	ctx := context.Background()

	// Pre-create user
	_, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "existing@example.com", EmailVerified: true, Name: "Existing", Provider: "google", ProviderUserID: "google-sub-123", ProviderEmail: "existing@example.com"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create auth request for CompleteAuthRequest to succeed
	arID, err := store.CreateTestAuthRequest(ctx, "existing")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.CompleteBrowserLogin(ctx, arID, fakeUser, "127.0.0.1", "test-agent")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove", result.Action)
	}
	if result.SessionID == "" {
		t.Error("session should be created")
	}
}

func TestHandleCallback_PendingDeletion_RecoveryAutoApprove(t *testing.T) {
	svc, store, fakeUser := setupLoginService(t)
	ctx := context.Background()

	// Create user, then set to pending_deletion
	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "pending@example.com", EmailVerified: true, Name: "Pending", Provider: "google", ProviderUserID: "google-sub-123", ProviderEmail: "pending@example.com"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	arID, err := store.CreateTestAuthRequest(ctx, "pending-recovery")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.CompleteBrowserLogin(ctx, arID, fakeUser, "127.0.0.1", "test-agent")

	// Should recover and auto-approve
	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (recovered)", result.Action)
	}
	if result.SessionID == "" {
		t.Error("session should be created after recovery")
	}
}

func TestHandleCallback_InactiveUser_Error(t *testing.T) {
	svc, store, fakeUser := setupLoginService(t)
	ctx := context.Background()

	// Create disabled user
	user, _ := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "disabled@example.com", EmailVerified: true, Name: "Disabled", Provider: "google", ProviderUserID: "google-sub-123", ProviderEmail: "disabled@example.com"})
	store.DisableUser(ctx, user.ID)
	arID, err := store.CreateTestAuthRequest(ctx, "req-disabled")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.CompleteBrowserLogin(ctx, arID, fakeUser, "127.0.0.1", "test-agent")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// browser-007 / E2E 6: 복구가 유효한 auth_request 콜백에서 멱등적으로 동작해야 한다.
//
// #162 이전에는 잘못된 authRequestID로도 복구가 선행되었다 (Exchange가 먼저
// 호출됐으므로). 그 동작은 outbound IdP 트래픽 amplification 표면이라
// 제거되었다. 새 동작: 잘못된 authRequestID 콜백은 Exchange 전에 거부되며
// 복구도 일어나지 않는다. 유효한 authRequestID 콜백에서만 복구가 일어나고,
// 두 번 이상 호출돼도 멱등이다.
func TestBrowser007_RecoveryRetryIdempotent(t *testing.T) {
	fx := setupGapTest(t)
	ctx := context.Background()

	// Create user, then set to pending_deletion
	user, _ := fx.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "retry@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "gap-sub", ProviderEmail: "r@test.com"})
	fx.Store.SetUserStatus(ctx, user.ID, "pending_deletion")

	// First attempt: callback with bogus authRequestID is rejected before
	// Exchange. Recovery does NOT happen.
	result1 := fx.LoginSvc.CompleteBrowserLogin(ctx, "invalid-ar-id", fx.FakeUser, "127.0.0.1", "browser")
	if result1.Action != ActionError {
		t.Fatalf("invalid authRequestID should be rejected, got %v", result1.Action)
	}
	var status string
	fx.Store.DB().QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "pending_deletion" {
		t.Fatalf("user must remain pending_deletion when auth_request invalid, got %q", status)
	}

	// Second attempt: valid authRequestID — recovery + completion in one shot.
	arID, _ := fx.Store.CreateTestAuthRequest(ctx, "retry")
	result2 := fx.LoginSvc.CompleteBrowserLogin(ctx, arID, fx.FakeUser, "127.0.0.1", "browser")
	if result2.Action != ActionAutoApprove {
		t.Errorf("retry action = %v, want AutoApprove", result2.Action)
	}
	fx.Store.DB().QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "active" {
		t.Fatalf("after valid callback, user should be active, got %q", status)
	}

	// Third attempt: idempotent retry on a fresh authRequestID also succeeds.
	arID2, _ := fx.Store.CreateTestAuthRequest(ctx, "retry-2")
	result3 := fx.LoginSvc.CompleteBrowserLogin(ctx, arID2, fx.FakeUser, "127.0.0.1", "browser")
	if result3.Action != ActionAutoApprove {
		t.Errorf("idempotent retry action = %v, want AutoApprove", result3.Action)
	}
}
