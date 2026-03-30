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

const (
	termsV   = "2026-03-28"
	privacyV = "2026-03-28"
)

func setupLoginService(t *testing.T) (*LoginService, *storage.Storage) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{
		User: &upstream.UserInfo{
			Sub:           "google-sub-123",
			Email:         "test@example.com",
			EmailVerified: true,
			Name:          "Test User",
			Picture:       "https://example.com/photo.jpg",
		},
	}

	svc := NewLoginService(store, fakeProvider, termsV, privacyV, 24*time.Hour)
	return svc, store
}

func TestHandleLogin_NoSession_RedirectsToIdP(t *testing.T) {
	svc, _ := setupLoginService(t)

	result := svc.HandleLogin(context.Background(), "req-123", "")

	if result.Action != ActionRedirectToIdP {
		t.Errorf("action = %v, want RedirectToIdP", result.Action)
	}
	if result.RedirectURL == "" {
		t.Error("redirect URL should not be empty")
	}
}

func TestHandleLogin_MissingAuthRequestID_Error(t *testing.T) {
	svc, _ := setupLoginService(t)

	result := svc.HandleLogin(context.Background(), "", "")

	if result.Action != ActionError {
		t.Errorf("action = %v, want Error", result.Action)
	}
}

func TestHandleCallback_NewUser_Signup_ShowTerms(t *testing.T) {
	svc, _ := setupLoginService(t)
	ctx := context.Background()

	result := svc.HandleCallback(ctx, "fake-code", "req-123", "127.0.0.1", "test-agent")

	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (new user needs terms)", result.Action)
	}
	if result.SessionID == "" {
		t.Error("session should be created")
	}
	if result.AuthRequestID != "req-123" {
		t.Errorf("authRequestID = %q, want req-123", result.AuthRequestID)
	}
}

func TestHandleCallback_ExistingUser_AutoApprove(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	// Pre-create user with terms accepted
	user, err := store.CreateUserWithIdentity(ctx, "existing@example.com", true, "Existing", "", "google", "google-sub-123", "existing@example.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)

	// Create auth request for CompleteAuthRequest to succeed
	arID, err := store.CreateTestAuthRequest(ctx, "existing")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test-agent")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (existing user with terms)", result.Action)
	}
	if result.SessionID == "" {
		t.Error("session should be created")
	}
}

func TestHandleTermsSubmit_Success(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	// Simulate: new user just completed callback, has session, needs terms
	user, err := store.CreateUserWithIdentity(ctx, "terms-submit@example.com", true, "Terms User", "", "google", "terms-sub-456", "terms@example.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, err := store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Create auth request
	arID, err := store.CreateTestAuthRequest(ctx, "terms")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.HandleTermsSubmit(ctx, arID, sessionID, true, true, true, "127.0.0.1", "test-agent")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove", result.Action)
	}
}

func TestHandleTermsSubmit_MissingCheckbox_ShowTermsAgain(t *testing.T) {
	svc, _ := setupLoginService(t)
	ctx := context.Background()

	result := svc.HandleTermsSubmit(ctx, "req-123", "session-123", false, true, true, "", "")

	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (checkbox missing)", result.Action)
	}
	if result.Error == "" {
		t.Error("should have error message")
	}
}

func TestHandleCallback_PendingDeletion_RecoveryAndTerms(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	// Create user with terms accepted, then set to pending_deletion
	user, err := store.CreateUserWithIdentity(ctx, "pending@example.com", true, "Pending", "", "google", "google-sub-123", "pending@example.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	// Don't accept terms — user should need terms after recovery
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	result := svc.HandleCallback(ctx, "fake-code", "req-pending", "127.0.0.1", "test-agent")

	// Should recover and then show terms (not infinite loop, not auto-approve)
	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (recovered but needs terms)", result.Action)
	}
	if result.SessionID == "" {
		t.Error("session should be created after recovery")
	}
}

func TestHandleCallback_PendingDeletion_RecoveryWithTerms_AutoApprove(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	// Create user with terms accepted, then set to pending_deletion
	user, err := store.CreateUserWithIdentity(ctx, "pending-ok@example.com", true, "PendingOK", "", "google", "google-sub-123", "pending-ok@example.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	arID, err := store.CreateTestAuthRequest(ctx, "pending-recovery")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test-agent")

	// Should recover and auto-approve (terms already accepted)
	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (recovered with terms done)", result.Action)
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
// browser-004: reconsent_required → terms 재동의 표시
func TestBrowser004_ReconsentRequired_ShowTerms(t *testing.T) {
	svc, store := setupBrowserExtTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "reconsent@test.com", true, "Test", "", "google", "browser-ext-sub", "r@test.com")
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version") // wrong version

	result := svc.HandleCallback(ctx, "fake-code", "req-reconsent", "127.0.0.1", "test")
	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (reconsent_required)", result.Action)
	}
}

// browser-terms-002: reconsent 재동의 완료 → onboarding_complete
func TestBrowserTerms002_ReconsentComplete(t *testing.T) {
	svc, store := setupBrowserExtTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "reconsent-done@test.com", true, "Test", "", "google", "reconsent-done-sub", "rd@test.com")
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version")
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	arID, _ := store.CreateTestAuthRequest(ctx, "reconsent-done")

	result := svc.HandleTermsSubmit(ctx, arID, sessionID, true, true, true, "127.0.0.1", "test")
	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (reconsent done)", result.Action)
	}
}

// browser-terms-004: age_confirm만 미선택 → 200 + 재표시
func TestBrowserTerms004_AgeConfirmMissing(t *testing.T) {
	svc, _ := setupBrowserExtTest(t)
	ctx := context.Background()

	result := svc.HandleTermsSubmit(ctx, "req-age", "session-age", true, true, false, "", "")
	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (age_confirm missing)", result.Action)
	}
}

// browser-terms: privacy만 미선택 → 200 + 재표시
func TestBrowserTerms_PrivacyMissing(t *testing.T) {
	svc, _ := setupBrowserExtTest(t)
	ctx := context.Background()

	result := svc.HandleTermsSubmit(ctx, "req-priv", "session-priv", true, false, true, "", "")
	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (privacy missing)", result.Action)
	}
}
// browser-007 / E2E 6: 복구 후 auth_request 완료 실패 → 재시도 멱등성
func TestBrowser007_RecoveryRetryIdempotent(t *testing.T) {
	loginSvc, _, _, store, _, _ := setupGapTest(t)
	ctx := context.Background()

	// Create complete user, then set to pending_deletion
	user, _ := store.CreateUserWithIdentity(ctx, "retry@test.com", true, "Test", "", "google", "gap-sub", "r@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
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
		t.Errorf("retry action = %v, want AutoApprove (recovery already done, terms accepted)", result2.Action)
	}

	_ = result1 // first result may be error, that's OK
}
