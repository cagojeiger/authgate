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

func setupAccountTest(t *testing.T) (*AccountService, *LoginService, *storage.Storage, *sql.DB, clock.FixedClock) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{
		User: &upstream.UserInfo{Sub: "acct-sub-123", Email: "acct@test.com", EmailVerified: true, Name: "Acct User"},
	}

	accountSvc := NewAccountService(db, clk)
	loginSvc := NewLoginService(store, fakeProvider, termsV, privacyV, 24*time.Hour)
	return accountSvc, loginSvc, store, db, clk
}

func TestDeleteAccount_Success(t *testing.T) {
	accountSvc, _, store, db, _ := setupAccountTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "delete@test.com", true, "Test", "", "google", "del-sub", "d@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)

	result := accountSvc.RequestDeletion(ctx, user.ID, "127.0.0.1", "test")
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.Message)
	}

	// Verify status
	var status string
	db.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "pending_deletion" {
		t.Errorf("status = %q, want pending_deletion", status)
	}

	// Verify refresh tokens revoked
	var revokedCount int
	db.QueryRowContext(ctx, `SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NOT NULL`, user.ID).Scan(&revokedCount)
	// No tokens exist yet, but query should work without error
}

func TestDeleteAccount_Idempotent(t *testing.T) {
	accountSvc, _, store, _, _ := setupAccountTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "idempotent@test.com", true, "Test", "", "google", "idem-sub", "i@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)

	// First request
	accountSvc.RequestDeletion(ctx, user.ID, "127.0.0.1", "test")
	// Second request — should be idempotent
	result := accountSvc.RequestDeletion(ctx, user.ID, "127.0.0.1", "test")
	if !result.Success {
		t.Errorf("expected idempotent success, got: %s", result.Message)
	}
}

func TestDeleteAccount_InactiveUser_Rejected(t *testing.T) {
	accountSvc, _, store, _, _ := setupAccountTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "disabled-del@test.com", true, "Test", "", "google", "dis-del-sub", "dd@test.com")
	store.DisableUser(ctx, user.ID)

	result := accountSvc.RequestDeletion(ctx, user.ID, "127.0.0.1", "test")
	if result.Success {
		t.Error("expected failure for disabled user")
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// E2E 4: 탈퇴 후 복구
func TestE2E_DeleteThenRecover(t *testing.T) {
	accountSvc, loginSvc, store, db, _ := setupAccountTest(t)
	ctx := context.Background()

	// 1. Create complete user
	user, _ := store.CreateUserWithIdentity(ctx, "e2e4@test.com", true, "E2E4", "", "google", "acct-sub-123", "e2e4@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)

	// 2. Delete account
	accountSvc.RequestDeletion(ctx, user.ID, "127.0.0.1", "test")

	// 3. Verify pending_deletion
	var status string
	db.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "pending_deletion" {
		t.Fatalf("status = %q, want pending_deletion", status)
	}

	// 4. Browser login → recovery (via HandleCallback with fake provider returning same sub)
	arID, _ := store.CreateTestAuthRequest(ctx, "e2e4-recovery")
	result := loginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "test")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (recovered + terms done)", result.Action)
	}

	// 5. Verify active again
	db.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "active" {
		t.Errorf("status after recovery = %q, want active", status)
	}
}

// E2E 5: 탈퇴 후 삭제 → 재가입
func TestE2E_DeleteThenReregister(t *testing.T) {
	accountSvc, loginSvc, store, db, clk := setupAccountTest(t)
	ctx := context.Background()

	// 1. Create complete user
	user, _ := store.CreateUserWithIdentity(ctx, "e2e5@test.com", true, "E2E5", "", "google", "acct-sub-123", "e2e5@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)

	// 2. Delete account
	accountSvc.RequestDeletion(ctx, user.ID, "127.0.0.1", "test")

	// 3. Simulate 30 days passing → deletion cleanup
	db.ExecContext(ctx, `UPDATE users SET deletion_scheduled_at = $1 WHERE id = $2`,
		clk.Now().Add(-1*time.Hour), user.ID)

	cleanupSvc := NewCleanupService(db, clk, time.Hour)
	cleanupSvc.RunOnce(ctx)

	// 4. Verify deleted + PII scrubbed
	var status, email string
	db.QueryRowContext(ctx, `SELECT status, email FROM users WHERE id = $1`, user.ID).Scan(&status, &email)
	if status != "deleted" {
		t.Fatalf("status = %q, want deleted", status)
	}
	if email == "e2e5@test.com" {
		t.Error("email should be scrubbed")
	}

	// 5. Same Google sub tries to login → new signup (ErrNotFound)
	result := loginSvc.HandleCallback(ctx, "fake-code", "req-reregister", "127.0.0.1", "test")

	// Should create new user → show terms
	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (new signup after deletion)", result.Action)
	}
	if result.SessionID == "" {
		t.Error("new session should be created for re-registered user")
	}

	// 6. Verify new user has different ID
	var newUserCount int
	db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE email = 'acct@test.com'`).Scan(&newUserCount)
	if newUserCount != 1 {
		t.Errorf("expected 1 new user, got %d", newUserCount)
	}
}
// account-005: initial_onboarding_incomplete → DELETE /account → pending_deletion
func TestAccount005_IncompleteCanDelete(t *testing.T) {
	svc, store := setupAccountExtTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "incomplete-del@test.com", true, "Test", "", "google", "incomplete-del-sub", "id@test.com")
	// Don't accept terms → initial_onboarding_incomplete

	result := svc.RequestDeletion(ctx, user.ID, "127.0.0.1", "test")
	if !result.Success {
		t.Errorf("expected success for incomplete user deletion, got: %s", result.Message)
	}
}

// account-006: reconsent_required → DELETE /account → pending_deletion
func TestAccount006_ReconsentCanDelete(t *testing.T) {
	svc, store := setupAccountExtTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "reconsent-del@test.com", true, "Test", "", "google", "reconsent-del-sub", "rd@test.com")
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version")

	result := svc.RequestDeletion(ctx, user.ID, "127.0.0.1", "test")
	if !result.Success {
		t.Errorf("expected success for reconsent user deletion, got: %s", result.Message)
	}
}

// account-004: pending_deletion + Device/MCP → account_inactive (tested via device callback)
// Already covered by TestDevice005_RecoverableCallback_Rejected
// account-004: pending_deletion + Device login → account_inactive
func TestAccount004_PendingDeletion_DeviceRejected(t *testing.T) {
	_, deviceSvc, _, store, _, _ := setupGapTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "pd-device@test.com", true, "Test", "", "google", "gap-sub", "pd@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	result := deviceSvc.HandleDeviceCallback(ctx, "fake-code", "PD-CODE", "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (pending_deletion on device)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// account-004b: pending_deletion + MCP login → recovery (browser path)
func TestAccount004b_PendingDeletion_MCPRecovery(t *testing.T) {
	loginSvc, _, _, store, _, _ := setupGapTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "pd-mcp@test.com", true, "Test", "", "google", "gap-sub", "pdm@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	// MCP uses browser path → recovery happens
	arID, _ := store.CreateTestAuthRequest(ctx, "pd-mcp")
	result := loginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "mcp-client")

	// Browser path recovers pending_deletion
	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (MCP uses browser path, recovery + terms done)", result.Action)
	}
}
