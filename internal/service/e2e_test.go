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

func setupE2ETest(t *testing.T) (*LoginService, *DeviceService, *AccountService, *storage.Storage, *sql.DB, clock.FixedClock) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{
		User: &upstream.UserInfo{Sub: "e2e-sub", Email: "e2e@test.com", EmailVerified: true, Name: "E2E User"},
	}

	loginSvc := NewLoginService(store, fakeProvider, termsV, privacyV, 24*time.Hour)
	deviceSvc := NewDeviceService(store, fakeProvider, termsV, privacyV, "http://localhost:8080", 24*time.Hour)
	accountSvc := NewAccountService(db, clk)
	return loginSvc, deviceSvc, accountSvc, store, db, clk
}

// E2E 1: 최초 가입 → 정상 사용 → Device/MCP 후속 채널
func TestE2E1_SignupToAllChannels(t *testing.T) {
	loginSvc, deviceSvc, _, store, _, _ := setupE2ETest(t)
	ctx := context.Background()

	// 1. Browser signup → show terms
	result := loginSvc.HandleCallback(ctx, "fake-code", "req-e2e1", "127.0.0.1", "browser")
	if result.Action != ActionShowTerms {
		t.Fatalf("step 1: action = %v, want ShowTerms", result.Action)
	}

	// 2. Accept terms
	arID, _ := store.CreateTestAuthRequest(ctx, "e2e1-terms")
	termsResult := loginSvc.HandleTermsSubmit(ctx, arID, result.SessionID, true, true, true, "127.0.0.1", "browser")
	if termsResult.Action != ActionAutoApprove {
		t.Fatalf("step 2: action = %v, want AutoApprove", termsResult.Action)
	}

	// 3. Browser re-login → auto-approve
	arID2, _ := store.CreateTestAuthRequest(ctx, "e2e1-relogin")
	relogin := loginSvc.HandleCallback(ctx, "fake-code", arID2, "127.0.0.1", "browser")
	if relogin.Action != ActionAutoApprove {
		t.Fatalf("step 3: action = %v, want AutoApprove", relogin.Action)
	}

	// 4. Device callback → should succeed (redirect back)
	store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e1", "E2E1-CODE", time.Now().Add(5*time.Minute), []string{"openid"})
	devResult := deviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E1-CODE", "127.0.0.1", "cli")
	if devResult.Action != DeviceRedirectBack {
		t.Fatalf("step 4: device action = %v, want RedirectBack", devResult.Action)
	}

	// 5. MCP (same as browser path) → auto-approve
	arID3, _ := store.CreateTestAuthRequest(ctx, "e2e1-mcp")
	mcpResult := loginSvc.HandleCallback(ctx, "fake-code", arID3, "127.0.0.1", "mcp-client")
	if mcpResult.Action != ActionAutoApprove {
		t.Fatalf("step 5: mcp action = %v, want AutoApprove", mcpResult.Action)
	}
}

// E2E 2: 가입 중 이탈 후 복귀
func TestE2E2_AbandonAndReturn(t *testing.T) {
	loginSvc, deviceSvc, _, store, _, _ := setupE2ETest(t)
	ctx := context.Background()

	// 1. Browser signup → show terms
	result := loginSvc.HandleCallback(ctx, "fake-code", "req-e2e2", "127.0.0.1", "browser")
	if result.Action != ActionShowTerms {
		t.Fatalf("step 1: action = %v, want ShowTerms", result.Action)
	}

	// 2. User abandons (no terms submit)

	// 3. Browser re-login → show terms again
	result2 := loginSvc.HandleCallback(ctx, "fake-code", "req-e2e2-retry", "127.0.0.1", "browser")
	if result2.Action != ActionShowTerms {
		t.Fatalf("step 3: action = %v, want ShowTerms (still incomplete)", result2.Action)
	}

	// 4. Device callback → signup_required
	store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e2", "E2E2-CODE", time.Now().Add(5*time.Minute), []string{"openid"})
	devResult := deviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E2-CODE", "127.0.0.1", "cli")
	if devResult.Action != DeviceError || devResult.ErrorCode != 403 {
		t.Fatalf("step 4: device should reject incomplete user, got action=%v code=%d", devResult.Action, devResult.ErrorCode)
	}

	// 5. Finally accept terms
	arID, _ := store.CreateTestAuthRequest(ctx, "e2e2-terms")
	termsResult := loginSvc.HandleTermsSubmit(ctx, arID, result2.SessionID, true, true, true, "127.0.0.1", "browser")
	if termsResult.Action != ActionAutoApprove {
		t.Fatalf("step 5: action = %v, want AutoApprove", termsResult.Action)
	}
}

// E2E 3: 재동의 사이클
func TestE2E3_ReconsentCycle(t *testing.T) {
	loginSvc, _, _, store, _, _ := setupE2ETest(t)
	ctx := context.Background()

	// 1. Create complete user
	user, _ := store.CreateUserWithIdentity(ctx, "e2e3@test.com", true, "Test", "", "google", "e2e-sub", "e2e3@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)

	// 2. Verify normal login works
	arID, _ := store.CreateTestAuthRequest(ctx, "e2e3-ok")
	result := loginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "browser")
	if result.Action != ActionAutoApprove {
		t.Fatalf("step 2: action = %v, want AutoApprove", result.Action)
	}

	// 3. Change terms version → reconsent_required (simulated by changing user's stored version)
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version")

	// 4. Browser login → show terms
	reconsentResult := loginSvc.HandleCallback(ctx, "fake-code", "req-e2e3-reconsent", "127.0.0.1", "browser")
	if reconsentResult.Action != ActionShowTerms {
		t.Fatalf("step 4: action = %v, want ShowTerms (reconsent)", reconsentResult.Action)
	}

	// 5. Re-accept terms
	arID2, _ := store.CreateTestAuthRequest(ctx, "e2e3-reaccept")
	reacceptResult := loginSvc.HandleTermsSubmit(ctx, arID2, reconsentResult.SessionID, true, true, true, "127.0.0.1", "browser")
	if reacceptResult.Action != ActionAutoApprove {
		t.Fatalf("step 5: action = %v, want AutoApprove (reconsent done)", reacceptResult.Action)
	}
}

// E2E 7: cleanup 멱등성
func TestE2E7_CleanupIdempotent(t *testing.T) {
	_, _, _, store, db, clk := setupE2ETest(t)
	ctx := context.Background()

	// Onboarding cleanup: create stale user
	user, _ := store.CreateUserWithIdentity(ctx, "e2e7-stale@test.com", true, "Test", "", "google", "e2e7-stale-sub", "e2e7@test.com")
	db.ExecContext(ctx, `UPDATE users SET created_at = $1 WHERE id = $2`, clk.Now().Add(-8*24*time.Hour), user.ID)

	svc := NewCleanupService(db, clk, time.Hour)

	// First run
	svc.RunOnce(ctx)
	var count int
	db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE id = $1`, user.ID).Scan(&count)
	if count != 0 {
		t.Fatal("stale user should be deleted after first cleanup")
	}

	// Second run — should not error
	svc.RunOnce(ctx)
	// No panic/error = idempotent
}
