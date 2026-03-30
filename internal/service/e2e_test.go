//go:build integration

package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/guard"
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
	stateChecker := func(user *storage.User) error {
		ui := &guard.UserInfo{
			Status:            user.Status,
			TermsAcceptedAt:   user.TermsAcceptedAt,
			PrivacyAcceptedAt: user.PrivacyAcceptedAt,
		}
		if user.TermsVersion != nil {
			ui.TermsVersion = *user.TermsVersion
		}
		if user.PrivacyVersion != nil {
			ui.PrivacyVersion = *user.PrivacyVersion
		}
		state := guard.DeriveLoginState(ui, termsV, privacyV)
		if state != guard.OnboardingComplete {
			return fmt.Errorf("login state: %s", state)
		}
		return nil
	}
	store := storage.New(db, clk, gen, stateChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: "e2e-sub", Email: "e2e@test.com", EmailVerified: true, Name: "E2E User"},
	}

	loginSvc := NewLoginService(store, fakeProvider, fakeProvider, termsV, privacyV, 24*time.Hour)
	deviceSvc := NewDeviceService(store, fakeProvider, termsV, privacyV, "http://localhost:8080", 24*time.Hour, clk)
	accountSvc := NewAccountService(db, clk)
	return loginSvc, deviceSvc, accountSvc, store, db, clk
}

func createRefreshTokenForUser(t *testing.T, ctx context.Context, store *storage.Storage, userID string) string {
	t.Helper()
	subject := userID
	_, refreshToken, _, err := store.CreateAccessAndRefreshTokens(ctx, &storage.AuthRequestModel{
		Subject:  &subject,
		ClientID: "test-client",
		Scopes:   storage.StringArray{"openid", "profile", "email", "offline_access"},
	}, "")
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	return refreshToken
}

// E2E 1: 최초 가입 → 정상 사용 → Device/MCP 후속 채널
func TestE2E1_SignupToAllChannels(t *testing.T) {
	loginSvc, deviceSvc, _, store, _, clk := setupE2ETest(t)
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
	user, err := store.GetUserByProviderIdentity(ctx, "google", "e2e-sub")
	if err != nil {
		t.Fatalf("load user after signup: %v", err)
	}
	if user.TermsAcceptedAt == nil || user.PrivacyAcceptedAt == nil {
		t.Fatal("step 2: user should be onboarding_complete after terms submit")
	}

	// 3. Browser re-login → auto-approve
	arID2, _ := store.CreateTestAuthRequest(ctx, "e2e1-relogin")
	relogin := loginSvc.HandleCallback(ctx, "fake-code", arID2, "127.0.0.1", "browser")
	if relogin.Action != ActionAutoApprove {
		t.Fatalf("step 3: action = %v, want AutoApprove", relogin.Action)
	}

	// 4. Device callback → should succeed (redirect back)
	store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e1", "E2E1-CODE", clk.Now().Add(5*time.Minute), []string{"openid"})
	devResult := deviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E1-CODE", "127.0.0.1", "cli")
	if devResult.Action != DeviceRedirectBack {
		t.Fatalf("step 4: device action = %v, want RedirectBack", devResult.Action)
	}

	// 5. MCP (same as browser path) → auto-approve
	arID3, _ := store.CreateTestAuthRequest(ctx, "e2e1-mcp")
	mcpResult := loginSvc.HandleMCPCallback(ctx, "fake-code", arID3, "127.0.0.1", "mcp-client")
	if mcpResult.Action != ActionAutoApprove {
		t.Fatalf("step 5: mcp action = %v, want AutoApprove", mcpResult.Action)
	}
}

// E2E 2: 가입 중 이탈 후 복귀
func TestE2E2_AbandonAndReturn(t *testing.T) {
	loginSvc, deviceSvc, _, store, _, clk := setupE2ETest(t)
	ctx := context.Background()

	// 1. Browser signup → show terms
	result := loginSvc.HandleCallback(ctx, "fake-code", "req-e2e2", "127.0.0.1", "browser")
	if result.Action != ActionShowTerms {
		t.Fatalf("step 1: action = %v, want ShowTerms", result.Action)
	}

	// 2. User abandons (no terms submit)
	user, err := store.GetUserByProviderIdentity(ctx, "google", "e2e-sub")
	if err != nil {
		t.Fatalf("step 2: user should exist after signup start: %v", err)
	}
	if user.TermsAcceptedAt != nil || user.PrivacyAcceptedAt != nil {
		t.Fatal("step 2: user should remain initial_onboarding_incomplete")
	}

	// 3. Browser re-login → show terms again
	result2 := loginSvc.HandleCallback(ctx, "fake-code", "req-e2e2-retry", "127.0.0.1", "browser")
	if result2.Action != ActionShowTerms {
		t.Fatalf("step 3: action = %v, want ShowTerms (still incomplete)", result2.Action)
	}

	// 4. Device callback → signup_required
	store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e2", "E2E2-CODE", clk.Now().Add(5*time.Minute), []string{"openid"})
	devResult := deviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E2-CODE", "127.0.0.1", "cli")
	if devResult.Action != DeviceError || devResult.ErrorCode != 403 {
		t.Fatalf("step 4: device should reject incomplete user, got action=%v code=%d", devResult.Action, devResult.ErrorCode)
	}
	arIDMCP, _ := store.CreateTestAuthRequest(ctx, "e2e2-mcp")
	mcpResult := loginSvc.HandleMCPCallback(ctx, "fake-code", arIDMCP, "127.0.0.1", "mcp-client")
	if mcpResult.Action != ActionError || mcpResult.ErrorCode != 403 {
		t.Fatalf("step 4: mcp should reject incomplete user, got action=%v code=%d", mcpResult.Action, mcpResult.ErrorCode)
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
	loginSvc, deviceSvc, _, store, _, clk := setupE2ETest(t)
	ctx := context.Background()

	// 1. Create complete user
	user, _ := store.CreateUserWithIdentity(ctx, "e2e3@test.com", true, "Test", "", "google", "e2e-sub", "e2e3@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	refreshToken := createRefreshTokenForUser(t, ctx, store, user.ID)

	// 2. Verify normal login works
	arID, _ := store.CreateTestAuthRequest(ctx, "e2e3-ok")
	result := loginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "browser")
	if result.Action != ActionAutoApprove {
		t.Fatalf("step 2: action = %v, want AutoApprove", result.Action)
	}

	// 3. Change terms version → reconsent_required (simulated by changing user's stored version)
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version")
	_, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("step 3: refresh should fail with invalid_grant, got err=%v", err)
	}

	// 4. Device/MCP should be rejected
	store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e3", "E2E3-CODE", clk.Now().Add(5*time.Minute), []string{"openid"})
	devResult := deviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E3-CODE", "127.0.0.1", "cli")
	if devResult.Action != DeviceError || devResult.ErrorCode != 403 {
		t.Fatalf("step 4: device should reject reconsent_required user, got action=%v code=%d", devResult.Action, devResult.ErrorCode)
	}
	arIDMCP, _ := store.CreateTestAuthRequest(ctx, "e2e3-mcp")
	mcpResult := loginSvc.HandleMCPCallback(ctx, "fake-code", arIDMCP, "127.0.0.1", "mcp-client")
	if mcpResult.Action != ActionError || mcpResult.ErrorCode != 403 {
		t.Fatalf("step 4: mcp should reject reconsent_required user, got action=%v code=%d", mcpResult.Action, mcpResult.ErrorCode)
	}

	// 5. Browser login → show terms
	reconsentResult := loginSvc.HandleCallback(ctx, "fake-code", "req-e2e3-reconsent", "127.0.0.1", "browser")
	if reconsentResult.Action != ActionShowTerms {
		t.Fatalf("step 5: action = %v, want ShowTerms (reconsent)", reconsentResult.Action)
	}

	// 6. Re-accept terms
	arID2, _ := store.CreateTestAuthRequest(ctx, "e2e3-reaccept")
	reacceptResult := loginSvc.HandleTermsSubmit(ctx, arID2, reconsentResult.SessionID, true, true, true, "127.0.0.1", "browser")
	if reacceptResult.Action != ActionAutoApprove {
		t.Fatalf("step 6: action = %v, want AutoApprove (reconsent done)", reacceptResult.Action)
	}
}

// E2E 4: 탈퇴 후 복구
func TestE2E4_DeleteThenRecoverFullCycle(t *testing.T) {
	loginSvc, deviceSvc, accountSvc, store, db, clk := setupE2ETest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "e2e4-full@test.com", true, "Test", "", "google", "e2e-sub", "e2e4-full@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	refreshToken := createRefreshTokenForUser(t, ctx, store, user.ID)

	// 1. DELETE /account -> pending_deletion
	result := accountSvc.RequestDeletion(ctx, user.ID, "127.0.0.1", "test")
	if !result.Success {
		t.Fatalf("step 1: deletion request failed: %s", result.Message)
	}
	var status string
	db.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "pending_deletion" {
		t.Fatalf("step 1: status = %q, want pending_deletion", status)
	}

	// 2. Refresh should fail immediately
	_, err := store.TokenRequestByRefreshToken(ctx, refreshToken)
	if err == nil || !strings.Contains(err.Error(), "invalid_refresh_token") {
		t.Fatalf("step 2: refresh should fail with invalid_refresh_token, got err=%v", err)
	}

	// 3. Device/MCP should be rejected
	store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e4", "E2E4-CODE", clk.Now().Add(5*time.Minute), []string{"openid"})
	devResult := deviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E4-CODE", "127.0.0.1", "cli")
	if devResult.Action != DeviceError || devResult.ErrorCode != 403 {
		t.Fatalf("step 3: device should reject pending_deletion user, got action=%v code=%d", devResult.Action, devResult.ErrorCode)
	}
	arIDMCP, _ := store.CreateTestAuthRequest(ctx, "e2e4-mcp")
	mcpResult := loginSvc.HandleMCPCallback(ctx, "fake-code", arIDMCP, "127.0.0.1", "mcp-client")
	if mcpResult.Action != ActionError || mcpResult.ErrorCode != 403 {
		t.Fatalf("step 3: mcp should reject pending_deletion user, got action=%v code=%d", mcpResult.Action, mcpResult.ErrorCode)
	}

	// 4. Browser login recovers
	arIDBrowser, _ := store.CreateTestAuthRequest(ctx, "e2e4-browser")
	recoverResult := loginSvc.HandleCallback(ctx, "fake-code", arIDBrowser, "127.0.0.1", "browser")
	if recoverResult.Action != ActionAutoApprove {
		t.Fatalf("step 4: browser recovery action = %v, want AutoApprove", recoverResult.Action)
	}

	// 5. After recovery, refresh/device/mcp work again
	newRefreshToken := createRefreshTokenForUser(t, ctx, store, user.ID)
	if _, err := store.TokenRequestByRefreshToken(ctx, newRefreshToken); err != nil {
		t.Fatalf("step 5: refresh should succeed after recovery, got err=%v", err)
	}
	store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e4-ok", "E2E4-OK", clk.Now().Add(5*time.Minute), []string{"openid"})
	devResult2 := deviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E4-OK", "127.0.0.1", "cli")
	if devResult2.Action != DeviceRedirectBack {
		t.Fatalf("step 5: device should succeed after recovery, got action=%v", devResult2.Action)
	}
	arIDMCP2, _ := store.CreateTestAuthRequest(ctx, "e2e4-mcp-ok")
	mcpResult2 := loginSvc.HandleMCPCallback(ctx, "fake-code", arIDMCP2, "127.0.0.1", "mcp-client")
	if mcpResult2.Action != ActionAutoApprove {
		t.Fatalf("step 5: mcp should succeed after recovery, got action=%v", mcpResult2.Action)
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
