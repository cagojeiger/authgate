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
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
	"github.com/kangheeyong/authgate/internal/upstream"
)

type e2eFixture struct {
	LoginSvc    *LoginService
	MCPLoginSvc *MCPLoginService
	DeviceSvc   *DeviceService
	AccountSvc  *AccountService
	Store       *storage.Storage
	DB          *sql.DB
	Clock       *clock.FixedClock
}

func setupE2ETest(t *testing.T) *e2eFixture {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	stateChecker := func(user *storage.User) error {
		if user.Status != "active" {
			return fmt.Errorf("account not active: %s", user.Status)
		}
		return nil
	}
	store := storage.New(db, clk, gen, stateChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: "e2e-sub", Email: "e2e@test.com", EmailVerified: true, Name: "E2E User"},
	}

	loginSvc := NewLoginService(store, fakeProvider, 24*time.Hour)
	mcpLoginSvc := NewMCPLoginService(store, fakeProvider, 24*time.Hour)
	deviceSvc := NewDeviceService(store, fakeProvider, "http://localhost:8080", 24*time.Hour, clk)
	accountSvc := NewAccountService(store)
	return &e2eFixture{
		LoginSvc:    loginSvc,
		MCPLoginSvc: mcpLoginSvc,
		DeviceSvc:   deviceSvc,
		AccountSvc:  accountSvc,
		Store:       store,
		DB:          db,
		Clock:       clk,
	}
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
	fx := setupE2ETest(t)
	ctx := context.Background()

	// 1. Browser signup → auto-approve (no terms step)
	arID1, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e1-signup")
	result := fx.LoginSvc.HandleCallback(ctx, "fake-code", arID1, "127.0.0.1", "browser")
	if result.Action != ActionAutoApprove {
		t.Fatalf("step 1: action = %v, want AutoApprove", result.Action)
	}

	// 2. Browser re-login → auto-approve
	arID2, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e1-relogin")
	relogin := fx.LoginSvc.HandleCallback(ctx, "fake-code", arID2, "127.0.0.1", "browser")
	if relogin.Action != ActionAutoApprove {
		t.Fatalf("step 2: action = %v, want AutoApprove", relogin.Action)
	}

	// 3. Device callback → should succeed (redirect back)
	fx.Store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e1", "E2E1-CODE", fx.Clock.Now().Add(5*time.Minute), []string{"openid"})
	devResult := fx.DeviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E1-CODE", "127.0.0.1", "cli")
	if devResult.Action != DeviceRedirectBack {
		t.Fatalf("step 3: device action = %v, want RedirectBack", devResult.Action)
	}

	// 4. MCP → auto-approve
	arID3, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e1-mcp")
	mcpResult := fx.MCPLoginSvc.HandleCallback(ctx, "fake-code", arID3, "127.0.0.1", "mcp-client")
	if mcpResult.Action != ActionAutoApprove {
		t.Fatalf("step 4: mcp action = %v, want AutoApprove", mcpResult.Action)
	}
}

// E2E 2: 가입 중 이탈 → Device/MCP 차단 → Browser 완료 후 정상화
// 시나리오: 유저가 Browser 가입을 시작했지만 완료하지 않은 상태에서
// Device/MCP 로그인을 시도하면 account_not_found로 차단된다.
// Browser로 가입 완료 후에는 모든 채널이 정상 동작해야 한다.
func TestE2E2_SignupAbandonAndReturn(t *testing.T) {
	fx := setupE2ETest(t)
	ctx := context.Background()

	// Step 2/3: 유저 DB 없음 → Device/MCP 차단 (account_not_found)
	fx.Store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e2", "E2E2-DCODE", fx.Clock.Now().Add(5*time.Minute), []string{"openid"})
	devResult := fx.DeviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E2-DCODE", "127.0.0.1", "cli")
	if devResult.Action != DeviceError {
		t.Fatalf("device before signup: action=%v, want DeviceError", devResult.Action)
	}

	arIDMCP, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e2-mcp-pre")
	mcpResult := fx.MCPLoginSvc.HandleCallback(ctx, "fake-code", arIDMCP, "127.0.0.1", "mcp")
	if mcpResult.Action != ActionError {
		t.Fatalf("mcp before signup: action=%v, want ActionError", mcpResult.Action)
	}

	// Step 3: Browser 완료 → 가입 (새 유저 생성)
	arIDBrowser, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e2-browser")
	browserResult := fx.LoginSvc.HandleCallback(ctx, "fake-code", arIDBrowser, "127.0.0.1", "browser")
	if browserResult.Action != ActionAutoApprove {
		t.Fatalf("browser signup: action=%v, want ActionAutoApprove", browserResult.Action)
	}

	// 가입 후 Device 정상 동작
	fx.Store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e2-ok", "E2E2-DCODE2", fx.Clock.Now().Add(5*time.Minute), []string{"openid"})
	devResult2 := fx.DeviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E2-DCODE2", "127.0.0.1", "cli")
	if devResult2.Action != DeviceRedirectBack {
		t.Fatalf("device after signup: action=%v, want DeviceRedirectBack", devResult2.Action)
	}

	// 가입 후 MCP 정상 동작
	arIDMCP2, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e2-mcp-post")
	mcpResult2 := fx.MCPLoginSvc.HandleCallback(ctx, "fake-code", arIDMCP2, "127.0.0.1", "mcp")
	if mcpResult2.Action != ActionAutoApprove {
		t.Fatalf("mcp after signup: action=%v, want ActionAutoApprove", mcpResult2.Action)
	}
}

// E2E 4: 탈퇴 후 복구
func TestE2E4_DeleteThenRecoverFullCycle(t *testing.T) {
	fx := setupE2ETest(t)
	ctx := context.Background()

	user, _ := fx.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "e2e4-full@test.com", EmailVerified: true, Name: "Test", AvatarURL: "", Provider: "google", ProviderUserID: "e2e-sub", ProviderEmail: "e2e4-full@test.com"})
	sessionID, _ := fx.Store.CreateSession(ctx, user.ID, 24*time.Hour)
	refreshToken := createRefreshTokenForUser(t, ctx, fx.Store, user.ID)

	// 1. DELETE /account -> pending_deletion
	result := fx.AccountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
	if !result.Success {
		t.Fatalf("step 1: deletion request failed: %s", result.Message)
	}
	var status string
	fx.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "pending_deletion" {
		t.Fatalf("step 1: status = %q, want pending_deletion", status)
	}

	// 2. Refresh should fail immediately
	_, err := fx.Store.TokenRequestByRefreshToken(ctx, refreshToken)
	if err == nil || !strings.Contains(err.Error(), "invalid_refresh_token") {
		t.Fatalf("step 2: refresh should fail with invalid_refresh_token, got err=%v", err)
	}

	// 3. Device/MCP should be rejected
	fx.Store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e4", "E2E4-CODE", fx.Clock.Now().Add(5*time.Minute), []string{"openid"})
	devResult := fx.DeviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E4-CODE", "127.0.0.1", "cli")
	if devResult.Action != DeviceError || devResult.ErrorCode != 403 {
		t.Fatalf("step 3: device should reject pending_deletion user, got action=%v code=%d", devResult.Action, devResult.ErrorCode)
	}
	arIDMCP, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e4-mcp")
	mcpResult := fx.MCPLoginSvc.HandleCallback(ctx, "fake-code", arIDMCP, "127.0.0.1", "mcp-client")
	if mcpResult.Action != ActionError || mcpResult.ErrorCode != 403 {
		t.Fatalf("step 3: mcp should reject pending_deletion user, got action=%v code=%d", mcpResult.Action, mcpResult.ErrorCode)
	}

	// 4. Browser login recovers
	arIDBrowser, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e4-browser")
	recoverResult := fx.LoginSvc.HandleCallback(ctx, "fake-code", arIDBrowser, "127.0.0.1", "browser")
	if recoverResult.Action != ActionAutoApprove {
		t.Fatalf("step 4: browser recovery action = %v, want AutoApprove", recoverResult.Action)
	}

	// 5. After recovery, refresh/device/mcp work again
	newRefreshToken := createRefreshTokenForUser(t, ctx, fx.Store, user.ID)
	if _, err := fx.Store.TokenRequestByRefreshToken(ctx, newRefreshToken); err != nil {
		t.Fatalf("step 5: refresh should succeed after recovery, got err=%v", err)
	}
	fx.Store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e4-ok", "E2E4-OK", fx.Clock.Now().Add(5*time.Minute), []string{"openid"})
	devResult2 := fx.DeviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E4-OK", "127.0.0.1", "cli")
	if devResult2.Action != DeviceRedirectBack {
		t.Fatalf("step 5: device should succeed after recovery, got action=%v", devResult2.Action)
	}
	arIDMCP2, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e4-mcp-ok")
	mcpResult2 := fx.MCPLoginSvc.HandleCallback(ctx, "fake-code", arIDMCP2, "127.0.0.1", "mcp-client")
	if mcpResult2.Action != ActionAutoApprove {
		t.Fatalf("step 5: mcp should succeed after recovery, got action=%v", mcpResult2.Action)
	}
}

// E2E 5: 복구 후 로그인 완료 실패가 발생해도 다음 재시도에서 정상 완료되어야 한다.
func TestE2E5_RecoveryThenAuthRequestRetry(t *testing.T) {
	fx := setupE2ETest(t)
	ctx := context.Background()

	user, _ := fx.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "e2e5-retry@test.com", EmailVerified: true, Name: "Retry User", AvatarURL: "", Provider: "google", ProviderUserID: "e2e-sub", ProviderEmail: "e2e5-retry@test.com"})
	sessionID, _ := fx.Store.CreateSession(ctx, user.ID, 24*time.Hour)

	// 1) pending_deletion 전환
	del := fx.AccountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
	if !del.Success {
		t.Fatalf("deletion request failed: %s", del.Message)
	}

	// 2) Browser callback 시도하되 존재하지 않는 authRequestID로 완료 단계 실패 유도
	first := fx.LoginSvc.HandleCallback(ctx, "fake-code", "missing-auth-request", "127.0.0.1", "browser")
	if first.Action != ActionError {
		t.Fatalf("first action = %v, want ActionError", first.Action)
	}

	// 복구는 선행되므로 status는 active여야 한다.
	var status string
	fx.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "active" {
		t.Fatalf("status after failed completion = %q, want active", status)
	}

	// 3) 정상 authRequest로 재시도 시 성공해야 한다.
	arID, _ := fx.Store.CreateTestAuthRequest(ctx, "e2e5-retry")
	second := fx.LoginSvc.HandleCallback(ctx, "fake-code", arID, "127.0.0.1", "browser")
	if second.Action != ActionAutoApprove {
		t.Fatalf("second action = %v, want ActionAutoApprove", second.Action)
	}
}
