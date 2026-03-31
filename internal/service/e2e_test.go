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

func setupE2ETest(t *testing.T) (*LoginService, *DeviceService, *AccountService, *storage.Storage, *sql.DB, *clock.FixedClock) {
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

	loginSvc := NewLoginService(store, fakeProvider, fakeProvider, 24*time.Hour)
	deviceSvc := NewDeviceService(store, fakeProvider, "http://localhost:8080", 24*time.Hour, clk)
	accountSvc := NewAccountService(store)
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

	// 1. Browser signup → auto-approve (no terms step)
	arID1, _ := store.CreateTestAuthRequest(ctx, "e2e1-signup")
	result := loginSvc.HandleCallback(ctx, "fake-code", arID1, "127.0.0.1", "browser")
	if result.Action != ActionAutoApprove {
		t.Fatalf("step 1: action = %v, want AutoApprove", result.Action)
	}

	// 2. Browser re-login → auto-approve
	arID2, _ := store.CreateTestAuthRequest(ctx, "e2e1-relogin")
	relogin := loginSvc.HandleCallback(ctx, "fake-code", arID2, "127.0.0.1", "browser")
	if relogin.Action != ActionAutoApprove {
		t.Fatalf("step 2: action = %v, want AutoApprove", relogin.Action)
	}

	// 3. Device callback → should succeed (redirect back)
	store.StoreDeviceAuthorization(ctx, "test-client", "dc-e2e1", "E2E1-CODE", clk.Now().Add(5*time.Minute), []string{"openid"})
	devResult := deviceSvc.HandleDeviceCallback(ctx, "fake-code", "E2E1-CODE", "127.0.0.1", "cli")
	if devResult.Action != DeviceRedirectBack {
		t.Fatalf("step 3: device action = %v, want RedirectBack", devResult.Action)
	}

	// 4. MCP → auto-approve
	arID3, _ := store.CreateTestAuthRequest(ctx, "e2e1-mcp")
	mcpResult := loginSvc.HandleMCPCallback(ctx, "fake-code", arID3, "127.0.0.1", "mcp-client")
	if mcpResult.Action != ActionAutoApprove {
		t.Fatalf("step 4: mcp action = %v, want AutoApprove", mcpResult.Action)
	}
}

// E2E 4: 탈퇴 후 복구
func TestE2E4_DeleteThenRecoverFullCycle(t *testing.T) {
	loginSvc, deviceSvc, accountSvc, store, db, clk := setupE2ETest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "e2e4-full@test.com", true, "Test", "", "google", "e2e-sub", "e2e4-full@test.com")
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	refreshToken := createRefreshTokenForUser(t, ctx, store, user.ID)

	// 1. DELETE /account -> pending_deletion
	result := accountSvc.RequestDeletion(ctx, sessionID, "127.0.0.1", "test")
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
