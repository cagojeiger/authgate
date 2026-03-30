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

func setupDeviceService(t *testing.T) (*DeviceService, *storage.Storage) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{
		User: &upstream.UserInfo{
			Sub:           "device-sub-123",
			Email:         "device@example.com",
			EmailVerified: true,
			Name:          "Device User",
		},
	}

	svc := NewDeviceService(store, fakeProvider, termsV, privacyV, "http://localhost:8080", 24*time.Hour)
	return svc, store
}

func insertDeviceCode(t *testing.T, store *storage.Storage, userCode string) {
	t.Helper()
	ctx := context.Background()
	err := store.StoreDeviceAuthorization(ctx, "test-client", "dc-"+userCode, userCode,
		time.Now().Add(5*time.Minute), []string{"openid"})
	if err != nil {
		t.Fatalf("insert device code: %v", err)
	}
}

func TestDevicePage_NoUserCode_ShowEntry(t *testing.T) {
	svc, _ := setupDeviceService(t)
	result := svc.HandleDevicePage(context.Background(), "", "")
	if result.Action != DeviceShowEntry {
		t.Errorf("action = %v, want DeviceShowEntry", result.Action)
	}
}

func TestDevicePage_InvalidUserCode_ShowEntryWithError(t *testing.T) {
	svc, _ := setupDeviceService(t)
	result := svc.HandleDevicePage(context.Background(), "INVALID", "")
	if result.Action != DeviceShowEntry {
		t.Errorf("action = %v, want DeviceShowEntry", result.Action)
	}
	if result.Error == "" {
		t.Error("should have error message for invalid code")
	}
}

func TestDevicePage_ValidCode_NoSession_RedirectIdP(t *testing.T) {
	svc, store := setupDeviceService(t)
	insertDeviceCode(t, store, "BCDF-GHKM")

	result := svc.HandleDevicePage(context.Background(), "BCDF-GHKM", "")
	if result.Action != DeviceRedirectIdP {
		t.Errorf("action = %v, want DeviceRedirectIdP", result.Action)
	}
}

func TestDevicePage_ValidCode_WithSession_ShowApprove(t *testing.T) {
	svc, store := setupDeviceService(t)
	ctx := context.Background()

	// Create user with terms, session
	user, _ := store.CreateUserWithIdentity(ctx, "device-approve@test.com", true, "Test", "", "google", "device-approve-sub", "d@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)

	insertDeviceCode(t, store, "APPR-CODE")

	result := svc.HandleDevicePage(ctx, "APPR-CODE", sessionID)
	if result.Action != DeviceShowApprove {
		t.Errorf("action = %v, want DeviceShowApprove", result.Action)
	}
}

func TestDevicePage_IncompleteUser_Rejected(t *testing.T) {
	svc, store := setupDeviceService(t)
	ctx := context.Background()

	// Create user WITHOUT terms accepted
	user, _ := store.CreateUserWithIdentity(ctx, "device-incomplete@test.com", true, "Test", "", "google", "device-incomplete-sub", "di@test.com")
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)

	insertDeviceCode(t, store, "INCM-CODE")

	result := svc.HandleDevicePage(ctx, "INCM-CODE", sessionID)
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (signup_required)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

func TestDeviceApprove_Allow(t *testing.T) {
	svc, store := setupDeviceService(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "device-allow@test.com", true, "Test", "", "google", "device-allow-sub", "da@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)

	insertDeviceCode(t, store, "ALLW-CODE")

	result := svc.HandleDeviceApprove(ctx, "ALLW-CODE", "approve", sessionID, "127.0.0.1", "test")
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}
}

func TestDeviceApprove_Deny(t *testing.T) {
	svc, store := setupDeviceService(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "device-deny@test.com", true, "Test", "", "google", "device-deny-sub", "dd@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)

	insertDeviceCode(t, store, "DENY-CODE")

	result := svc.HandleDeviceApprove(ctx, "DENY-CODE", "deny", sessionID, "127.0.0.1", "test")
	if result.Success {
		t.Error("expected denial, got success")
	}
}

func TestDeviceApprove_NoSession_Unauthorized(t *testing.T) {
	svc, store := setupDeviceService(t)
	insertDeviceCode(t, store, "NSES-CODE")

	result := svc.HandleDeviceApprove(context.Background(), "NSES-CODE", "approve", "", "127.0.0.1", "test")
	if result.Success {
		t.Error("expected failure without session")
	}
	if result.ErrorCode != 401 {
		t.Errorf("errorCode = %d, want 401", result.ErrorCode)
	}
}

func TestDeviceCallback_NewUser_SignupRequired(t *testing.T) {
	svc, _ := setupDeviceService(t)
	// FakeProvider returns a user that doesn't exist in DB yet
	result := svc.HandleDeviceCallback(context.Background(), "fake-code", "CBCK-CODE", "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (signup_required)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

func TestDeviceCallback_ExistingUser_RedirectBack(t *testing.T) {
	svc, store := setupDeviceService(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "device-cb@test.com", true, "Test", "", "google", "device-sub-123", "dc@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)

	result := svc.HandleDeviceCallback(ctx, "fake-code", "RDIR-CODE", "127.0.0.1", "test")
	if result.Action != DeviceRedirectBack {
		t.Errorf("action = %v, want DeviceRedirectBack", result.Action)
	}
	if result.UserCode != "RDIR-CODE" {
		t.Errorf("userCode = %q, want RDIR-CODE", result.UserCode)
	}
}
// device-004: reconsent_required callback → signup_required
func TestDevice004_ReconsentCallback_Rejected(t *testing.T) {
	svc, store := setupDeviceExtTest(t, "dev-reconsent-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "dev-reconsent@test.com", true, "Test", "", "google", "dev-reconsent-sub", "dr@test.com")
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version")

	result := svc.HandleDeviceCallback(ctx, "fake-code", "RCON-CODE", "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (reconsent on device)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// device-005: recoverable_browser_only callback → account_inactive
func TestDevice005_RecoverableCallback_Rejected(t *testing.T) {
	svc, store := setupDeviceExtTest(t, "dev-recover-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "dev-recover@test.com", true, "Test", "", "google", "dev-recover-sub", "drc@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	store.SetUserStatus(ctx, user.ID, "pending_deletion")

	result := svc.HandleDeviceCallback(ctx, "fake-code", "RECV-CODE", "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (recoverable on device)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// device-006: inactive callback → account_inactive
func TestDevice006_InactiveCallback_Rejected(t *testing.T) {
	svc, store := setupDeviceExtTest(t, "dev-inactive-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "dev-inactive@test.com", true, "Test", "", "google", "dev-inactive-sub", "di@test.com")
	store.DisableUser(ctx, user.ID)

	result := svc.HandleDeviceCallback(ctx, "fake-code", "INAC-CODE", "127.0.0.1", "test")
	if result.Action != DeviceError {
		t.Errorf("action = %v, want DeviceError (inactive on device)", result.Action)
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// device-010: approve 직전 reconsent_required로 변경 → signup_required
func TestDevice010_ApproveAfterReconsentChange(t *testing.T) {
	svc, store := setupDeviceExtTest(t, "dev-approve-change-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "dev-approve-chg@test.com", true, "Test", "", "google", "dev-approve-change-sub", "dac@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	insertDeviceCode(t, store, "ACHG-CODE")

	// Change terms version AFTER session creation → reconsent_required
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version")

	result := svc.HandleDeviceApprove(ctx, "ACHG-CODE", "approve", sessionID, "127.0.0.1", "test")
	if result.Success {
		t.Error("expected rejection after reconsent change at approve time")
	}
	if result.ErrorCode != 403 {
		t.Errorf("errorCode = %d, want 403", result.ErrorCode)
	}
}

// device-011: approve 직전 inactive로 변경 → account_inactive
func TestDevice011_ApproveAfterDisable(t *testing.T) {
	svc, store := setupDeviceExtTest(t, "dev-approve-dis-sub")
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "dev-approve-dis@test.com", true, "Test", "", "google", "dev-approve-dis-sub", "dad@test.com")
	store.AcceptTerms(ctx, user.ID, termsV, privacyV)
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	insertDeviceCode(t, store, "ADIS-CODE")

	// Disable user AFTER session creation
	store.DisableUser(ctx, user.ID)

	result := svc.HandleDeviceApprove(ctx, "ADIS-CODE", "approve", sessionID, "127.0.0.1", "test")
	if result.Success {
		t.Error("expected rejection after disable at approve time")
	}
}
