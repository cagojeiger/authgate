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

func setupDeviceExtTest(t *testing.T, sub string) (*DeviceService, *storage.Storage) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{
		User: &upstream.UserInfo{Sub: sub, Email: sub + "@test.com", EmailVerified: true, Name: "Device Ext"},
	}
	svc := NewDeviceService(store, fakeProvider, termsV, privacyV, "http://localhost:8080", 24*time.Hour)
	return svc, store
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
