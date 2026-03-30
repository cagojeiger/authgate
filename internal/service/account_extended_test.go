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
)

func setupAccountExtTest(t *testing.T) (*AccountService, *storage.Storage) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)
	svc := NewAccountService(db, clk)
	return svc, store
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
