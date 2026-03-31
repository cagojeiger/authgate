//go:build integration

package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/testutil"
)

func TestAuthRequestByID_Expired_Rejected(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	store := New(db, clk, gen, nil, 15*time.Minute, 30*24*time.Hour)
	ctx := context.Background()

	// Create auth request with 10 min TTL
	arID, err := store.CreateTestAuthRequest(ctx, "expiry-test")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	// Verify it works before expiry
	_, err = store.AuthRequestByID(ctx, arID)
	if err != nil {
		t.Fatalf("expected auth request to be valid, got: %v", err)
	}

	// Advance clock past expiry (11 minutes)
	clk.T = clk.T.Add(11 * time.Minute)

	_, err = store.AuthRequestByID(ctx, arID)
	if err == nil {
		t.Fatal("expected error for expired auth request, got nil")
	}
	if !strings.Contains(err.Error(), "auth request expired") {
		t.Errorf("error = %q, want to contain 'auth request expired'", err.Error())
	}
}

func TestAuthRequestByCode_Expired_Rejected(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	store := New(db, clk, gen, nil, 15*time.Minute, 30*24*time.Hour)
	ctx := context.Background()

	// Create auth request + complete + save code
	arID, _ := store.CreateTestAuthRequest(ctx, "code-expiry")
	user, _ := store.CreateUserWithIdentity(ctx, "code-expiry@test.com", true, "Test", "", "google", "code-expiry-sub", "ce@test.com")
	store.CompleteAuthRequest(ctx, arID, user.ID)
	store.SaveAuthCode(ctx, arID, "test-code-expiry")

	// Works before expiry
	_, err := store.AuthRequestByCode(ctx, "test-code-expiry")
	if err != nil {
		t.Fatalf("expected code lookup to succeed, got: %v", err)
	}

	// Advance clock past expiry
	clk.T = clk.T.Add(11 * time.Minute)

	_, err = store.AuthRequestByCode(ctx, "test-code-expiry")
	if err == nil {
		t.Fatal("expected error for expired code, got nil")
	}
}

func TestCompleteAuthRequest_Expired_Rejected(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	store := New(db, clk, gen, nil, 15*time.Minute, 30*24*time.Hour)
	ctx := context.Background()

	arID, _ := store.CreateTestAuthRequest(ctx, "complete-expiry")

	// Advance clock past expiry
	clk.T = clk.T.Add(11 * time.Minute)

	err := store.CompleteAuthRequest(ctx, arID, "some-user-id")
	if err == nil {
		t.Fatal("expected error for completing expired auth request, got nil")
	}
	if err != ErrNotFound {
		t.Errorf("error = %v, want ErrNotFound (expired request not matched by WHERE)", err)
	}
}
