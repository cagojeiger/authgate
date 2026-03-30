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

	result := svc.HandleTermsSubmit(ctx, arID, sessionID, true, true, "127.0.0.1", "test-agent")

	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove", result.Action)
	}
}

func TestHandleTermsSubmit_MissingCheckbox_ShowTermsAgain(t *testing.T) {
	svc, _ := setupLoginService(t)
	ctx := context.Background()

	result := svc.HandleTermsSubmit(ctx, "req-123", "session-123", false, true, "", "")

	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (checkbox missing)", result.Action)
	}
	if result.Error == "" {
		t.Error("should have error message")
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
