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

func setupBrowserExtTest(t *testing.T) (*LoginService, *storage.Storage) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)

	fakeProvider := &upstream.FakeProvider{
		User: &upstream.UserInfo{Sub: "browser-ext-sub", Email: "browser-ext@test.com", EmailVerified: true, Name: "Browser Ext"},
	}
	svc := NewLoginService(store, fakeProvider, termsV, privacyV, 24*time.Hour)
	return svc, store
}

// browser-004: reconsent_required → terms 재동의 표시
func TestBrowser004_ReconsentRequired_ShowTerms(t *testing.T) {
	svc, store := setupBrowserExtTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "reconsent@test.com", true, "Test", "", "google", "browser-ext-sub", "r@test.com")
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version") // wrong version

	result := svc.HandleCallback(ctx, "fake-code", "req-reconsent", "127.0.0.1", "test")
	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (reconsent_required)", result.Action)
	}
}

// browser-terms-002: reconsent 재동의 완료 → onboarding_complete
func TestBrowserTerms002_ReconsentComplete(t *testing.T) {
	svc, store := setupBrowserExtTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "reconsent-done@test.com", true, "Test", "", "google", "reconsent-done-sub", "rd@test.com")
	store.AcceptTerms(ctx, user.ID, "old-version", "old-version")
	sessionID, _ := store.CreateSession(ctx, user.ID, 24*time.Hour)
	arID, _ := store.CreateTestAuthRequest(ctx, "reconsent-done")

	result := svc.HandleTermsSubmit(ctx, arID, sessionID, true, true, true, "127.0.0.1", "test")
	if result.Action != ActionAutoApprove {
		t.Errorf("action = %v, want AutoApprove (reconsent done)", result.Action)
	}
}

// browser-terms-004: age_confirm만 미선택 → 200 + 재표시
func TestBrowserTerms004_AgeConfirmMissing(t *testing.T) {
	svc, _ := setupBrowserExtTest(t)
	ctx := context.Background()

	result := svc.HandleTermsSubmit(ctx, "req-age", "session-age", true, true, false, "", "")
	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (age_confirm missing)", result.Action)
	}
}

// browser-terms: privacy만 미선택 → 200 + 재표시
func TestBrowserTerms_PrivacyMissing(t *testing.T) {
	svc, _ := setupBrowserExtTest(t)
	ctx := context.Background()

	result := svc.HandleTermsSubmit(ctx, "req-priv", "session-priv", true, false, true, "", "")
	if result.Action != ActionShowTerms {
		t.Errorf("action = %v, want ShowTerms (privacy missing)", result.Action)
	}
}
