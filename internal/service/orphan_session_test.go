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

type expireAfterCreateSessionStore struct {
	*storage.Storage
	clk *clock.FixedClock
}

var _ LoginStore = (*expireAfterCreateSessionStore)(nil)

func (s *expireAfterCreateSessionStore) CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	sessionID, err := s.Storage.CreateSession(ctx, userID, ttl)
	if err != nil {
		return "", err
	}
	s.clk.T = s.clk.T.Add(11 * time.Minute)
	return sessionID, nil
}

func (s *expireAfterCreateSessionStore) CompleteLogin(ctx context.Context, authRequestID, userID string, sessionTTL time.Duration) (string, error) {
	s.clk.T = s.clk.T.Add(11 * time.Minute)
	return s.Storage.CompleteLogin(ctx, authRequestID, userID, sessionTTL)
}

func setupOrphanSessionTest(t *testing.T, providerUserID, email string) (*storage.Storage, *expireAfterCreateSessionStore, *upstream.FakeProvider) {
	t.Helper()

	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, idgen.CryptoGenerator{}, noopChecker, 15*time.Minute, 30*24*time.Hour)
	expiringStore := &expireAfterCreateSessionStore{Storage: store, clk: clk}
	provider := &upstream.FakeProvider{
		ProviderName: "google",
		User: &upstream.UserInfo{
			Sub:           providerUserID,
			Email:         email,
			EmailVerified: true,
			Name:          "Orphan Session User",
			Picture:       "https://example.com/photo.jpg",
		},
	}

	return store, expiringStore, provider
}

func activeSessionCount(t *testing.T, db *sql.DB, userID string) int {
	t.Helper()

	var count int
	if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, userID).Scan(&count); err != nil {
		t.Fatalf("count active sessions: %v", err)
	}
	return count
}

func TestLoginCallback_CompleteExpiresAfterCreateSession_LeavesOrphanSession(t *testing.T) {
	store, expiringStore, provider := setupOrphanSessionTest(t, "orphan-browser-sub", "orphan-browser@test.com")
	svc := NewLoginService(expiringStore, provider, 24*time.Hour)
	ctx := context.Background()

	authRequestID, err := store.CreateTestAuthRequest(ctx, "orphan-browser")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.HandleCallback(ctx, "fake-code", authRequestID, "127.0.0.1", "test-agent")

	if result.Action != ActionError {
		t.Fatalf("action = %v, want ActionError", result.Action)
	}
	if result.SessionID != "" {
		t.Fatalf("sessionID = %q, want empty", result.SessionID)
	}

	user, err := store.GetUserByProviderIdentity(ctx, "google", "orphan-browser-sub")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got := activeSessionCount(t, store.DB(), user.ID); got != 0 {
		t.Fatalf("active sessions = %d, want 0 (atomic tx now rolls back session insert on completion failure)", got)
	}
}

func TestMCPCallback_CompleteExpiresAfterCreateSession_LeavesOrphanSession(t *testing.T) {
	store, expiringStore, provider := setupOrphanSessionTest(t, "orphan-mcp-sub", "orphan-mcp@test.com")
	svc := NewMCPLoginService(expiringStore, provider, 24*time.Hour)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email:          "orphan-mcp@test.com",
		EmailVerified:  true,
		Name:           "Orphan MCP User",
		AvatarURL:      "",
		Provider:       "google",
		ProviderUserID: "orphan-mcp-sub",
		ProviderEmail:  "orphan-mcp@test.com",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	authRequestID, err := store.CreateTestAuthRequestWithResource(ctx, "orphan-mcp", "http://localhost/mcp")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	result := svc.HandleCallback(ctx, "fake-code", authRequestID, "127.0.0.1", "mcp-client")

	if result.Action != ActionError {
		t.Fatalf("action = %v, want ActionError", result.Action)
	}
	if result.SessionID != "" {
		t.Fatalf("sessionID = %q, want empty", result.SessionID)
	}
	if got := activeSessionCount(t, store.DB(), user.ID); got != 0 {
		t.Fatalf("active sessions = %d, want 0 (atomic tx now rolls back session insert on completion failure)", got)
	}
}

func TestLoginCallback_DoubleCallback_CreatesMultipleActiveSessions(t *testing.T) {
	svc, store := setupLoginService(t)
	ctx := context.Background()

	authRequestID, err := store.CreateTestAuthRequest(ctx, "double-callback")
	if err != nil {
		t.Fatalf("create auth request: %v", err)
	}

	first := svc.HandleCallback(ctx, "fake-code", authRequestID, "127.0.0.1", "test-agent")
	if first.Action != ActionAutoApprove {
		t.Fatalf("first action = %v, want ActionAutoApprove", first.Action)
	}
	second := svc.HandleCallback(ctx, "fake-code", authRequestID, "127.0.0.1", "test-agent")
	if second.Action != ActionError {
		t.Fatalf("second action = %v, want ActionError", second.Action)
	}
	if second.SessionID != "" {
		t.Fatalf("second sessionID = %q, want empty", second.SessionID)
	}

	user, err := store.GetUserByProviderIdentity(ctx, "google", "google-sub-123")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got := activeSessionCount(t, store.DB(), user.ID); got != 1 {
		t.Fatalf("active sessions = %d, want 1 (second callback must fail without creating another session)", got)
	}
}
