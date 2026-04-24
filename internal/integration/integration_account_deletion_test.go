//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/storage"
)

// TestAccountDeletionRevokesSession verifies that DELETE /account atomically
// revokes all active sessions for the user (spec-006).
func TestAccountDeletionRevokesSession(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	// 1. Create user + session
	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email:          "deletion-session-test@test.com",
		EmailVerified:  true,
		Name:           "Deletion Test",
		AvatarURL:      "",
		Provider:       "google",
		ProviderUserID: "deletion-session-sub",
		ProviderEmail:  "deletion-session-test@test.com",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	sessionID, err := ts.Store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// 2. Verify session is currently active (revoked_at IS NULL)
	var revokedBefore *time.Time
	err = ts.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM sessions WHERE id = $1`, sessionID,
	).Scan(&revokedBefore)
	if err != nil {
		t.Fatalf("query session before deletion: %v", err)
	}
	if revokedBefore != nil {
		t.Fatalf("session should not be revoked before deletion request, got revoked_at=%v", revokedBefore)
	}

	// 3. Call DELETE /account
	req, err := http.NewRequest(http.MethodDelete, ts.BaseURL+"/account", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Origin", ts.BaseURL)
	req.AddCookie(&http.Cookie{Name: "authgate_session", Value: sessionID})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /account: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /account status = %d, want 200", resp.StatusCode)
	}

	// 4. Verify session is now revoked (revoked_at IS NOT NULL)
	var revokedAfter *time.Time
	err = ts.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM sessions WHERE id = $1`, sessionID,
	).Scan(&revokedAfter)
	if err != nil {
		t.Fatalf("query session after deletion: %v", err)
	}
	if revokedAfter == nil {
		t.Fatal("session revoked_at should be set after deletion request, but got NULL")
	}
}

// TestAccountDeletionRevokesAllSessions verifies that all sessions for the user
// are revoked, not just the one used to make the request.
func TestAccountDeletionRevokesAllSessions(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	// Create user
	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email:          "deletion-multi-session@test.com",
		EmailVerified:  true,
		Name:           "Multi Session Test",
		AvatarURL:      "",
		Provider:       "google",
		ProviderUserID: "deletion-multi-session-sub",
		ProviderEmail:  "deletion-multi-session@test.com",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Create multiple sessions
	sessionID1, err := ts.Store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session 1: %v", err)
	}
	sessionID2, err := ts.Store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session 2: %v", err)
	}
	sessionID3, err := ts.Store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session 3: %v", err)
	}

	// Call DELETE /account using session 1
	req, err := http.NewRequest(http.MethodDelete, ts.BaseURL+"/account", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Origin", ts.BaseURL)
	req.AddCookie(&http.Cookie{Name: "authgate_session", Value: sessionID1})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /account: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /account status = %d, want 200", resp.StatusCode)
	}

	// Verify all three sessions are revoked
	for _, sid := range []string{sessionID1, sessionID2, sessionID3} {
		var revokedAt *time.Time
		err = ts.DB.QueryRowContext(ctx,
			`SELECT revoked_at FROM sessions WHERE id = $1`, sid,
		).Scan(&revokedAt)
		if err != nil {
			t.Fatalf("query session %s: %v", sid, err)
		}
		if revokedAt == nil {
			t.Errorf("session %s revoked_at should be set after deletion request, but got NULL", sid)
		}
	}
}
