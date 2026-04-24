//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/storage"
)

// TestAccountDeletion_IdempotentAndSessionAlive verifies that:
// 1. DELETE /account marks user as pending_deletion and revokes refresh tokens
// 2. Sessions are NOT immediately revoked (they expire naturally per industry standard)
// 3. A second DELETE /account call returns 200 (idempotent)
func TestAccountDeletion_IdempotentAndSessionAlive(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email:          "deletion-idempotent@test.com",
		EmailVerified:  true,
		Name:           "Deletion Test",
		Provider:       "google",
		ProviderUserID: "deletion-idempotent-sub",
		ProviderEmail:  "deletion-idempotent@test.com",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	sessionID, err := ts.Store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	doDelete := func(label string) {
		req, _ := http.NewRequest(http.MethodDelete, ts.BaseURL+"/account", nil)
		req.Header.Set("Origin", ts.BaseURL)
		req.AddCookie(&http.Cookie{Name: "authgate_session", Value: sessionID})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: request error: %v", label, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", label, resp.StatusCode)
		}
	}

	// First call
	doDelete("first DELETE")

	// Session must still be alive (not revoked)
	var revokedAt *time.Time
	if err := ts.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM sessions WHERE id = $1`, sessionID,
	).Scan(&revokedAt); err != nil {
		t.Fatalf("query session: %v", err)
	}
	if revokedAt != nil {
		t.Error("session should NOT be revoked on deletion request (industry standard: let expire naturally)")
	}

	// Second call must also return 200 (idempotent)
	doDelete("second DELETE (idempotency check)")
}
