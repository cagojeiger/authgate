//go:build integration

package storage

import (
	"context"
	"testing"
	"time"
)

// TerminateSession audits only a logout that ended something. Replayed or
// duplicate logout requests must not add auth.logout rows for sessions that
// were already gone.
func TestTerminateSession_AuditsOnlyWhenSessionsWereRevoked(t *testing.T) {
	store, _, _ := newTombstoneStore(t)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "terminate@test.com", EmailVerified: true, Name: "T", Provider: "google", ProviderUserID: "terminate-sub",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := store.CreateSession(ctx, user.ID, time.Hour); err != nil {
		t.Fatalf("create session: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := store.TerminateSession(ctx, user.ID, "test-client"); err != nil {
			t.Fatalf("terminate %d: %v", i, err)
		}
	}

	var n int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'auth.logout' AND user_id = $1`, user.ID,
	).Scan(&n); err != nil {
		t.Fatalf("count auth.logout: %v", err)
	}
	if n != 1 {
		t.Fatalf("auth.logout rows = %d, want 1 (only the call that revoked a session)", n)
	}
}
