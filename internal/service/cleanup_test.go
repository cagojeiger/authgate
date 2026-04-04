//go:build integration

package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
)

func setupCleanupTest(t *testing.T) (*sql.DB, *storage.Storage, *clock.FixedClock) {
	t.Helper()
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	noopChecker := func(user *storage.User) error { return nil }
	store := storage.New(db, clk, gen, noopChecker, 15*time.Minute, 30*24*time.Hour)
	return db, store, clk
}

func TestCleanup_ExpiredSessions(t *testing.T) {
	db, store, clk := setupCleanupTest(t)
	ctx := context.Background()

	// Create user + expired session
	user, _ := store.CreateUserWithIdentity(ctx, "cleanup-session@test.com", true, "Test", "", "google", "cleanup-session-sub", "c@test.com")
	db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (uuid_generate_v4(), $1, $2, $3)`,
		user.ID, clk.Now().Add(-1*time.Hour), clk.Now().Add(-25*time.Hour), // expired 1 hour ago
	)

	// Verify session exists
	var count int
	db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, user.ID).Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 session, got %d", count)
	}

	// Run cleanup
	svc := NewCleanupService(storage.NewCleanupRunner(db), clk, time.Hour)
	svc.RunOnce(ctx)

	// Session should be deleted
	db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, user.ID).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 sessions after cleanup, got %d", count)
	}
}

func TestCleanup_ExpiredAuthRequests(t *testing.T) {
	db, _, clk := setupCleanupTest(t)
	ctx := context.Background()

	// Insert expired auth request (expired 2 hours ago)
	db.ExecContext(ctx,
		`INSERT INTO auth_requests (id, client_id, redirect_uri, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), 'test', 'http://localhost', '{openid}', $1, $2)`,
		clk.Now().Add(-2*time.Hour), clk.Now().Add(-3*time.Hour),
	)

	var count int
	db.QueryRowContext(ctx, `SELECT count(*) FROM auth_requests`).Scan(&count)
	if count < 1 {
		t.Fatal("expected at least 1 auth request")
	}

	svc := NewCleanupService(storage.NewCleanupRunner(db), clk, time.Hour)
	svc.RunOnce(ctx)

	db.QueryRowContext(ctx, `SELECT count(*) FROM auth_requests WHERE expires_at < $1`, clk.Now().Add(-1*time.Hour)).Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 expired auth requests after cleanup, got %d", count)
	}
}

func TestCleanup_DeletionPIIScrub(t *testing.T) {
	db, store, clk := setupCleanupTest(t)
	ctx := context.Background()

	// Create user, then set to pending_deletion with past scheduled date
	user, _ := store.CreateUserWithIdentity(ctx, "delete-me@test.com", true, "Delete Me", "", "google", "delete-sub", "d@test.com")
	db.ExecContext(ctx,
		`UPDATE users SET status = 'pending_deletion', deletion_scheduled_at = $1 WHERE id = $2`,
		clk.Now().Add(-1*time.Hour), user.ID, // scheduled in the past
	)

	// Create session and identity that should be cleaned up
	store.CreateSession(ctx, user.ID, 24*time.Hour)

	svc := NewCleanupService(storage.NewCleanupRunner(db), clk, time.Hour)
	svc.RunOnce(ctx)

	// User should be scrubbed
	var status, email string
	var name sql.NullString
	db.QueryRowContext(ctx, `SELECT status, email, name FROM users WHERE id = $1`, user.ID).Scan(&status, &email, &name)
	if status != "deleted" {
		t.Errorf("status = %q, want deleted", status)
	}
	if email == "delete-me@test.com" {
		t.Error("email should be scrubbed")
	}
	if name.Valid {
		t.Error("name should be NULL after scrub")
	}

	// Child records should be gone
	var identityCount, sessionCount int
	db.QueryRowContext(ctx, `SELECT count(*) FROM user_identities WHERE user_id = $1`, user.ID).Scan(&identityCount)
	db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, user.ID).Scan(&sessionCount)
	if identityCount != 0 {
		t.Errorf("expected 0 identities, got %d", identityCount)
	}
	if sessionCount != 0 {
		t.Errorf("expected 0 sessions, got %d", sessionCount)
	}

	// Audit event should exist
	var auditCount int
	db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE user_id = $1 AND event_type = 'auth.deletion_completed'`, user.ID).Scan(&auditCount)
	if auditCount != 1 {
		t.Errorf("expected 1 deletion_completed audit, got %d", auditCount)
	}
}

// E2E 8: cleanup 롤백 — 중간 실패 시 데이터 일관성
func TestE2E8_CleanupRollback(t *testing.T) {
	_, _, _, store, db, clk := setupGapTest(t)
	ctx := context.Background()

	// Create user set for deletion
	user, _ := store.CreateUserWithIdentity(ctx, "rollback@test.com", true, "Test", "", "google", "rollback-sub", "rb@test.com")
	db.ExecContext(ctx, `UPDATE users SET status='pending_deletion', deletion_scheduled_at=$1 WHERE id=$2`,
		clk.Now().Add(-1*time.Hour), user.ID)

	// Create child records that would be removed during cleanup.
	sessionID, err := store.CreateSession(ctx, user.ID, 24*time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	_, err = db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, uuid_generate_v4(), $2, 'test-client', '{openid}', $3, $4)`,
		"rollback-token-hash", user.ID, clk.Now().Add(30*24*time.Hour), clk.Now(),
	)
	if err != nil {
		t.Fatalf("insert refresh token: %v", err)
	}

	simulatedErr := errors.New("simulated cleanup failure")
	svc := NewCleanupService(storage.NewCleanupRunner(db), clk, time.Hour)
	svc.deleteUserHook = func(ctx context.Context, userID string) error {
		return simulatedErr
	}
	svc.RunOnce(ctx)

	// Verify everything rolled back: user is still pending_deletion, child records still exist.
	var status string
	db.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "pending_deletion" {
		t.Fatalf("status = %q, want pending_deletion after rollback", status)
	}

	var identityCount, sessionCount, refreshCount, auditCount int
	db.QueryRowContext(ctx, `SELECT count(*) FROM user_identities WHERE user_id = $1`, user.ID).Scan(&identityCount)
	db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE id = $1 AND user_id = $2`, sessionID, user.ID).Scan(&sessionCount)
	db.QueryRowContext(ctx, `SELECT count(*) FROM refresh_tokens WHERE user_id = $1`, user.ID).Scan(&refreshCount)
	db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE user_id = $1 AND event_type = 'auth.deletion_completed'`, user.ID).Scan(&auditCount)

	if identityCount != 1 {
		t.Errorf("identity count = %d, want 1 after rollback", identityCount)
	}
	if sessionCount != 1 {
		t.Errorf("session count = %d, want 1 after rollback", sessionCount)
	}
	if refreshCount != 1 {
		t.Errorf("refresh token count = %d, want 1 after rollback", refreshCount)
	}
	if auditCount != 0 {
		t.Errorf("audit count = %d, want 0 after rollback", auditCount)
	}
}

// E2E 6: cleanup job idempotency
func TestCleanup_DeletionPIIScrub_Idempotent(t *testing.T) {
	db, store, clk := setupCleanupTest(t)
	ctx := context.Background()

	user, _ := store.CreateUserWithIdentity(ctx, "cleanup-idem@test.com", true, "Idem", "", "google", "cleanup-idem-sub", "cleanup-idem@test.com")
	db.ExecContext(ctx,
		`UPDATE users SET status = 'pending_deletion', deletion_scheduled_at = $1 WHERE id = $2`,
		clk.Now().Add(-1*time.Hour), user.ID,
	)
	store.CreateSession(ctx, user.ID, 24*time.Hour)

	svc := NewCleanupService(storage.NewCleanupRunner(db), clk, time.Hour)
	svc.RunOnce(ctx)
	svc.RunOnce(ctx)

	var status string
	db.QueryRowContext(ctx, `SELECT status FROM users WHERE id = $1`, user.ID).Scan(&status)
	if status != "deleted" {
		t.Fatalf("status = %q, want deleted", status)
	}

	var identityCount, sessionCount, refreshCount, auditCount int
	db.QueryRowContext(ctx, `SELECT count(*) FROM user_identities WHERE user_id = $1`, user.ID).Scan(&identityCount)
	db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, user.ID).Scan(&sessionCount)
	db.QueryRowContext(ctx, `SELECT count(*) FROM refresh_tokens WHERE user_id = $1`, user.ID).Scan(&refreshCount)
	db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE user_id = $1 AND event_type = 'auth.deletion_completed'`, user.ID).Scan(&auditCount)

	if identityCount != 0 || sessionCount != 0 || refreshCount != 0 {
		t.Fatalf("child rows should remain deleted, got identities=%d sessions=%d refresh=%d", identityCount, sessionCount, refreshCount)
	}
	if auditCount != 1 {
		t.Fatalf("deletion_completed audit count = %d, want 1", auditCount)
	}
}
