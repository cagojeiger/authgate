//go:build integration

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/testutil"
)

func TestAudit010And011_RefreshReuseAndFamilyRevoke(t *testing.T) {
	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}
	store := New(db, clk, gen, func(user *User) error { return nil }, 15*time.Minute, 30*24*time.Hour)
	ctx := context.Background()

	user, err := store.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{Email: "audit-refresh@test.com", EmailVerified: true, Name: "Refresh Audit", AvatarURL: "", Provider: "google", ProviderUserID: "audit-refresh-sub", ProviderEmail: "audit-refresh@test.com"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := clk.Now()
	familyID := gen.NewUUID()
	reusedToken := "audit-reused-token"
	currentToken := "audit-current-token"
	reusedHash := hashToken(reusedToken)
	currentHash := hashToken(currentToken)

	if _, err := db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, revoked_at, used_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5, $5, $6)`,
		reusedHash, familyID, user.ID, now.Add(30*24*time.Hour), now, now,
	); err != nil {
		t.Fatalf("insert reused token: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES (uuid_generate_v4(), $1, $2, $3, 'test-client', '{openid}', $4, $5)`,
		currentHash, familyID, user.ID, now.Add(30*24*time.Hour), now,
	); err != nil {
		t.Fatalf("insert current token: %v", err)
	}

	if _, err := store.TokenRequestByRefreshToken(ctx, reusedToken); err == nil {
		t.Fatal("expected invalid refresh token error")
	}

	reuseEvent := requireStorageAuditEvent(t, db, user.ID, "auth.refresh_reuse_detected")
	if reuseEvent["family_id"] != familyID {
		t.Fatalf("reuse family_id = %v, want %s", reuseEvent["family_id"], familyID)
	}

	familyEvent := requireStorageAuditEvent(t, db, user.ID, "auth.refresh_family_revoked")
	if familyEvent["family_id"] != familyID {
		t.Fatalf("family revoke family_id = %v, want %s", familyEvent["family_id"], familyID)
	}
}

func requireStorageAuditEvent(t *testing.T, db *sql.DB, userID, eventType string) map[string]any {
	t.Helper()

	var raw []byte
	err := db.QueryRowContext(context.Background(),
		`SELECT metadata FROM audit_log WHERE user_id = $1 AND event_type = $2`,
		userID, eventType,
	).Scan(&raw)
	if err != nil {
		t.Fatalf("query audit event %s: %v", eventType, err)
	}

	var metadata map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &metadata); err != nil {
			t.Fatalf("decode metadata: %v", err)
		}
	}
	return metadata
}
