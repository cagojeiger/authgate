//go:build integration

package storage

import (
	"context"
	"testing"
	"time"
)

func TestRevokeToken_UnknownUUID_NoAudit(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email:          "revoke-unknown@test.com",
		EmailVerified:  true,
		Name:           "Revoke Unknown",
		Provider:       "google",
		ProviderUserID: "revoke-unknown-sub",
		ProviderEmail:  "revoke-unknown@test.com",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	errOIDC := s.RevokeToken(ctx, "00000000-0000-0000-0000-000000000001", user.ID, "test-client")
	if errOIDC != nil {
		t.Fatalf("revoke token: %v", errOIDC)
	}

	if got := countTokenRevokedAudit(t, s, user.ID); got != 0 {
		t.Fatalf("auth.token_revoked audit count = %d, want 0", got)
	}
}

func TestRevokeToken_ValidRefreshTokenID_Audits(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email:          "revoke-valid@test.com",
		EmailVerified:  true,
		Name:           "Revoke Valid",
		Provider:       "google",
		ProviderUserID: "revoke-valid-sub",
		ProviderEmail:  "revoke-valid@test.com",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	now := s.clock.Now()
	refreshTokenID := s.idgen.NewUUID()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, token_hash, family_id, user_id, client_id, scopes, expires_at, created_at)
		 VALUES ($1, $2, uuid_generate_v4(), $3, 'test-client', '{openid}', $4, $5)`,
		refreshTokenID, hashToken("revoke-valid-refresh-token"), user.ID, now.Add(30*24*time.Hour), now,
	)
	if err != nil {
		t.Fatalf("insert refresh token: %v", err)
	}

	errOIDC := s.RevokeToken(ctx, refreshTokenID, user.ID, "test-client")
	if errOIDC != nil {
		t.Fatalf("revoke token: %v", errOIDC)
	}

	if got := countTokenRevokedAudit(t, s, user.ID); got != 1 {
		t.Fatalf("auth.token_revoked audit count = %d, want 1", got)
	}

	var revoked bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE id = $1`,
		refreshTokenID,
	).Scan(&revoked); err != nil {
		t.Fatalf("query revoked_at: %v", err)
	}
	if !revoked {
		t.Fatal("refresh token revoked_at is NULL, want non-NULL")
	}
}

func countTokenRevokedAudit(t *testing.T, s *Storage, userID string) int {
	t.Helper()

	var count int
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit_log WHERE user_id = $1 AND event_type = 'auth.token_revoked'`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	return count
}
