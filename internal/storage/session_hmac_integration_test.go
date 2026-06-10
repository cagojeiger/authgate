//go:build integration

package storage

import (
	"context"
	"testing"
	"time"
)

func TestSession_UsesSessionHMACWhenEncrypted(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()
	keys := testKeys(t, "enc-1", 0x11, "lkp-1", 0x22)
	s.SetKeys(keys)
	if err := s.EnsureCryptoEpochs(ctx); err != nil {
		t.Fatalf("ensure epochs: %v", err)
	}
	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "sess-hmac@test.com", EmailVerified: true, Name: "S", Provider: "google", ProviderUserID: "sess-hmac-sub",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, err := s.CreateSession(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	var stored string
	if err := s.DB().QueryRowContext(ctx,
		`SELECT token_hash FROM sessions WHERE user_id=$1`, user.ID,
	).Scan(&stored); err != nil {
		t.Fatalf("read token_hash: %v", err)
	}
	if stored != keys.SessionHash(token) {
		t.Error("token_hash is not the lookup/session HMAC")
	}
	if stored == hashToken(token) {
		t.Error("token_hash still uses legacy SHA-256 when keys configured")
	}

	got, err := s.GetValidSession(ctx, token)
	if err != nil || got.ID != user.ID {
		t.Fatalf("validate session: id=%v err=%v", got, err)
	}
}
