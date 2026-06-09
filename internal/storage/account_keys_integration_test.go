//go:build integration

package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/kangheeyong/authgate/internal/crypto"
)

func testKEKProvider(t *testing.T) *crypto.KEKProvider {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	kek, err := crypto.NewMasterKEK(key, "test", "1")
	if err != nil {
		t.Fatalf("new kek: %v", err)
	}
	p, err := crypto.NewKEKProvider(kek)
	if err != nil {
		t.Fatalf("new kek provider: %v", err)
	}
	return p
}

func TestAccountDEK_NotConfigured(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()
	user := mustUser(t, s, "dek-unconfigured@test.com", "dek-unconfigured-sub")

	if _, err := s.GetOrCreateAccountDEK(ctx, user.ID); !errors.Is(err, ErrEncryptionNotConfigured) {
		t.Fatalf("err = %v, want ErrEncryptionNotConfigured", err)
	}
}

func TestAccountDEK_CreateIsStableAndWrapped(t *testing.T) {
	s := testStorage(t)
	s.SetKEKProvider(testKEKProvider(t))
	ctx := context.Background()
	user := mustUser(t, s, "dek-create@test.com", "dek-create-sub")

	dek1, err := s.GetOrCreateAccountDEK(ctx, user.ID)
	if err != nil {
		t.Fatalf("create dek: %v", err)
	}
	if len(dek1) != crypto.KeySize {
		t.Fatalf("dek size = %d, want %d", len(dek1), crypto.KeySize)
	}

	// Second call returns the same persisted DEK (stable per account).
	dek2, err := s.GetOrCreateAccountDEK(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload dek: %v", err)
	}
	if !bytes.Equal(dek1, dek2) {
		t.Fatal("DEK not stable across calls")
	}

	// The raw DEK must never be persisted — only a wrapped blob.
	var wrapped []byte
	if err := s.DB().QueryRowContext(ctx,
		`SELECT wrapped_dek FROM account_encryption_keys WHERE account_id = $1`, user.ID,
	).Scan(&wrapped); err != nil {
		t.Fatalf("read wrapped_dek: %v", err)
	}
	if bytes.Contains(wrapped, dek1) {
		t.Fatal("stored wrapped_dek contains the raw DEK")
	}
}

func TestAccountDEK_CryptoShred(t *testing.T) {
	s := testStorage(t)
	s.SetKEKProvider(testKEKProvider(t))
	ctx := context.Background()
	user := mustUser(t, s, "dek-shred@test.com", "dek-shred-sub")

	if _, err := s.GetOrCreateAccountDEK(ctx, user.ID); err != nil {
		t.Fatalf("create dek: %v", err)
	}

	if err := s.DestroyAccountDEK(ctx, user.ID); err != nil {
		t.Fatalf("destroy dek: %v", err)
	}

	// After crypto-shred the DEK is permanently unrecoverable.
	if _, err := s.GetOrCreateAccountDEK(ctx, user.ID); !errors.Is(err, ErrAccountKeyDestroyed) {
		t.Fatalf("err = %v, want ErrAccountKeyDestroyed", err)
	}

	// Idempotent: destroying again is a no-op.
	if err := s.DestroyAccountDEK(ctx, user.ID); err != nil {
		t.Fatalf("second destroy: %v", err)
	}
}

func mustUser(t *testing.T, s *Storage, email, sub string) *User {
	t.Helper()
	user, err := s.CreateUserWithIdentity(context.Background(), CreateUserWithIdentityInput{
		Email: email, EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: sub,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}
