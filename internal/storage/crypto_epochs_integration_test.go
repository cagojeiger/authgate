//go:build integration

package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/crypto"
)

func testKeys(t *testing.T, encKeyID string, encByte byte, lookupKeyID string, lookupByte byte) *crypto.Keys {
	t.Helper()
	mk := func(b byte) []byte {
		s := make([]byte, crypto.KeySize)
		for i := range s {
			s[i] = b
		}
		return s
	}
	enc, err := crypto.NewRoot(crypto.DomainEnc, encKeyID, mk(encByte))
	if err != nil {
		t.Fatalf("enc root: %v", err)
	}
	lookup, err := crypto.NewRoot(crypto.DomainLookup, lookupKeyID, mk(lookupByte))
	if err != nil {
		t.Fatalf("lookup root: %v", err)
	}
	keys, err := crypto.NewKeys(enc, lookup)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	return keys
}

func TestEnsureCryptoEpochs_CreatesAndIsIdempotent(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()
	s.SetKeys(testKeys(t, "enc-1", 0x11, "lkp-1", 0x22))

	if err := s.EnsureCryptoEpochs(ctx); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	// Exactly one active epoch per domain, with the configured key_id.
	for _, want := range []struct{ domain, keyID string }{{"enc", "enc-1"}, {"lookup", "lkp-1"}} {
		var keyID string
		var n int
		if err := s.DB().QueryRowContext(ctx,
			`SELECT count(*), max(key_id) FROM crypto_key_epochs WHERE domain=$1 AND status='active'`, want.domain,
		).Scan(&n, &keyID); err != nil {
			t.Fatalf("query %s: %v", want.domain, err)
		}
		if n != 1 || keyID != want.keyID {
			t.Fatalf("%s active epochs = %d key_id=%q, want 1 / %q", want.domain, n, keyID, want.keyID)
		}
	}

	// Re-ensure with the same keys is a no-op (idempotent).
	if err := s.EnsureCryptoEpochs(ctx); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
}

func TestEnsureCryptoEpochs_WrongSecretRejected(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()
	s.SetKeys(testKeys(t, "enc-1", 0x11, "lkp-1", 0x22))
	if err := s.EnsureCryptoEpochs(ctx); err != nil {
		t.Fatalf("seed ensure: %v", err)
	}

	// Same key_id, different root secret → verify_tag mismatch → startup fails.
	s.SetKeys(testKeys(t, "enc-1", 0x99, "lkp-1", 0x22))
	err := s.EnsureCryptoEpochs(ctx)
	if err == nil || !strings.Contains(err.Error(), "verify_tag mismatch") {
		t.Fatalf("err = %v, want verify_tag mismatch", err)
	}
}

func TestEnsureCryptoEpochs_DifferentActiveKeyIDRejected(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()
	s.SetKeys(testKeys(t, "enc-1", 0x11, "lkp-1", 0x22))
	if err := s.EnsureCryptoEpochs(ctx); err != nil {
		t.Fatalf("seed ensure: %v", err)
	}

	// A different active key_id (runtime rotation attempt) must be rejected.
	s.SetKeys(testKeys(t, "enc-2", 0x33, "lkp-1", 0x22))
	err := s.EnsureCryptoEpochs(ctx)
	if err == nil || !strings.Contains(err.Error(), "runtime rotation is not supported") {
		t.Fatalf("err = %v, want runtime rotation rejection", err)
	}
}

func TestEnsureCryptoEpochs_InertWhenUnset(t *testing.T) {
	s := testStorage(t)
	if err := s.EnsureCryptoEpochs(context.Background()); err != nil {
		t.Fatalf("inert ensure should no-op, got %v", err)
	}
	if s.Keys() != nil {
		t.Fatal("Keys() should be nil when unconfigured")
	}
}
