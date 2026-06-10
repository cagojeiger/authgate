//go:build integration

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"testing"

	"github.com/kangheeyong/authgate/internal/crypto"
)

func TestProviderSub_EncryptedOnSignupAndLookup(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()
	keys := testKeys(t, "enc-1", 0x11, "lkp-1", 0x22)
	s.SetKeys(keys)
	if err := s.EnsureCryptoEpochs(ctx); err != nil {
		t.Fatalf("ensure epochs: %v", err)
	}

	const sub = "google-sub-xyz-123"
	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "ps@test.com", EmailVerified: true, Name: "PS", Provider: "google", ProviderUserID: sub,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Plaintext provider_user_id must be NULL; hash + ciphertext present and not raw.
	var pUID, hash sql.NullString
	var ct, nonce []byte
	if err := s.DB().QueryRowContext(ctx,
		`SELECT provider_user_id, provider_sub_hash, provider_sub_ciphertext, provider_sub_nonce
		 FROM user_identities WHERE user_id = $1`, user.ID,
	).Scan(&pUID, &hash, &ct, &nonce); err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if pUID.Valid {
		t.Error("provider_user_id should be NULL when encrypted")
	}
	if !hash.Valid || hash.String == "" {
		t.Error("provider_sub_hash missing")
	}
	if bytes.Contains(ct, []byte(sub)) {
		t.Error("ciphertext contains the raw provider sub")
	}

	// Ciphertext decrypts back to the original sub (with the bound AAD).
	aad := crypto.FieldAAD(providerSubAADField, user.ID, keys.EncKeyID(), providerSubVersion)
	got, err := keys.DecryptPII(ct, nonce, aad)
	if err != nil || string(got) != sub {
		t.Fatalf("decrypt = %q err=%v, want %q", got, err, sub)
	}

	// Login matching works (lookup goes through the hash internally).
	found, err := s.GetUserByProviderIdentity(ctx, "google", sub)
	if err != nil || found.ID != user.ID {
		t.Fatalf("lookup by sub: id=%v err=%v, want %v", found, err, user.ID)
	}
	if _, err := s.GetUserByProviderIdentity(ctx, "google", "not-a-sub"); err != ErrNotFound {
		t.Errorf("lookup wrong sub err=%v, want ErrNotFound", err)
	}
}

func TestProviderSub_Backfill(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	// Legacy plaintext identity (no keys → plaintext path).
	const sub = "legacy-sub-789"
	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "legacy@test.com", EmailVerified: true, Name: "L", Provider: "google", ProviderUserID: sub,
	})
	if err != nil {
		t.Fatalf("create legacy: %v", err)
	}

	// Configure keys and backfill.
	s.SetKeys(testKeys(t, "enc-1", 0x11, "lkp-1", 0x22))
	if err := s.EnsureCryptoEpochs(ctx); err != nil {
		t.Fatalf("ensure epochs: %v", err)
	}
	n, err := s.BackfillProviderSub(ctx)
	if err != nil || n != 1 {
		t.Fatalf("backfill = %d err=%v, want 1", n, err)
	}
	remaining, err := s.ProviderSubBackfillRemaining(ctx)
	if err != nil || remaining != 0 {
		t.Fatalf("remaining = %d err=%v, want 0", remaining, err)
	}

	// Backfill scrubs the plaintext provider_user_id.
	var pUID sql.NullString
	if err := s.DB().QueryRowContext(ctx,
		`SELECT provider_user_id FROM user_identities WHERE user_id=$1`, user.ID,
	).Scan(&pUID); err != nil {
		t.Fatalf("read plaintext: %v", err)
	}
	if pUID.Valid {
		t.Error("plaintext provider_user_id not cleared after backfill")
	}

	// Lookup now resolves via hash even though the row was created as plaintext.
	found, err := s.GetUserByProviderIdentity(ctx, "google", sub)
	if err != nil || found.ID != user.ID {
		t.Fatalf("post-backfill lookup: id=%v err=%v", found, err)
	}

	// Idempotent: a second backfill touches nothing.
	n2, err := s.BackfillProviderSub(ctx)
	if err != nil || n2 != 0 {
		t.Fatalf("second backfill = %d err=%v, want 0", n2, err)
	}
}
