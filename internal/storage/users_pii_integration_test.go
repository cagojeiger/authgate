//go:build integration

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func encStorage(t *testing.T) *Storage {
	t.Helper()
	s := testStorage(t)
	s.SetKeys(testKeys(t, "enc-1", 0x11, "lkp-1", 0x22))
	if err := s.EnsureCryptoEpochs(context.Background()); err != nil {
		t.Fatalf("ensure epochs: %v", err)
	}
	return s
}

func TestUserPII_EncryptedSignupAndAllReadPaths(t *testing.T) {
	s := encStorage(t)
	ctx := context.Background()

	const email, name, sub = "Person@Example.com", "Alice", "sub-1"
	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: email, EmailVerified: true, Name: name, Provider: "google", ProviderUserID: sub,
	})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}

	// Plaintext columns NULL; ciphertext present and not containing the raw values.
	var ePlain, nPlain sql.NullString
	var eCT, nCT []byte
	if err := s.DB().QueryRowContext(ctx,
		`SELECT email, name, email_ciphertext, name_ciphertext FROM users WHERE id=$1`, user.ID,
	).Scan(&ePlain, &nPlain, &eCT, &nCT); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if ePlain.Valid || nPlain.Valid {
		t.Error("plaintext email/name should be NULL when encrypted")
	}
	if bytes.Contains(eCT, []byte(email)) || bytes.Contains(nCT, []byte(name)) {
		t.Error("ciphertext contains raw PII")
	}

	// Every user-returning read path must decrypt email + name.
	check := func(label string, u *User, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if u.Email != email || u.Name != name {
			t.Errorf("%s: email=%q name=%q, want %q/%q", label, u.Email, u.Name, email, name)
		}
	}
	byID, err := s.GetUserByID(ctx, user.ID)
	check("GetUserByID", byID, err)

	byProv, err := s.GetUserByProviderIdentity(ctx, "google", sub)
	check("GetUserByProviderIdentity", byProv, err)

	token, err := s.CreateSession(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	bySession, err := s.GetValidSession(ctx, token)
	check("GetValidSession", bySession, err)
}

func TestUserPII_EmailUniquenessNormalized(t *testing.T) {
	s := encStorage(t)
	ctx := context.Background()

	if _, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "dup@example.com", EmailVerified: true, Name: "A", Provider: "google", ProviderUserID: "s1",
	}); err != nil {
		t.Fatalf("first signup: %v", err)
	}
	// Same email with different case/whitespace normalizes to the same hash.
	_, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: "  DUP@Example.com ", EmailVerified: true, Name: "B", Provider: "google", ProviderUserID: "s2",
	})
	if !errors.Is(err, ErrEmailConflict) {
		t.Fatalf("err = %v, want ErrEmailConflict", err)
	}
}

func TestUserPII_Backfill(t *testing.T) {
	s := testStorage(t) // no keys → plaintext signup
	ctx := context.Background()

	const email, name, sub = "legacy@example.com", "Legacy", "legacy-sub"
	user, err := s.CreateUserWithIdentity(ctx, CreateUserWithIdentityInput{
		Email: email, EmailVerified: true, Name: name, Provider: "google", ProviderUserID: sub,
	})
	if err != nil {
		t.Fatalf("legacy signup: %v", err)
	}

	s.SetKeys(testKeys(t, "enc-1", 0x11, "lkp-1", 0x22))
	if err := s.EnsureCryptoEpochs(ctx); err != nil {
		t.Fatalf("ensure epochs: %v", err)
	}
	n, err := s.BackfillUserPII(ctx)
	if err != nil || n != 1 {
		t.Fatalf("backfill = %d err=%v, want 1", n, err)
	}
	remaining, err := s.UserPIIBackfillRemaining(ctx)
	if err != nil || remaining != 0 {
		t.Fatalf("remaining = %d err=%v, want 0", remaining, err)
	}

	// Backfill scrubs the plaintext columns (PII no longer at rest in clear).
	var ePlain, nPlain sql.NullString
	if err := s.DB().QueryRowContext(ctx,
		`SELECT email, name FROM users WHERE id=$1`, user.ID,
	).Scan(&ePlain, &nPlain); err != nil {
		t.Fatalf("read plaintext: %v", err)
	}
	if ePlain.Valid || nPlain.Valid {
		t.Error("plaintext email/name not cleared after backfill")
	}

	// Reads now decrypt the backfilled values.
	got, err := s.GetUserByID(ctx, user.ID)
	if err != nil || got.Email != email || got.Name != name {
		t.Fatalf("post-backfill read: %+v err=%v", got, err)
	}

	n2, err := s.BackfillUserPII(ctx)
	if err != nil || n2 != 0 {
		t.Fatalf("second backfill = %d err=%v, want 0", n2, err)
	}
}
