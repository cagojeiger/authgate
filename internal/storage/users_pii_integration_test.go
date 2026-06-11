//go:build integration

package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func encStorage(t *testing.T) *Storage {
	t.Helper()
	return testStorage(t)
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

	// Ciphertext present and not containing the raw values.
	var eCT, nCT []byte
	if err := s.DB().QueryRowContext(ctx,
		`SELECT email_ciphertext, name_ciphertext FROM users WHERE id=$1`, user.ID,
	).Scan(&eCT, &nCT); err != nil {
		t.Fatalf("read row: %v", err)
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
