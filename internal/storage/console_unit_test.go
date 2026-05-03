package storage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/kangheeyong/authgate/internal/clock"
)

// signTestToken returns a serialized RS256-signed JWT carrying the given claims.
func signTestToken(t *testing.T, key *rsa.PrivateKey, claims josejwt.Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	tok, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func newConsoleTestStore(t *testing.T) (*Storage, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	clk := &clock.FixedClock{T: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}
	s := &Storage{
		clock:        clk,
		signingKey:   key,
		signingKeyID: "kid-1",
		issuer:       "https://authgate.example.com",
	}
	return s, key
}

// #150: tokens whose `aud` is a resource URL (RFC 8707, used by MCP flows)
// must not be accepted on console APIs even though they share the same
// signing key as legitimate console tokens.
func TestValidateBearerToken_RejectsURLAudience(t *testing.T) {
	s, key := newConsoleTestStore(t)
	now := s.clock.Now()
	token := signTestToken(t, key, josejwt.Claims{
		Issuer:   "https://authgate.example.com",
		Subject:  "user-1",
		Audience: josejwt.Audience{"https://other-app.example.com/mcp"},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(15 * time.Minute)),
	})

	_, _, err := s.ValidateBearerTokenWithClientID(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected rejection of resource-URL audience")
	}
	if !strings.Contains(err.Error(), "resource-bound") {
		t.Fatalf("error = %v, want one mentioning resource-bound", err)
	}
}

// #150: a token signed with the same key but issued by a different authgate
// instance (or one whose issuer claim is otherwise wrong) must be rejected.
func TestValidateBearerToken_RejectsWrongIssuer(t *testing.T) {
	s, key := newConsoleTestStore(t)
	now := s.clock.Now()
	token := signTestToken(t, key, josejwt.Claims{
		Issuer:   "https://other-authgate.example.com",
		Subject:  "user-1",
		Audience: josejwt.Audience{"client-a"},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(15 * time.Minute)),
	})

	_, _, err := s.ValidateBearerTokenWithClientID(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected rejection of wrong issuer")
	}
}

// Tokens with no audience cannot be mapped to a client and must be rejected.
func TestValidateBearerToken_RejectsMissingAudience(t *testing.T) {
	s, key := newConsoleTestStore(t)
	now := s.clock.Now()
	token := signTestToken(t, key, josejwt.Claims{
		Issuer:   "https://authgate.example.com",
		Subject:  "user-1",
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(15 * time.Minute)),
	})

	_, _, err := s.ValidateBearerTokenWithClientID(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected rejection of missing aud")
	}
	if !strings.Contains(err.Error(), "aud") {
		t.Fatalf("error = %v, want one mentioning aud", err)
	}
}
