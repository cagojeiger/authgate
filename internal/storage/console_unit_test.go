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
	return signTestTokenWithKID(t, key, "", claims)
}

// signTestTokenWithKID returns a serialized RS256-signed JWT with the given
// `kid` header (empty string omits the header).
func signTestTokenWithKID(t *testing.T, key *rsa.PrivateKey, kid string, claims josejwt.Claims) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		opts,
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

// #151: a 2-slot rotation (current + previous keys, both exposed via JWKS)
// must be honored on the console path. Tokens carrying `kid=previousKeyID`
// are signed with the previous key and must verify against it; tokens with
// an unknown `kid` must be rejected before signature verification.

func newConsoleTestStoreWithRotation(t *testing.T) (s *Storage, currentKey, previousKey *rsa.PrivateKey) {
	t.Helper()
	curr, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa current: %v", err)
	}
	prev, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa previous: %v", err)
	}
	clk := &clock.FixedClock{T: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}
	s = &Storage{
		clock:         clk,
		signingKey:    curr,
		signingKeyID:  "kid-current",
		previousKey:   prev,
		previousKeyID: "kid-previous",
		issuer:        "https://authgate.example.com",
	}
	return s, curr, prev
}

func TestValidateBearerToken_PreviousKeyAcceptedDuringRotation(t *testing.T) {
	// selectVerificationKey is what implements the kid-based fallback;
	// exercising it directly avoids the DB roundtrip that follows successful
	// signature verification.
	s, _, _ := newConsoleTestStoreWithRotation(t)
	tok := signedTestJWT(t, s.previousKey, "kid-previous")
	got, err := s.selectVerificationKey(tok)
	if err != nil {
		t.Fatalf("expected previous-key resolution to succeed, got %v", err)
	}
	if got != s.previousKey.Public() {
		t.Fatal("expected resolved key to equal s.previousKey.Public()")
	}
}

func TestValidateBearerToken_CurrentKIDResolvesCurrent(t *testing.T) {
	s, _, _ := newConsoleTestStoreWithRotation(t)
	tok := signedTestJWT(t, s.signingKey, "kid-current")
	got, err := s.selectVerificationKey(tok)
	if err != nil {
		t.Fatalf("expected current-key resolution to succeed, got %v", err)
	}
	if got != s.signingKey.Public() {
		t.Fatal("expected resolved key to equal s.signingKey.Public()")
	}
}

func TestValidateBearerToken_EmptyKIDFallsBackToCurrent(t *testing.T) {
	s, _, _ := newConsoleTestStoreWithRotation(t)
	tok := signedTestJWT(t, s.signingKey, "")
	got, err := s.selectVerificationKey(tok)
	if err != nil {
		t.Fatalf("expected empty-kid fallback to succeed, got %v", err)
	}
	if got != s.signingKey.Public() {
		t.Fatal("expected empty-kid fallback to resolve to current key")
	}
}

func signedTestJWT(t *testing.T, key *rsa.PrivateKey, kid string) *josejwt.JSONWebToken {
	t.Helper()
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	raw := signTestTokenWithKID(t, key, kid, josejwt.Claims{
		Issuer:   "https://authgate.example.com",
		Subject:  "user-1",
		Audience: josejwt.Audience{"client-a"},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(15 * time.Minute)),
	})
	tok, err := josejwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tok
}

func TestValidateBearerToken_UnknownKIDRejected(t *testing.T) {
	s, curr, _ := newConsoleTestStoreWithRotation(t)
	now := s.clock.Now()
	token := signTestTokenWithKID(t, curr, "kid-attacker", josejwt.Claims{
		Issuer:   "https://authgate.example.com",
		Subject:  "user-1",
		Audience: josejwt.Audience{"client-a"},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(15 * time.Minute)),
	})

	_, _, err := s.ValidateBearerTokenWithClientID(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected rejection of unknown kid")
	}
	if !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("error = %v, want one mentioning unknown key", err)
	}
}

func TestValidateBearerToken_KIDSignedByOtherKeyRejected(t *testing.T) {
	// Token carries kid=current but is actually signed with the previous key.
	s, _, prev := newConsoleTestStoreWithRotation(t)
	now := s.clock.Now()
	token := signTestTokenWithKID(t, prev, "kid-current", josejwt.Claims{
		Issuer:   "https://authgate.example.com",
		Subject:  "user-1",
		Audience: josejwt.Audience{"client-a"},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(15 * time.Minute)),
	})

	_, _, err := s.ValidateBearerTokenWithClientID(context.Background(), "Bearer "+token)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("error = %v, want one mentioning signature", err)
	}
}
