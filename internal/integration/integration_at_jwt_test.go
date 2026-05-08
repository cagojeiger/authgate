//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/storage"
)

// #187: RFC 9068 §2.1 mandates that JWT access tokens carry the JOSE
// header `typ=at+jwt`. Resource servers that strictly validate the
// profile reject tokens with `typ=JWT`, and the typ separation
// prevents an access token from being misinterpreted as an id_token.
// id_tokens MUST keep `typ=JWT` per OIDC Core 1.0 §2 — the headers
// must differ.
func TestAccessToken_TypIsAtJWTAndIDTokenStaysJWT(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	if _, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email: "atjwt@test.com", EmailVerified: true, Name: "AT JWT",
		AvatarURL: "", Provider: "google", ProviderUserID: "test-google-sub",
		ProviderEmail: "atjwt@test.com",
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	client := NewOAuthClient(t, ts.BaseURL)
	code := completeLoginFlowToCode(t, ts, client)
	tokens := client.ExchangeCode(code)
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("token exchange failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}
	if tokens.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if tokens.IDToken == "" {
		t.Fatal("expected non-empty id_token")
	}

	atTyp := jwtTyp(t, "access_token", tokens.AccessToken)
	if atTyp != "at+jwt" {
		t.Errorf("access_token typ = %q, want %q (RFC 9068 §2.1)", atTyp, "at+jwt")
	}

	idTyp := jwtTyp(t, "id_token", tokens.IDToken)
	if idTyp != "JWT" {
		t.Errorf("id_token typ = %q, want %q (OIDC Core 1.0 — separation from access_token)", idTyp, "JWT")
	}
}

// jwtTyp decodes the JOSE header of a compact JWS and returns the typ
// header value. Failures are reported via t.Fatalf rather than returned
// so callers don't need extra error handling on a malformed input.
func jwtTyp(t *testing.T, label, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("%s is not a compact JWS (got %d segments)", label, len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode %s header: %v", label, err)
	}
	var header struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("parse %s header: %v", label, err)
	}
	return header.Typ
}
