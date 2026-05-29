//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"

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
		Provider: "google", ProviderUserID: "test-google-sub",
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

// #187 (refresh grant): the at+jwt typ rewrite must also apply to access
// tokens minted via the refresh_token grant. Same code path through
// /oauth/token, but worth exercising explicitly so the wrapper isn't
// inadvertently bypassed by a future refactor that splits the routes.
func TestRefreshGrant_AccessTokenTypIsAtJWT(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	if _, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email: "atjwt-refresh@test.com", EmailVerified: true, Name: "AT JWT Refresh",
		Provider: "google", ProviderUserID: "test-google-sub",
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	client := NewOAuthClient(t, ts.BaseURL)
	code := completeLoginFlowToCode(t, ts, client)
	first := client.ExchangeCode(code)
	if first.StatusCode != http.StatusOK || first.RefreshToken == "" {
		t.Fatalf("first exchange: status=%d body=%s", first.StatusCode, first.RawBody)
	}

	refreshed := client.RefreshToken(first.RefreshToken)
	if refreshed.StatusCode != http.StatusOK {
		t.Fatalf("refresh: status=%d body=%s", refreshed.StatusCode, refreshed.RawBody)
	}
	if refreshed.AccessToken == "" {
		t.Fatal("expected non-empty refreshed access_token")
	}
	if got := jwtTyp(t, "refreshed access_token", refreshed.AccessToken); got != "at+jwt" {
		t.Errorf("refreshed access_token typ = %q, want at+jwt", got)
	}
}

// #187 (device grant): same invariant for tokens minted from a
// device-code grant. Different grant_type in the same /oauth/token
// handler — guard against a future grant-specific bypass.
func TestDeviceGrant_AccessTokenTypIsAtJWT(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email: "atjwt-device@test.com", EmailVerified: true, Name: "AT JWT Device",
		Provider: "google", ProviderUserID: "test-google-sub",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	authz := startDeviceAuthorization(t, ts)
	if err := ts.Store.ApproveDeviceCode(ctx, authz.UserCode, user.ID); err != nil {
		t.Fatalf("approve device code: %v", err)
	}
	result := pollDeviceToken(t, ts, authz.DeviceCode)
	if result.StatusCode != http.StatusOK {
		t.Fatalf("device token exchange: status=%d body=%s", result.StatusCode, result.RawBody)
	}
	if result.AccessToken == "" {
		t.Fatal("expected non-empty device-grant access_token")
	}
	if got := jwtTyp(t, "device-grant access_token", result.AccessToken); got != "at+jwt" {
		t.Errorf("device-grant access_token typ = %q, want at+jwt", got)
	}
}

// #265-followup: the access_token is re-signed (typ=at+jwt) after zitadel
// computes the id_token's at_hash over the original token string. If the
// id_token isn't re-bound, at_hash hashes the stale token and strict OIDC
// clients (OIDC Core 1.0 §3.1.3.6) reject the response on at_hash mismatch.
func TestIDTokenAtHashMatchesRewrittenAccessToken(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	if _, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email: "athash@test.com", EmailVerified: true, Name: "AT Hash",
		Provider: "google", ProviderUserID: "test-google-sub",
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	client := NewOAuthClient(t, ts.BaseURL)
	code := completeLoginFlowToCode(t, ts, client)
	tokens := client.ExchangeCode(code)
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("token exchange failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}

	assertAtHashBinds(t, tokens.IDToken, tokens.AccessToken)
}

// TestRefreshGrant_IDTokenAtHashMatches guards the same invariant on the
// refresh_token grant, which also returns an id_token through the rewrite.
func TestRefreshGrant_IDTokenAtHashMatches(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	if _, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email: "athash-refresh@test.com", EmailVerified: true, Name: "AT Hash Refresh",
		Provider: "google", ProviderUserID: "test-google-sub",
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	client := NewOAuthClient(t, ts.BaseURL)
	code := completeLoginFlowToCode(t, ts, client)
	first := client.ExchangeCode(code)
	if first.StatusCode != http.StatusOK || first.RefreshToken == "" {
		t.Fatalf("first exchange: status=%d body=%s", first.StatusCode, first.RawBody)
	}

	refreshed := client.RefreshToken(first.RefreshToken)
	if refreshed.StatusCode != http.StatusOK {
		t.Fatalf("refresh: status=%d body=%s", refreshed.StatusCode, refreshed.RawBody)
	}
	if refreshed.IDToken == "" {
		t.Skip("refresh response carried no id_token; nothing to bind")
	}
	assertAtHashBinds(t, refreshed.IDToken, refreshed.AccessToken)
}

// assertAtHashBinds fails unless the id_token carries an at_hash claim that
// equals oidc.ClaimHash(accessToken) under the id_token's signing alg.
func assertAtHashBinds(t *testing.T, idToken, accessToken string) {
	t.Helper()
	if idToken == "" || accessToken == "" {
		t.Fatalf("missing tokens: id_token empty=%v access_token empty=%v", idToken == "", accessToken == "")
	}

	alg := jose.SignatureAlgorithm(jwtAlg(t, idToken))
	want, err := oidc.ClaimHash(accessToken, alg)
	if err != nil {
		t.Fatalf("compute expected at_hash: %v", err)
	}

	claims := jwtPayloadMap(t, idToken)
	got, ok := claims["at_hash"].(string)
	if !ok {
		t.Fatalf("id_token has no at_hash claim (claims: %v)", claims)
	}
	if got != want {
		t.Errorf("id_token at_hash = %q, want %q (must bind the rewritten access_token)", got, want)
	}
}

// jwtAlg returns the alg JOSE header of a compact JWS.
func jwtAlg(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS (got %d segments)", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	return header.Alg
}

// jwtPayloadMap decodes and returns the payload claims of a compact JWS.
func jwtPayloadMap(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS (got %d segments)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	return claims
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
