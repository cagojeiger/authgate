package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	testClientID     = "test-client"
	testClientSecret = "test-secret"
	testRedirectURI  = "http://localhost/callback"
)

// fakeIdP is an in-process OIDC IdP for testing OIDCProvider without external dependencies.
// Uses httptest.Server so no network, no Docker, no build tags required.
type fakeIdP struct {
	srv            *httptest.Server
	key            *rsa.PrivateKey
	keyID          string
	userInfoResp   map[string]any
	tokenStatus    int // non-zero overrides token endpoint HTTP status
	userinfoStatus int // non-zero overrides userinfo endpoint HTTP status
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	idp := &fakeIdP{
		key:   key,
		keyID: "test-key-1",
		userInfoResp: map[string]any{
			"sub":            "test-sub",
			"email":          "test@example.com",
			"email_verified": true,
			"name":           "Test User",
			"picture":        "https://example.com/photo.jpg",
		},
	}

	mux := http.NewServeMux()
	var srvURL string // set after server starts; handlers close over it

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srvURL,
			"authorization_endpoint":                srvURL + "/authorize",
			"token_endpoint":                        srvURL + "/token",
			"jwks_uri":                              srvURL + "/keys",
			"userinfo_endpoint":                     srvURL + "/userinfo",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:       &idp.key.PublicKey,
					KeyID:     idp.keyID,
					Algorithm: string(jose.RS256),
					Use:       "sig",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if idp.tokenStatus != 0 {
			http.Error(w, "token error", idp.tokenStatus)
			return
		}

		sig, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: idp.key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", idp.keyID),
		)
		if err != nil {
			http.Error(w, "signer error", http.StatusInternalServerError)
			return
		}

		sub, _ := idp.userInfoResp["sub"].(string)
		now := time.Now()
		idToken, err := jwt.Signed(sig).Claims(map[string]any{
			"iss": srvURL,
			"sub": sub,
			"aud": testClientID,
			"exp": now.Add(5 * time.Minute).Unix(),
			"iat": now.Unix(),
		}).Serialize()
		if err != nil {
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"id_token":     idToken,
			"expires_in":   300,
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if idp.userinfoStatus != 0 {
			http.Error(w, "userinfo error", idp.userinfoStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(idp.userInfoResp)
	})

	idp.srv = httptest.NewServer(mux)
	srvURL = idp.srv.URL
	t.Cleanup(idp.srv.Close)

	return idp
}

func (idp *fakeIdP) newProvider(t *testing.T) *OIDCProvider {
	t.Helper()
	p, err := NewOIDCProvider(context.Background(), idp.srv.URL, testClientID, testClientSecret, testRedirectURI)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	return p
}

// ── oidc-name-001~003: deriveProviderName ────────────────────────────────────

func TestDeriveProviderName_Google(t *testing.T) {
	if got := deriveProviderName("https://accounts.google.com"); got != "google" {
		t.Errorf("got %q, want %q", got, "google")
	}
}

func TestDeriveProviderName_Localhost(t *testing.T) {
	if got := deriveProviderName("http://localhost:8082"); got != "localhost" {
		t.Errorf("got %q, want %q", got, "localhost")
	}
}

func TestDeriveProviderName_Microsoft(t *testing.T) {
	if got := deriveProviderName("https://login.microsoftonline.com"); got != "microsoftonline" {
		t.Errorf("got %q, want %q", got, "microsoftonline")
	}
}

func TestDeriveProviderName_InvalidURL(t *testing.T) {
	if got := deriveProviderName("not-a-url"); got != "unknown" {
		t.Errorf("got %q, want %q", got, "unknown")
	}
}

// ── oidc-disc-001: Discovery success ─────────────────────────────────────────

func TestOIDCProvider_Discovery_Success(t *testing.T) {
	idp := newFakeIdP(t)
	p, err := NewOIDCProvider(context.Background(), idp.srv.URL, testClientID, testClientSecret, testRedirectURI)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if p.Name() == "" {
		t.Error("Name() is empty after successful Discovery")
	}
	if p.AuthURL("state-001") == "" {
		t.Error("AuthURL() is empty after successful Discovery")
	}
}

// ── oidc-disc-002: Discovery server unreachable ───────────────────────────────

func TestOIDCProvider_Discovery_Unreachable(t *testing.T) {
	_, err := NewOIDCProvider(context.Background(), "http://127.0.0.1:1", testClientID, testClientSecret, testRedirectURI)
	if err == nil {
		t.Error("expected error for unreachable server, got nil")
	}
}

// ── oidc-disc-003: Discovery server returns non-200 ──────────────────────────

func TestOIDCProvider_Discovery_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := NewOIDCProvider(context.Background(), srv.URL, testClientID, testClientSecret, testRedirectURI)
	if err == nil {
		t.Error("expected error for 500 discovery response, got nil")
	}
}

// ── oidc-auth-001: AuthURL contains required OAuth2 parameters ────────────────

func TestOIDCProvider_AuthURL_ContainsRequiredParams(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.newProvider(t)
	u := p.AuthURL("req-state-123")
	for _, param := range []string{"client_id", "redirect_uri", "response_type", "state"} {
		if !strings.Contains(u, param) {
			t.Errorf("AuthURL missing param %q: %s", param, u)
		}
	}
}

// ── oidc-exchange-001: normal code exchange ───────────────────────────────────

func TestOIDCProvider_Exchange_Success(t *testing.T) {
	idp := newFakeIdP(t)
	p := idp.newProvider(t)
	info, err := p.Exchange(context.Background(), "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.Sub != "test-sub" {
		t.Errorf("Sub = %q, want test-sub", info.Sub)
	}
	if info.Email != "test@example.com" {
		t.Errorf("Email = %q", info.Email)
	}
	if info.Name != "Test User" {
		t.Errorf("Name = %q", info.Name)
	}
}

// ── oidc-exchange-002: token endpoint error ───────────────────────────────────

func TestOIDCProvider_Exchange_TokenEndpointError(t *testing.T) {
	idp := newFakeIdP(t)
	idp.tokenStatus = http.StatusUnauthorized
	p := idp.newProvider(t)
	_, err := p.Exchange(context.Background(), "any-code")
	if err == nil {
		t.Error("expected error for token endpoint 401, got nil")
	}
}

// ── oidc-exchange-003: userinfo endpoint error ────────────────────────────────

func TestOIDCProvider_Exchange_UserInfoError(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userinfoStatus = http.StatusUnauthorized
	p := idp.newProvider(t)
	_, err := p.Exchange(context.Background(), "fake-code")
	if err == nil {
		t.Error("expected error for userinfo endpoint 401, got nil")
	}
}

// ── oidc-map-001: all fields mapped correctly ─────────────────────────────────

func TestOIDCProvider_UserInfoMapping_AllFields(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userInfoResp = map[string]any{
		"sub":            "map-sub",
		"email":          "map@example.com",
		"email_verified": true,
		"name":           "Map User",
		"picture":        "https://example.com/pic.jpg",
	}
	p := idp.newProvider(t)
	info, err := p.Exchange(context.Background(), "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.Sub != "map-sub" {
		t.Errorf("Sub = %q, want map-sub", info.Sub)
	}
	if info.Email != "map@example.com" {
		t.Errorf("Email = %q", info.Email)
	}
	if !info.EmailVerified {
		t.Error("EmailVerified = false, want true")
	}
	if info.Name != "Map User" {
		t.Errorf("Name = %q", info.Name)
	}
	if info.Picture != "https://example.com/pic.jpg" {
		t.Errorf("Picture = %q", info.Picture)
	}
}

// ── oidc-map-002 (P0): email_verified=true regression ────────────────────────
// Guards against the prior bug where email_verified was always false due to
// missing JSON tags on the old upstream.UserInfo struct.

func TestOIDCProvider_EmailVerified_True(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userInfoResp["email_verified"] = true
	p := idp.newProvider(t)
	info, err := p.Exchange(context.Background(), "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !info.EmailVerified {
		t.Error("email_verified=true returned by IdP but UserInfo.EmailVerified=false (regression)")
	}
}

// ── oidc-map-003: email_verified=false ───────────────────────────────────────

func TestOIDCProvider_EmailVerified_False(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userInfoResp["email_verified"] = false
	p := idp.newProvider(t)
	info, err := p.Exchange(context.Background(), "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.EmailVerified {
		t.Error("email_verified=false returned by IdP but UserInfo.EmailVerified=true")
	}
}

// ── oidc-map-004: email_verified absent → defaults to false ──────────────────

func TestOIDCProvider_EmailVerified_Absent(t *testing.T) {
	idp := newFakeIdP(t)
	delete(idp.userInfoResp, "email_verified")
	p := idp.newProvider(t)
	info, err := p.Exchange(context.Background(), "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.EmailVerified {
		t.Error("email_verified absent in IdP response but UserInfo.EmailVerified=true")
	}
}

// ── oidc-map-005: picture field mapped ───────────────────────────────────────

func TestOIDCProvider_Picture_Mapped(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userInfoResp["picture"] = "https://example.com/avatar.jpg"
	p := idp.newProvider(t)
	info, err := p.Exchange(context.Background(), "fake-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.Picture != "https://example.com/avatar.jpg" {
		t.Errorf("Picture = %q, want https://example.com/avatar.jpg", info.Picture)
	}
}

// ── oidc-e2e-001: full path Discovery → AuthURL → Exchange → UserInfo ─────────

func TestOIDCProvider_FullPath(t *testing.T) {
	idp := newFakeIdP(t)

	p, err := NewOIDCProvider(context.Background(), idp.srv.URL, testClientID, testClientSecret, testRedirectURI)
	if err != nil {
		t.Fatalf("Discovery: %v", err)
	}

	authURL := p.AuthURL("full-path-state")
	if !strings.Contains(authURL, "full-path-state") {
		t.Errorf("AuthURL does not contain state: %s", authURL)
	}

	info, err := p.Exchange(context.Background(), "full-path-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if info.Sub == "" || info.Email == "" {
		t.Errorf("incomplete UserInfo after full path: sub=%q email=%q", info.Sub, info.Email)
	}
}

func TestOIDCProvider_MultiRedirectURIs(t *testing.T) {
	idp := newFakeIdP(t)

	tests := []struct {
		name        string
		redirectURI string
	}{
		{name: "browser", redirectURI: "http://localhost:8080/login/callback"},
		{name: "mcp", redirectURI: "http://localhost:8080/mcp/callback"},
		{name: "device", redirectURI: "http://localhost:8080/device/auth/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewOIDCProvider(context.Background(), idp.srv.URL, testClientID, testClientSecret, tt.redirectURI)
			if err != nil {
				t.Fatalf("NewOIDCProvider: %v", err)
			}

			authURL := p.AuthURL("state-" + tt.name)
			u, err := url.Parse(authURL)
			if err != nil {
				t.Fatalf("parse authURL: %v", err)
			}
			if got := u.Query().Get("redirect_uri"); got != tt.redirectURI {
				t.Fatalf("redirect_uri = %q, want %q", got, tt.redirectURI)
			}
		})
	}
}
