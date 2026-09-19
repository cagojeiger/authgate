//go:build integration

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/integration"
	"github.com/kangheeyong/authgate/internal/storage"
)

// Use the actual app registration with a real provider and storage. The
// integration helper's separate route assembly must not hide a wiring bypass.
func TestProviderRoutes_UserinfoWithRealProvider(t *testing.T) {
	ts := integration.SetupTestServer(t)
	ctx := context.Background()
	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "route@test.example", EmailVerified: true, Name: "Route", Provider: "google", ProviderUserID: "route-sub"})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := op.NewProvider(&op.Config{CryptoKey: sha256.Sum256([]byte("route-test-encryption"))}, ts.Store, op.StaticIssuer(ts.BaseURL), op.WithAllowInsecure())
	if err != nil {
		t.Fatal(err)
	}
	cfg := rateLimitTestConfig()
	cfg.PublicURL = ts.BaseURL
	mux := http.NewServeMux()
	registerProviderRoutes(mux, cfg, ts.Store, provider, newRouteLimiters(cfg))
	claims := oidc.NewAccessTokenClaims(ts.BaseURL, user.ID, []string{"test-client"}, time.Now().Add(time.Minute), "route-jti", "test-client", 0)
	claims.Scopes = []string{"openid"}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ts.Store.SigningKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"at+jwt", "JWT"} {
		t.Run(typ, func(t *testing.T) {
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: key.SignatureAlgorithm(), Key: &jose.JSONWebKey{Key: key.Key(), KeyID: key.ID()}}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			token, err := signed.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if typ == "JWT" {
				if rec.Code != 401 {
					t.Fatalf("ID-token type status %d", rec.Code)
				}
				return
			}
			var info map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
				t.Fatalf("userinfo %d: %s", rec.Code, rec.Body.String())
			}
			if rec.Code != 200 || info["sub"] != user.ID || len(info) != 1 {
				t.Fatalf("userinfo status=%d claims=%v", rec.Code, info)
			}
		})
	}
}
