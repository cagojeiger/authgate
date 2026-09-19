package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestTokenCallbacksRequireVerifiedClaims(t *testing.T) {
	store := new(Storage) // No DB access is allowed before token verification.
	if err := store.SetUserinfoFromToken(context.Background(), &oidc.UserInfo{}, "jti", "sub", ""); err == nil {
		t.Fatal("unverified userinfo accepted")
	}
	if err := store.SetIntrospectionFromToken(context.Background(), &oidc.IntrospectionResponse{}, "jti", "sub", "client"); err == nil {
		t.Fatal("unverified introspection accepted")
	}
}

func TestAccessTokenRewriteFailsClosed(t *testing.T) {
	for _, body := range []string{`{"access_token":"broken","refresh_token":"secret"}`, `{"access_token":"!.!.!","id_token":"secret"}`, `invalid json`} {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
		rec := httptest.NewRecorder()
		WrapAccessTokenJWTType(next, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth/token", nil))
		if rec.Code != 500 || strings.Contains(rec.Body.String(), "secret") || rec.Body.String() != `{"error":"server_error"}` {
			t.Fatalf("rewrite response: %d %s", rec.Code, rec.Body.String())
		}
	}
}
