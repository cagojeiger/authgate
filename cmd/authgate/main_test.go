package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/handler"
)

func rateLimitTestConfig() *config.Config {
	return &config.Config{
		EnableMCP:           true,
		RateLimitAuthRPS:    1,
		RateLimitAuthBurst:  0,
		RateLimitTokenRPS:   1,
		RateLimitTokenBurst: 0,
	}
}

func assertRateLimited(t *testing.T, mux http.Handler, method, target string) {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("%s %s status = %d, want %d", method, target, rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("%s %s Retry-After = %q, want 1", method, target, got)
	}
}

func TestRegisterProviderRoutes_RateLimitsSensitiveOAuthEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("provider should not be reached when limiter rejects %s", r.URL.Path)
	})

	registerProviderRoutes(mux, rateLimitTestConfig(), nil, provider)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/oauth/token"},
		{http.MethodPost, "/oauth/revoke"},
		{http.MethodPost, "/oauth/introspect"},
		{http.MethodPost, "/oauth/device/authorize"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assertRateLimited(t, mux, tt.method, tt.path)
		})
	}
}

func TestRegisterAuthgateRoutes_RateLimitsSensitiveAuthgateEndpoints(t *testing.T) {
	mux := http.NewServeMux()

	registerAuthgateRoutes(
		mux,
		rateLimitTestConfig(),
		handler.NewLoginHandler(nil, true, "authgate"),
		handler.NewDeviceHandler(nil, true, "authgate"),
		handler.NewAccountHandler(nil, "http://authgate.example.com"),
		handler.NewMCPLoginHandler(nil, true, "authgate"),
		handler.NewConsoleHandler(nil),
	)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/login"},
		{http.MethodGet, "/login/callback"},
		{http.MethodGet, "/mcp/login"},
		{http.MethodGet, "/mcp/callback"},
		{http.MethodDelete, "/account"},
		{http.MethodPost, "/device/approve"},
		{http.MethodGet, "/device/auth/callback"},
		{http.MethodGet, "/console/clients"},
		{http.MethodGet, "/console/me/connections"},
		{http.MethodDelete, "/console/me/connections/client-a"},
		{http.MethodGet, "/console/me/sessions"},
		{http.MethodDelete, "/console/me/sessions/session-a"},
		{http.MethodPost, "/console/me/sessions/revoke-others"},
		{http.MethodGet, "/console/me/audit-log"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assertRateLimited(t, mux, tt.method, tt.path)
		})
	}
}
