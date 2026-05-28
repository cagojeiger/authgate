package app

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/handler"
)

func rateLimitTestConfig() *config.Config {
	return &config.Config{
		EnableMCP:           true,
		RateLimitAuthRPS:    1,
		RateLimitAuthBurst:  1,
		RateLimitTokenRPS:   1,
		RateLimitTokenBurst: 1,
	}
}

func TestRegisterHealthRoutes_DoesNotExposeMetricsOnPublicMux(t *testing.T) {
	mux := http.NewServeMux()
	registerHealthRoutes(mux, nil, &atomic.Bool{})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /metrics status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func assertRateLimited(t *testing.T, mux http.Handler, method, target string) {
	t.Helper()

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(method, target, nil)
		rec := httptest.NewRecorder()
		panicked := serveHTTPRecovering(mux, rec, req)

		if i == 0 {
			if rec.Code == http.StatusTooManyRequests {
				t.Fatalf("%s %s first request was unexpectedly rate limited", method, target)
			}
			continue
		}
		if panicked {
			t.Fatalf("%s %s second request reached handler instead of being rate limited", method, target)
		}
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("%s %s second request status = %d, want %d", method, target, rec.Code, http.StatusTooManyRequests)
		}
		if got := rec.Header().Get("Retry-After"); got != "1" {
			t.Fatalf("%s %s Retry-After = %q, want 1", method, target, got)
		}
	}
}

func serveHTTPRecovering(h http.Handler, rec *httptest.ResponseRecorder, req *http.Request) (panicked bool) {
	// The first request intentionally consumes a realistic burst token and may
	// reach nil-backed handlers in this route-wiring test. The second request
	// must be rejected by the limiter before any handler code runs.
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	h.ServeHTTP(rec, req)
	return false
}

func TestRegisterProviderRoutes_RateLimitsSensitiveOAuthEndpoints(t *testing.T) {
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
			mux := http.NewServeMux()
			provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			registerProviderRoutes(mux, rateLimitTestConfig(), nil, provider)

			assertRateLimited(t, mux, tt.method, tt.path)
		})
	}
}

func TestRegisterAuthgateRoutes_RateLimitsSensitiveAuthgateEndpoints(t *testing.T) {
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/login"},
		{http.MethodGet, "/login/callback"},
		{http.MethodGet, "/mcp/login"},
		{http.MethodGet, "/mcp/callback"},
		{http.MethodDelete, "/account"},
		{http.MethodGet, "/device"},
		{http.MethodPost, "/device/approve"},
		{http.MethodGet, "/device/auth/callback"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			mux := http.NewServeMux()
			registerAuthgateRoutes(
				mux,
				rateLimitTestConfig(),
				handler.NewLoginHandler(nil, nil, true, "authgate"),
				handler.NewDeviceHandler(nil, nil, true, "authgate"),
				handler.NewAccountHandler(nil, "http://authgate.example.com"),
				handler.NewMCPLoginHandler(nil, nil, true, "authgate"),
			)

			assertRateLimited(t, mux, tt.method, tt.path)
		})
	}
}
