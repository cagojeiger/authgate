//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/middleware"
)

// TestCORSHeaders verifies CORS header behavior for token endpoints.
func TestCORSHeaders(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{EnableMCP: false})

	// The test client's redirect URI is srv.URL+"/callback", so the allowed
	// origin is the scheme+host of that URI — which equals ts.BaseURL.
	allowedOrigin := ts.BaseURL
	unknownOrigin := "https://evil.example.com"

	t.Run("preflight OPTIONS to /oauth/token with allowed origin returns 204 and CORS headers", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodOptions, ts.BaseURL+"/oauth/token", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Origin", allowedOrigin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type")

		client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("preflight status: want 204, got %d", resp.StatusCode)
		}
		assertCORSHeaders(t, resp, allowedOrigin)
	})

	t.Run("POST to /oauth/token with allowed origin includes CORS headers", func(t *testing.T) {
		body := strings.NewReader("grant_type=authorization_code&client_id=test-client&code=invalid&redirect_uri=" + ts.BaseURL + "/callback")
		req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/oauth/token", body)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", allowedOrigin)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /oauth/token: %v", err)
		}
		defer resp.Body.Close()

		// The request may fail (bad code) — we only care about CORS headers.
		got := resp.Header.Get("Access-Control-Allow-Origin")
		if got != allowedOrigin {
			t.Errorf("Access-Control-Allow-Origin: want %q, got %q", allowedOrigin, got)
		}
	})

	t.Run("POST to /oauth/token with unknown origin has no CORS headers", func(t *testing.T) {
		body := strings.NewReader("grant_type=authorization_code&client_id=test-client&code=invalid&redirect_uri=" + ts.BaseURL + "/callback")
		req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/oauth/token", body)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", unknownOrigin)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /oauth/token: %v", err)
		}
		defer resp.Body.Close()

		got := resp.Header.Get("Access-Control-Allow-Origin")
		if got != "" {
			t.Errorf("Access-Control-Allow-Origin: want empty for unknown origin, got %q", got)
		}
	})
}

func assertCORSHeaders(t *testing.T, resp *http.Response, expectedOrigin string) {
	t.Helper()
	checks := []struct {
		header string
		want   string
	}{
		{"Access-Control-Allow-Origin", expectedOrigin},
		{"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
		{"Access-Control-Allow-Headers", "Content-Type, Authorization"},
		{"Access-Control-Allow-Credentials", "true"},
	}
	for _, c := range checks {
		got := resp.Header.Get(c.header)
		if got != c.want {
			t.Errorf("%s: want %q, got %q", c.header, c.want, got)
		}
	}
}

// Ensure OriginsFromRedirectURIs is importable from this package (compile check).
var _ = middleware.OriginsFromRedirectURIs
