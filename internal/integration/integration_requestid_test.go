//go:build integration

package integration

import (
	"net/http"
	"regexp"
	"testing"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// TestRequestIDMiddleware verifies X-Request-ID header behavior.
func TestRequestIDMiddleware(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{EnableMCP: false})

	t.Run("auto-generates UUID when X-Request-ID header is absent", func(t *testing.T) {
		resp, err := http.Get(ts.BaseURL + "/health")
		if err != nil {
			t.Fatalf("GET /health: %v", err)
		}
		defer resp.Body.Close()

		got := resp.Header.Get("X-Request-ID")
		if got == "" {
			t.Fatal("X-Request-ID header missing from response")
		}
		if !uuidPattern.MatchString(got) {
			t.Errorf("X-Request-ID %q is not a valid UUID", got)
		}
	})

	t.Run("echoes back X-Request-ID when provided by client", func(t *testing.T) {
		const clientID = "my-trace-123"
		req, err := http.NewRequest(http.MethodGet, ts.BaseURL+"/health", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("X-Request-ID", clientID)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /health: %v", err)
		}
		defer resp.Body.Close()

		got := resp.Header.Get("X-Request-ID")
		if got != clientID {
			t.Errorf("X-Request-ID: want %q, got %q", clientID, got)
		}
	})
}
