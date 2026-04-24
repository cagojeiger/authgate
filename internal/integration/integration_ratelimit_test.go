//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestRateLimiting verifies that rapid burst requests to /oauth/token trigger HTTP 429.
func TestRateLimiting(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{EnableMCP: false})

	data := url.Values{
		"grant_type": {"password"},
		"client_id":  {"test-client"},
		"username":   {"notreal@example.com"},
		"password":   {"wrong"},
	}
	body := data.Encode()

	got429 := false
	const attempts = 50
	for i := 0; i < attempts; i++ {
		resp, err := http.Post(
			ts.BaseURL+"/oauth/token",
			"application/x-www-form-urlencoded",
			strings.NewReader(body),
		)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}

	if !got429 {
		t.Errorf("expected at least one 429 response after %d rapid requests to /oauth/token, got none", attempts)
	}
}
