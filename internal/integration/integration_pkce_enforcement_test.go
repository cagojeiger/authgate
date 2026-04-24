//go:build integration

package integration

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestPKCEEnforcement(t *testing.T) {
	t.Run("authorize without code_challenge returns invalid_request", func(t *testing.T) {
		ts := SetupTestServer(t)
		client := NewOAuthClient(t, ts.BaseURL)

		noFollow := *client.Client
		noFollow.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		resp, err := noFollow.Get(client.AuthorizeURLNoPKCE())
		if err != nil {
			t.Fatalf("authorize without pkce: %v", err)
		}
		defer resp.Body.Close()

		if loc := resp.Header.Get("Location"); loc != "" {
			u, parseErr := url.Parse(loc)
			if parseErr != nil {
				t.Fatalf("parse location: %v", parseErr)
			}
			if got := u.Query().Get("error"); got != "invalid_request" {
				t.Fatalf("expected error=invalid_request in redirect, got %q (location=%s)", got, loc)
			}
			return
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "invalid_request") {
			t.Fatalf("expected invalid_request in response body, status=%d body=%s", resp.StatusCode, string(body))
		}
	})

	t.Run("authorize with S256 code_challenge succeeds", func(t *testing.T) {
		ts := SetupTestServer(t)
		client := NewOAuthClient(t, ts.BaseURL)

		code := completeLoginFlowToCode(t, ts, client)
		if code == "" {
			t.Fatal("expected authorization code from redirect without error")
		}
	})
}
