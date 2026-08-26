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
			if got := u.Query().Get("iss"); got != ts.BaseURL {
				t.Fatalf("authorization response iss = %q, want %q", got, ts.BaseURL)
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

// A confidential client may waive PKCE via skip_pkce. This exists for OIDC
// libraries that cannot send code_challenge — Gitea's goth openidConnect
// provider has no PKCE support at all.
func TestPKCESkipForConfidentialClient(t *testing.T) {
	t.Run("authorize without code_challenge is accepted", func(t *testing.T) {
		ts := SetupTestServer(t)
		client := NewOAuthClientFor(t, ts.BaseURL, "skip-pkce-client", "/login/callback")

		noFollow := *client.Client
		noFollow.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		resp, err := noFollow.Get(client.AuthorizeURLNoPKCE())
		if err != nil {
			t.Fatalf("authorize without pkce: %v", err)
		}
		defer resp.Body.Close()

		// Assert the success shape, not the absence of one error string. A
		// waived request that still failed — for any reason, with any body —
		// has to fail this test, so the only accepted outcome is the redirect
		// into the login flow that an authorized request produces.
		if resp.StatusCode != http.StatusFound {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 302: skip_pkce client was not authorized (body=%s)", resp.StatusCode, string(body))
		}

		loc := resp.Header.Get("Location")
		if loc == "" {
			t.Fatal("302 with no Location header")
		}
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("parse location %q: %v", loc, err)
		}
		// An error is reported by redirecting back to the client's redirect_uri
		// with ?error=…, so a bare check of the query would not distinguish it
		// from the login redirect. Pin the path instead.
		if u.Path != "/login" {
			t.Fatalf("Location path = %q, want /login (location=%s)", u.Path, loc)
		}
		if got := u.Query().Get("error"); got != "" {
			t.Fatalf("authorization returned error=%q (location=%s)", got, loc)
		}
		if u.Query().Get("authRequestID") == "" {
			t.Fatalf("no authRequestID in login redirect (location=%s)", loc)
		}
	})
}
