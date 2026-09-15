//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// promptChannelClients returns a fresh OAuth client per login channel.
func promptChannelClients(t *testing.T, ts *TestServer) map[string]*OAuthClient {
	t.Helper()
	return map[string]*OAuthClient{
		"browser": NewOAuthClient(t, ts.BaseURL),
		"mcp":     NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback"),
	}
}

// authorizeToLoginRedirect runs /authorize with the client's prompt and then
// the login URL it redirects to, returning the login response Location.
func authorizeToLoginRedirect(t *testing.T, ts *TestServer, client *OAuthClient) string {
	t.Helper()
	noFollow := noFollowCopy(client)
	resp, err := noFollow.Get(client.AuthorizeURL())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	loginLoc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.Contains(loginLoc, "login?authRequestID=") {
		t.Fatalf("authorize status=%d Location=%q, want redirect to login", resp.StatusCode, loginLoc)
	}
	resp, err = noFollow.Get(ts.BaseURL + loginLoc)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status=%d, want 302", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// browser-prompt-001 / mcp-prompt-001: prompt=select_account with a session
// goes to the upstream IdP with prompt=select_account instead of reusing it.
func TestIntegration_Prompt_SelectAccount_SkipsSession(t *testing.T) {
	ts := SetupTestServer(t)
	// MCP cannot sign up; a browser login creates the account first.
	completeLoginFlowToCode(t, ts, NewOAuthClient(t, ts.BaseURL))
	for channel, client := range promptChannelClients(t, ts) {
		t.Run(channel, func(t *testing.T) {
			// First login leaves a session cookie in the client's jar.
			completeLoginFlowToCode(t, ts, client)

			client.Prompt = "select_account"
			loc := authorizeToLoginRedirect(t, ts, client)
			idp, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("parse Location %q: %v", loc, err)
			}
			if idp.Path != "/fake-auth" {
				t.Fatalf("login Location = %q, want upstream IdP redirect (session must not be reused)", loc)
			}
			if got := idp.Query().Get("prompt"); got != "select_account" {
				t.Fatalf("upstream prompt = %q, want select_account", got)
			}
		})
	}
}

// browser-prompt-002 / mcp-prompt-002: prompt=none without a session answers
// the client with login_required, the request state and iss.
func TestIntegration_Prompt_None_NoSession_LoginRequired(t *testing.T) {
	ts := SetupTestServer(t)
	for channel, client := range promptChannelClients(t, ts) {
		t.Run(channel, func(t *testing.T) {
			client.Prompt = "none"
			loc := authorizeToLoginRedirect(t, ts, client)
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("parse Location %q: %v", loc, err)
			}
			if u.Scheme+"://"+u.Host+u.Path != client.RedirectURI {
				t.Fatalf("login Location = %q, want client redirect_uri %s", loc, client.RedirectURI)
			}
			q := u.Query()
			if q.Get("error") != "login_required" || q.Get("state") != "test-state" || q.Get("iss") != ts.BaseURL {
				t.Fatalf("error response query = %v, want error=login_required state=test-state iss=%s", q, ts.BaseURL)
			}
			if q.Has("code") {
				t.Fatalf("error response carries a code: %v", q)
			}
		})
	}
}

// browser-prompt-003 / mcp-prompt-003: prompt=none with a session issues a
// code without any interaction.
func TestIntegration_Prompt_None_WithSession_CodeIssued(t *testing.T) {
	ts := SetupTestServer(t)
	completeLoginFlowToCode(t, ts, NewOAuthClient(t, ts.BaseURL))
	for channel, client := range promptChannelClients(t, ts) {
		t.Run(channel, func(t *testing.T) {
			completeLoginFlowToCode(t, ts, client)

			client.Prompt = "none"
			noFollow := noFollowCopy(client)
			resp, err := noFollow.Get(client.AuthorizeURL())
			if err != nil {
				t.Fatalf("authorize: %v", err)
			}
			resp.Body.Close()
			code := followRedirectsToCode(t, noFollow, resp, ts.BaseURL)
			if tokens := client.ExchangeCode(code); tokens.StatusCode != http.StatusOK {
				t.Fatalf("token exchange status=%d body=%s", tokens.StatusCode, tokens.RawBody)
			}
		})
	}
}

// browser-prompt-004: prompt=none combined with another value is rejected at
// /authorize and never reaches /login.
func TestIntegration_Prompt_NoneWithLogin_Rejected(t *testing.T) {
	ts := SetupTestServer(t)
	client := NewOAuthClient(t, ts.BaseURL)
	client.Prompt = "none login"

	resp, err := noFollowCopy(client).Get(client.AuthorizeURL())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "login?authRequestID=") {
		t.Fatalf("authorize accepted prompt=none login: Location=%q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil || u.Query().Get("error") != "invalid_request" {
		t.Fatalf("authorize status=%d Location=%q, want invalid_request error response", resp.StatusCode, loc)
	}
}
