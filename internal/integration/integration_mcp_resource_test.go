//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/storage"
)

// TestMCPResourceBinding verifies that MCP callback rejects auth requests without a resource
// (resource binding bypass scenario per Spec 004).
func TestMCPResourceBinding(t *testing.T) {
	t.Run("callback with resource-less auth_request is rejected", func(t *testing.T) {
		ts := SetupTestServer(t)
		ctx := context.Background()

		// Create an auth request directly in the DB without a resource — simulates a tampered/injected request.
		authRequestID, err := ts.Store.CreateTestAuthRequest(ctx, "mcp-no-resource")
		if err != nil {
			t.Fatalf("create test auth request: %v", err)
		}

		// Attempt to complete the callback using this resource-less auth request.
		callbackURL := ts.BaseURL + "/mcp/callback?code=fake-code&state=" + authRequestID
		noFollowClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := noFollowClient.Get(callbackURL)
		if err != nil {
			t.Fatalf("mcp callback: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode == http.StatusFound {
			t.Fatalf("mcp callback with resource-less auth_request should be rejected, got redirect to %s", resp.Header.Get("Location"))
		}
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("mcp callback with resource-less auth_request should be rejected, got 200 body=%s", string(body))
		}
		if !strings.Contains(string(body), "invalid_target") && !strings.Contains(string(body), "auth_request_not_found") {
			t.Fatalf("expected invalid_target or auth_request_not_found, got body=%s", string(body))
		}
	})

	t.Run("normal MCP flow with resource succeeds", func(t *testing.T) {
		ts := SetupTestServer(t)
		client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")
		ctx := context.Background()

		if _, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
			Email: "mcp-resource-ok@test.com", EmailVerified: true, Name: "MCP Resource OK",
			Provider: "google", ProviderUserID: "test-google-sub",
		}); err != nil {
			t.Fatalf("create user: %v", err)
		}

		tokens := client.ExchangeCode(completeLoginFlowToCode(t, ts, client))
		if tokens.StatusCode != http.StatusOK {
			t.Fatalf("MCP login with resource should succeed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
		}
		if tokens.AccessToken == "" {
			t.Fatal("expected non-empty access_token")
		}
	})

	t.Run("callback with unknown authRequestID is rejected", func(t *testing.T) {
		ts := SetupTestServer(t)

		callbackURL := ts.BaseURL + "/mcp/callback?code=fake-code&state=nonexistent-auth-request-id"
		noFollowClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := noFollowClient.Get(callbackURL)
		if err != nil {
			t.Fatalf("mcp callback: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusOK {
			t.Fatalf("mcp callback with nonexistent auth_request should be rejected, got status=%d body=%s", resp.StatusCode, string(body))
		}
	})

	// #184: a non-MCP (browser) client must NOT be able to bind a token's
	// audience to an MCP resource URL. RFC 8707 §2.2 explicitly permits
	// the AS to reject `resource` values per its own policy via
	// invalid_target; our spec scopes resource to login_channel='mcp', so
	// a browser client passing resource= is a boundary-confusion attempt
	// that must be rejected at /authorize before any auth_request is
	// stored.
	t.Run("browser client passing resource is rejected at /authorize (#184)", func(t *testing.T) {
		ts := SetupTestServer(t)
		// "test-client" is the browser-channel client baked into the test server.
		client := NewOAuthClientFor(t, ts.BaseURL, "test-client", "/callback")
		client.Resource = ts.BaseURL + "/some-mcp-resource"

		noFollowClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, err := noFollowClient.Get(client.AuthorizeURL())
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		// Either a 4xx error response or a redirect carrying error=invalid_target
		// is acceptable. The critical invariants: not a successful login flow
		// (so no auth_request gets stored), and the error surface mentions
		// invalid_target.
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("browser client + resource should be rejected, got 200 body=%s", string(body))
		}
		combined := string(body) + " " + resp.Header.Get("Location")
		if !strings.Contains(combined, "invalid_target") {
			t.Fatalf("expected invalid_target in response, got status=%d body=%s location=%s",
				resp.StatusCode, string(body), resp.Header.Get("Location"))
		}
	})

	// #184: RFC 8707 lets the AS apply single-audience policy. Multiple
	// `resource` params at /authorize must be rejected so a malicious
	// client cannot smuggle in additional audiences (e.g. a private
	// internal MCP URL) past the front-door check.
	t.Run("duplicate resource params at /authorize are rejected (#184)", func(t *testing.T) {
		ts := SetupTestServer(t)
		client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")

		params := url.Values{
			"client_id":             {client.ClientID},
			"redirect_uri":          {client.RedirectURI},
			"response_type":         {"code"},
			"scope":                 {"openid profile email"},
			"code_challenge":        {client.CodeChallenge},
			"code_challenge_method": {"S256"},
			"state":                 {"test-state"},
		}
		// Encode so resource appears twice in the query string.
		raw := params.Encode() + "&resource=" + url.QueryEscape(ts.BaseURL+"/mcp-1") + "&resource=" + url.QueryEscape(ts.BaseURL+"/mcp-2")
		authzURL := ts.BaseURL + "/authorize?" + raw

		noFollowClient := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, err := noFollowClient.Get(authzURL)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode == http.StatusOK {
			t.Fatalf("duplicate resource params should be rejected, got 200 body=%s", string(body))
		}
		combined := string(body) + " " + resp.Header.Get("Location")
		if !strings.Contains(combined, "invalid_target") {
			t.Fatalf("expected invalid_target, got status=%d body=%s location=%s",
				resp.StatusCode, string(body), resp.Header.Get("Location"))
		}
	})

	t.Run("mismatched resource in token exchange is rejected", func(t *testing.T) {
		ts := SetupTestServer(t)
		client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")
		ctx := context.Background()

		if _, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
			Email: "mcp-resource-mismatch@test.com", EmailVerified: true, Name: "MCP Resource Mismatch",
			Provider: "google", ProviderUserID: "test-google-sub",
		}); err != nil {
			t.Fatalf("create user: %v", err)
		}

		code := completeLoginFlowToCode(t, ts, client)

		// Exchange the code but with a different resource than was used at authorize time.
		data := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {client.RedirectURI},
			"client_id":     {client.ClientID},
			"code_verifier": {client.CodeVerifier},
			"resource":      {ts.BaseURL + "/different-mcp-server"},
		}
		resp, err := http.Post(ts.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
		if err != nil {
			t.Fatalf("token exchange: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode == http.StatusOK {
			t.Fatalf("token exchange with mismatched resource should fail, got 200 body=%s", string(body))
		}
		if !strings.Contains(string(body), "invalid_grant") && !strings.Contains(string(body), "invalid_target") {
			t.Fatalf("expected invalid_grant or invalid_target, got body=%s", string(body))
		}
	})
}
