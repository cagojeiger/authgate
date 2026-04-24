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
			AvatarURL: "", Provider: "google", ProviderUserID: "test-google-sub",
			ProviderEmail: "mcp-resource-ok@test.com",
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

	t.Run("mismatched resource in token exchange is rejected", func(t *testing.T) {
		ts := SetupTestServer(t)
		client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")
		ctx := context.Background()

		if _, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
			Email: "mcp-resource-mismatch@test.com", EmailVerified: true, Name: "MCP Resource Mismatch",
			AvatarURL: "", Provider: "google", ProviderUserID: "test-google-sub",
			ProviderEmail: "mcp-resource-mismatch@test.com",
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
