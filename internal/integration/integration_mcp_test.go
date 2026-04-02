//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestIntegration_MCPTokenExchange_NoPKCE_Rejected(t *testing.T) {
	ts := SetupTestServer(t)
	client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, "mcp-pkce@test.com", true, "MCP PKCE", "", "google", "test-google-sub", "mcp-pkce@test.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	_ = user

	code := completeLoginFlowToCode(t, ts, client)

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {client.RedirectURI},
		"client_id":    {client.ClientID},
		// No code_verifier.
	}
	resp, err := http.Post(ts.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("token request without code_verifier: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("mcp token exchange without code_verifier should fail, got 200 body=%s", string(body))
	}
}

// mcp-token-003: MCP authorization must reject token exchange when resource is omitted.
func TestIntegration_MCPTokenExchange_MissingResource_Rejected(t *testing.T) {
	ts := SetupTestServer(t)
	client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")
	ctx := context.Background()

	if _, err := ts.Store.CreateUserWithIdentity(ctx, "mcp-missing-resource@test.com", true, "MCP Missing Resource", "", "google", "test-google-sub", "mcp-missing-resource@test.com"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	code := completeLoginFlowToCode(t, ts, client)
	client.Resource = ""
	result := client.ExchangeCode(code)

	if result.StatusCode == http.StatusOK {
		t.Fatalf("mcp token exchange without resource should fail, got 200 body=%s", result.RawBody)
	}
	if !strings.Contains(result.RawBody, "invalid_grant") && !strings.Contains(result.RawBody, "invalid_target") {
		t.Fatalf("expected invalid_grant/invalid_target, got body=%s", result.RawBody)
	}
}

// refresh-001: valid refresh token for active user should rotate successfully.
func TestIntegration_MCPRefresh_MismatchedResource_Rejected(t *testing.T) {
	ts := SetupTestServer(t)
	client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")
	ctx := context.Background()

	if _, err := ts.Store.CreateUserWithIdentity(ctx, "mcp-refresh-resource@test.com", true, "MCP Refresh Resource", "", "google", "test-google-sub", "mcp-refresh-resource@test.com"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	tokens := client.ExchangeCode(completeLoginFlowToCode(t, ts, client))
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("initial mcp login failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}

	client.Resource = ts.BaseURL + "/other-mcp"
	refresh := client.RefreshToken(tokens.RefreshToken)
	if refresh.StatusCode == http.StatusOK {
		t.Fatalf("mcp refresh with mismatched resource should fail, got 200 body=%s", refresh.RawBody)
	}
	if !strings.Contains(refresh.RawBody, "invalid_grant") && !strings.Contains(refresh.RawBody, "invalid_target") {
		t.Fatalf("expected invalid_grant/invalid_target, got body=%s", refresh.RawBody)
	}
}

// mcp-token-005: issued MCP access tokens must carry aud=resource across code and refresh flows.
func TestIntegration_MCPAccessToken_AudienceBoundToResource(t *testing.T) {
	ts := SetupTestServer(t)
	client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")
	ctx := context.Background()

	if _, err := ts.Store.CreateUserWithIdentity(ctx, "mcp-audience@test.com", true, "MCP Audience", "", "google", "test-google-sub", "mcp-audience@test.com"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	tokens := client.ExchangeCode(completeLoginFlowToCode(t, ts, client))
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("initial mcp login failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}
	claims := decodeJWTClaims(t, tokens.AccessToken)
	if !audienceContains(claims.Aud, client.Resource) {
		t.Fatalf("initial access token aud = %#v, want %q", claims.Aud, client.Resource)
	}

	refreshed := client.RefreshToken(tokens.RefreshToken)
	if refreshed.StatusCode != http.StatusOK {
		t.Fatalf("refresh failed: status=%d body=%s", refreshed.StatusCode, refreshed.RawBody)
	}
	refreshClaims := decodeJWTClaims(t, refreshed.AccessToken)
	if !audienceContains(refreshClaims.Aud, client.Resource) {
		t.Fatalf("refreshed access token aud = %#v, want %q", refreshClaims.Aud, client.Resource)
	}
}

// browser-token-003: auth code issued, then user becomes recoverable/inactive -> invalid_grant
func TestIntegration_MCPCodeExchange_StateChange_InvalidGrant(t *testing.T) {
	tests := []struct {
		name      string
		mutateSQL string
	}{
		{name: "pending_deletion", mutateSQL: `UPDATE users SET status = 'pending_deletion' WHERE id = $1`},
		{name: "disabled", mutateSQL: `UPDATE users SET status = 'disabled' WHERE id = $1`},
		{name: "deleted", mutateSQL: `UPDATE users SET status = 'deleted' WHERE id = $1`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := SetupTestServer(t)
			client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")

			ctx := context.Background()
			user, err := ts.Store.CreateUserWithIdentity(ctx, "mcp-token-state@test.com", true, "MCP Token", "", "google", "test-google-sub", "mcp-token-state@test.com")
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			_ = user

			code := completeLoginFlowToCode(t, ts, client)
			if _, err := ts.DB.ExecContext(ctx, tt.mutateSQL, user.ID); err != nil {
				t.Fatalf("mutate user state: %v", err)
			}

			result := client.ExchangeCode(code)
			if result.StatusCode == 200 {
				t.Fatalf("token exchange should fail after state change: %+v", result)
			}
			if !strings.Contains(result.RawBody, "invalid_grant") {
				t.Fatalf("expected invalid_grant, got body=%s", result.RawBody)
			}
		})
	}
}

// device-002: device callback must reject non-existent user (no browser signup).
func TestIntegration_MCPCallback_NewUser_Rejected(t *testing.T) {
	ts := SetupTestServer(t)
	resp, err := http.Get(ts.BaseURL + "/mcp/callback?code=fake-code&state=req-mcp-new")
	if err != nil {
		t.Fatalf("mcp callback: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want 403 body=%s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "account_not_found") {
		t.Fatalf("expected account_not_found in response, got body=%s", string(body))
	}
}

// channel-006: pending_deletion user must be rejected on MCP callback path.
func TestIntegration_MCPCallback_PendingDeletion_Rejected(t *testing.T) {
	ts := SetupTestServer(t)
	client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, "mcp-callback-pending@test.com", true, "MCP Callback Pending", "", "google", "test-google-sub", "mcp-callback-pending@test.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Stop on redirects so we can extract authRequestID before callback execution.
	noFollowClient := *client.Client
	noFollowClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp1, err := noFollowClient.Get(client.AuthorizeURL())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp1.Body.Close()

	loginLoc := resp1.Header.Get("Location")
	if loginLoc == "" {
		t.Fatalf("authorize did not redirect, status=%d", resp1.StatusCode)
	}

	resp2, err := noFollowClient.Get(ts.BaseURL + loginLoc)
	if err != nil {
		t.Fatalf("mcp login: %v", err)
	}
	resp2.Body.Close()

	idpLoc := resp2.Header.Get("Location")
	idpURL, err := url.Parse(idpLoc)
	if err != nil {
		t.Fatalf("parse idp redirect url: %v", err)
	}
	authRequestID := idpURL.Query().Get("state")
	if authRequestID == "" {
		t.Fatalf("no authRequestID(state) in idp redirect: %s", idpLoc)
	}

	if _, err := ts.DB.ExecContext(ctx, `UPDATE users SET status = 'pending_deletion' WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("set pending_deletion: %v", err)
	}

	callbackURL := ts.BaseURL + "/mcp/callback?code=fake-code&state=" + authRequestID
	cbResp, err := noFollowClient.Get(callbackURL)
	if err != nil {
		t.Fatalf("mcp callback: %v", err)
	}
	defer cbResp.Body.Close()
	body, _ := io.ReadAll(cbResp.Body)

	if cbResp.StatusCode != http.StatusForbidden {
		t.Fatalf("mcp callback status=%d, want 403 body=%s", cbResp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "account_inactive") {
		t.Fatalf("expected account_inactive in response body, got %s", string(body))
	}
}

// Verify second login (existing user) auto-approves
