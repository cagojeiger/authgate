//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type jwtClaims struct {
	Aud any `json:"aud"`
}

func decodeJWTClaims(t *testing.T, token string) jwtClaims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v", err)
	}
	return claims
}

func audienceContains(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			s, ok := item.(string)
			if ok && s == expected {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == expected {
				return true
			}
		}
	}
	return false
}

// Helper: complete the full browser login flow (authorize → login → callback → token)
func completeLoginFlow(t *testing.T, ts *TestServer) *TokenResponse {
	t.Helper()
	client := NewOAuthClient(t, ts.BaseURL)
	code := completeLoginFlowToCode(t, ts, client)
	return client.ExchangeCode(code)
}

// completeLoginFlowToCode runs the browser flow until the relying-party redirect returns an auth code.
func completeLoginFlowToCode(t *testing.T, ts *TestServer, client *OAuthClient) string {
	t.Helper()

	// Use a client that stops at ALL redirects so we can inspect each hop
	noFollowClient := *client.Client
	noFollowClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// 1. Start authorize → 302 to /login?authRequestID=xxx
	resp, err := noFollowClient.Get(client.AuthorizeURL())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()

	loginLoc := resp.Header.Get("Location")
	if loginLoc == "" {
		t.Fatalf("authorize did not redirect, status=%d", resp.StatusCode)
	}

	// 2. GET /login → 302 to FakeProvider AuthURL (state=authRequestID)
	loginURL := ts.BaseURL + loginLoc
	resp2, err := noFollowClient.Get(loginURL)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp2.Body.Close()

	idpLoc := resp2.Header.Get("Location")
	if idpLoc == "" {
		t.Fatalf("login did not redirect to IdP, status=%d", resp2.StatusCode)
	}

	// Extract authRequestID from the IdP redirect URL (it's in the state parameter)
	idpURL, _ := url.Parse(idpLoc)
	authRequestID := idpURL.Query().Get("state")
	if authRequestID == "" {
		t.Fatalf("no state/authRequestID in IdP redirect: %s", idpLoc)
	}

	// 3. Simulate IdP callback → new user is immediately active, so 302 redirect
	callbackURL := ts.BaseURL + client.AuthgateCallbackPath + "?code=fake-code&state=" + authRequestID
	cbResp, err := noFollowClient.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	body, _ := io.ReadAll(cbResp.Body)
	cbResp.Body.Close()

	// Should be 302 redirect (auto-approve, no terms page)
	if cbResp.StatusCode == http.StatusFound {
		return followRedirectsToCode(t, &noFollowClient, cbResp, client.BaseURL)
	}

	t.Fatalf("unexpected callback status=%d body=%s", cbResp.StatusCode, string(body))
	return ""
}

// followRedirectsToCode follows 302 redirects until it finds a code parameter.
func followRedirectsToCode(t *testing.T, client *http.Client, resp *http.Response, baseURL string) string {
	t.Helper()
	maxRedirects := 10
	for i := 0; i < maxRedirects; i++ {
		loc := resp.Header.Get("Location")
		if loc == "" {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("redirect %d: no Location header, status=%d body=%s", i, resp.StatusCode, string(body))
		}

		// Check if this redirect contains a code
		u, _ := url.Parse(loc)
		if code := u.Query().Get("code"); code != "" {
			return code
		}

		// Make absolute URL if relative
		if !strings.HasPrefix(loc, "http") {
			loc = baseURL + loc
		}

		var err error
		resp, err = client.Get(loc)
		if err != nil {
			t.Fatalf("redirect %d: %v", i, err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
			break
		}
	}
	t.Fatal("could not extract code from redirect chain")
	return ""
}

// browser-token-001: full authorize → callback → token exchange
func TestIntegration_BrowserFullFlow_TokenIssued(t *testing.T) {
	ts := SetupTestServer(t)

	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != 200 {
		t.Fatalf("token exchange failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}
	if tokens.AccessToken == "" {
		t.Error("access_token should not be empty")
	}
	if tokens.RefreshToken == "" {
		t.Error("refresh_token should not be empty")
	}
}

// mcp-007: PKCE enforcement — token exchange without code_verifier fails
func TestIntegration_NoPKCE_TokenExchangeFails(t *testing.T) {
	ts := SetupTestServer(t)

	// Complete login flow normally (with PKCE in authorize)
	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != 200 {
		t.Fatalf("setup login failed: %s", tokens.RawBody)
	}

	// Now try to exchange a code WITHOUT code_verifier
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"fake-code"},
		"redirect_uri": {ts.BaseURL + "/callback"},
		"client_id":    {"test-client"},
		// No code_verifier!
	}
	resp, err := http.Post(ts.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		t.Error("token exchange should fail without code_verifier")
	}
}

// mcp-007: MCP clients must fail token exchange if code_verifier is missing.
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

// Verify refresh token works after full flow
func TestIntegration_RefreshAfterLogin(t *testing.T) {
	ts := SetupTestServer(t)

	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != 200 {
		t.Fatalf("initial login failed: %s", tokens.RawBody)
	}

	// Refresh
	client := NewOAuthClient(t, ts.BaseURL)
	refreshResult := client.RefreshToken(tokens.RefreshToken)

	if refreshResult.StatusCode != 200 {
		t.Errorf("refresh failed: status=%d body=%s", refreshResult.StatusCode, refreshResult.RawBody)
	}
	if refreshResult.AccessToken == "" {
		t.Error("refreshed access_token should not be empty")
	}
}

// mcp-token-004: refresh token exchange must use the same MCP resource.
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
func TestIntegration_BrowserCodeExchange_StateChange_InvalidGrant(t *testing.T) {
	tests := []struct {
		name      string
		mutateSQL string
	}{
		{name: "pending_deletion", mutateSQL: `UPDATE users SET status = 'pending_deletion' WHERE id = $1`},
		{name: "disabled", mutateSQL: `UPDATE users SET status = 'disabled' WHERE id = $1`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := SetupTestServer(t)
			client := NewOAuthClient(t, ts.BaseURL)
			code := completeLoginFlowToCode(t, ts, client)

			ctx := context.Background()
			user, err := ts.Store.GetUserByProviderIdentity(ctx, "google", "test-google-sub")
			if err != nil {
				t.Fatalf("get user: %v", err)
			}
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

// mcp-token-002: auth code issued, then user becomes recoverable/inactive -> invalid_grant
func TestIntegration_MCPCodeExchange_StateChange_InvalidGrant(t *testing.T) {
	tests := []struct {
		name      string
		mutateSQL string
	}{
		{name: "pending_deletion", mutateSQL: `UPDATE users SET status = 'pending_deletion' WHERE id = $1`},
		{name: "disabled", mutateSQL: `UPDATE users SET status = 'disabled' WHERE id = $1`},
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

// Verify second login (existing user) auto-approves
func TestIntegration_SecondLogin_AutoApprove(t *testing.T) {
	ts := SetupTestServer(t)

	// First login (signup)
	tokens1 := completeLoginFlow(t, ts)
	if tokens1.StatusCode != 200 {
		t.Fatalf("first login failed: %s", tokens1.RawBody)
	}

	// Second login — should auto-approve
	tokens2 := completeLoginFlow(t, ts)
	if tokens2.StatusCode != 200 {
		t.Fatalf("second login failed: %s", tokens2.RawBody)
	}
}

// Verify OIDC discovery responds correctly
func TestIntegration_Discovery(t *testing.T) {
	ts := SetupTestServer(t)

	resp, err := http.Get(ts.BaseURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("discovery status = %d, want 200", resp.StatusCode)
	}
}

// device-008: consumed device code re-polling → error
func TestIntegration_DeviceConsumed_RePolling(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	// Create user and approve device code
	user, _ := ts.Store.CreateUserWithIdentity(ctx, "device-consumed@test.com", true, "Test", "", "google", "device-consumed-sub", "dc@test.com")
	_ = user

	// Store a device code and approve it
	ts.Store.StoreDeviceAuthorization(ctx, "test-client", "consumed-dc", "CONS-CODE", ts.Clock.Now().Add(5*60*1e9), []string{"openid"})
	ts.Store.ApproveDeviceCode(ctx, "CONS-CODE", user.ID)

	// First poll: should consume and return token
	data1 := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {"consumed-dc"},
		"client_id":   {"test-client"},
	}
	resp1, _ := http.Post(ts.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data1.Encode()))
	resp1.Body.Close()

	// Second poll: should fail (consumed)
	resp2, err2 := http.Post(ts.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data1.Encode()))
	if err2 != nil {
		t.Fatalf("second poll request: %v", err2)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == 200 {
		t.Error("second poll should fail (device code consumed)")
	}
}

type deviceAuthorizeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

func startDeviceAuthorization(t *testing.T, ts *TestServer) *deviceAuthorizeResponse {
	t.Helper()

	data := url.Values{
		"client_id": {"test-client"},
		"scope":     {"openid profile email offline_access"},
	}
	resp, err := http.Post(ts.BaseURL+"/oauth/device/authorize", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("device authorize failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var out deviceAuthorizeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode device authorize response: %v", err)
	}
	return &out
}

func pollDeviceToken(t *testing.T, ts *TestServer, deviceCode string) *TokenResponse {
	t.Helper()
	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {"test-client"},
	}
	resp, err := http.Post(ts.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("device token poll: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	tr := &TokenResponse{StatusCode: resp.StatusCode, RawBody: string(body)}
	if resp.StatusCode == http.StatusOK {
		_ = json.Unmarshal(body, tr)
	}
	return tr
}

// device-001/device-009: full device flow from authorization to token issuance.
func TestIntegration_DeviceFullFlow_TokenIssued(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, "device-ok@test.com", true, "Device OK", "", "google", "test-google-sub", "device-ok@test.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	authz := startDeviceAuthorization(t, ts)
	if err := ts.Store.ApproveDeviceCode(ctx, authz.UserCode, user.ID); err != nil {
		t.Fatalf("approve device code: %v", err)
	}

	result := pollDeviceToken(t, ts, authz.DeviceCode)
	if result.StatusCode != http.StatusOK {
		t.Fatalf("device token exchange failed: status=%d body=%s", result.StatusCode, result.RawBody)
	}
	if result.AccessToken == "" {
		t.Fatal("access_token should not be empty")
	}
	if result.RefreshToken == "" {
		t.Fatal("refresh_token should not be empty")
	}
}

// device-007: concurrent polling should succeed exactly once after approval.
func TestIntegration_DeviceConcurrentPolling_ExactlyOneSuccess(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, "device-race@test.com", true, "Device Race", "", "google", "test-google-sub", "device-race@test.com")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	authz := startDeviceAuthorization(t, ts)
	if err := ts.Store.ApproveDeviceCode(ctx, authz.UserCode, user.ID); err != nil {
		t.Fatalf("approve device code: %v", err)
	}

	var wg sync.WaitGroup
	results := make(chan *TokenResponse, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- pollDeviceToken(t, ts, authz.DeviceCode)
		}()
	}
	wg.Wait()
	close(results)

	success := 0
	fail := 0
	for result := range results {
		if result.StatusCode == http.StatusOK {
			success++
		} else {
			fail++
		}
	}

	if success != 1 || fail != 1 {
		t.Fatalf("expected exactly one success and one failure, got success=%d fail=%d", success, fail)
	}
}

// security-001: /device/approve rejects non-POST methods
func TestIntegration_DeviceApprove_GetRejected(t *testing.T) {
	ts := SetupTestServer(t)

	resp, err := http.Get(ts.BaseURL + "/device/approve")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /device/approve status = %d, want 405", resp.StatusCode)
	}
}

// security-002: DELETE /account with wrong Origin is rejected
func TestIntegration_DeleteAccount_WrongOrigin_Rejected(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	// Create user + get session
	user, _ := ts.Store.CreateUserWithIdentity(ctx, "origin-test@test.com", true, "Test", "", "google", "test-google-sub", "o@test.com")
	sessionID, _ := ts.Store.CreateSession(ctx, user.ID, 24*3600*1e9)

	req, _ := http.NewRequest("DELETE", ts.BaseURL+"/account", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.AddCookie(&http.Cookie{Name: "authgate_session", Value: sessionID})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("DELETE /account with wrong origin status = %d, want 403", resp.StatusCode)
	}
}
