//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/upstream"
)

func TestIntegration_IDTokenUserinfoAssertion_EmbedsRequestedClaims(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{
		EnableMCP:                true,
		IDTokenUserinfoAssertion: true,
	})

	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("token exchange failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}

	claims := jwtPayloadMap(t, tokens.IDToken)
	if got := claims["email"]; got != "test@example.com" {
		t.Errorf("id_token email = %#v, want test@example.com", got)
	}
	if got := claims["email_verified"]; got != true {
		t.Errorf("id_token email_verified = %#v, want true", got)
	}
	if got := claims["name"]; got != "Test User" {
		t.Errorf("id_token name = %#v, want Test User", got)
	}
}

func TestIntegration_IDTokenUserinfoAssertion_DefaultOmitsRequestedClaims(t *testing.T) {
	ts := SetupTestServer(t)

	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("token exchange failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}

	claims := jwtPayloadMap(t, tokens.IDToken)
	if _, ok := claims["email"]; ok {
		t.Errorf("id_token unexpectedly contains email without client opt-in")
	}
	if _, ok := claims["name"]; ok {
		t.Errorf("id_token unexpectedly contains name without client opt-in")
	}
}

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
func TestIntegration_BrowserCodeExchange_StateChange_InvalidGrant(t *testing.T) {
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
func TestIntegration_SessionCookie_Attributes(t *testing.T) {
	ts := SetupTestServer(t)

	noFollow := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	client := NewOAuthClient(t, ts.BaseURL)

	// 1. /authorize → 302 /login?authRequestID=...
	resp1, err := noFollow.Get(client.AuthorizeURL())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp1.Body.Close()
	loginLoc := resp1.Header.Get("Location")
	if loginLoc == "" {
		t.Fatalf("authorize did not redirect: status=%d", resp1.StatusCode)
	}

	// 2. /login → 302 fake IdP (state=authRequestID)
	resp2, err := noFollow.Get(ts.BaseURL + loginLoc)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp2.Body.Close()
	idpLoc := resp2.Header.Get("Location")

	idpURL, _ := url.Parse(idpLoc)
	authRequestID := idpURL.Query().Get("state")
	if authRequestID == "" {
		t.Fatalf("no state param in IdP redirect: %s", idpLoc)
	}

	// 3. /login/callback (simulate IdP returning) → sets session cookie
	callbackURL := ts.BaseURL + "/login/callback?code=fake-code&state=" + authRequestID
	resp3, err := noFollow.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	resp3.Body.Close()

	var sessionCookie *http.Cookie
	for _, c := range resp3.Cookies() {
		if c.Name == "authgate_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("authgate_session cookie not set in callback response")
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie: HttpOnly should be true")
	}
	// Lax, not Strict. This cookie is minted on the hop back from the IdP and
	// has to survive one more redirect; WebKit withholds a Strict cookie there
	// because the redirect chain began cross-site, which made the device flow
	// unusable in Safari. See internal/handler/session_cookie.go.
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie: SameSite = %v, want Lax", sessionCookie.SameSite)
	}
	// devMode=true in TestServer → Secure must be false
	if sessionCookie.Secure {
		t.Error("session cookie: Secure should be false in dev mode")
	}
}

// handler-account: 성공 시 JSON 응답 shape 검증 (status, message 필드)

// signup-domain-100: with SIGNUP_EMAIL_DOMAINS set, a first sign-in from an
// address outside the list is refused at the real /login/callback before any
// account exists, and is audited without a user.
func TestIntegration_SignupDomainGate_RefusesOutsideDomain(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{EnableMCP: true, SignupEmailDomains: []string{"example.com"}})
	ts.Upstream.User = &upstream.UserInfo{Sub: "outsider-sub", Email: "x@other.com", EmailVerified: true, Name: "Outsider"}

	status := browserCallbackStatus(t, ts)
	if status != http.StatusForbidden {
		t.Fatalf("callback status = %d, want 403", status)
	}

	ctx := context.Background()
	var users, signups, denied int
	if err := ts.DB.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := ts.DB.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE event_type = 'auth.signup'`).Scan(&signups); err != nil {
		t.Fatalf("count auth.signup: %v", err)
	}
	if err := ts.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_log WHERE event_type = 'auth.signup_denied' AND user_id IS NULL AND metadata->>'domain' = 'other.com' AND metadata->>'reason' = 'domain_not_allowed'`,
	).Scan(&denied); err != nil {
		t.Fatalf("count auth.signup_denied: %v", err)
	}
	if users != 0 || signups != 0 || denied != 1 {
		t.Fatalf("users=%d auth.signup=%d auth.signup_denied=%d, want 0/0/1", users, signups, denied)
	}
}

// signup-domain-101: an address inside the list signs up normally through the
// same gate.
func TestIntegration_SignupDomainGate_AdmitsListedDomain(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{EnableMCP: true, SignupEmailDomains: []string{"example.com"}})

	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("signup from a listed domain failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}
}

// browserCallbackStatus runs /authorize → /login → the fake IdP callback and
// returns the callback's status without following it.
func browserCallbackStatus(t *testing.T, ts *TestServer) int {
	t.Helper()
	client := NewOAuthClient(t, ts.BaseURL)
	noFollow := *client.Client
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := noFollow.Get(client.AuthorizeURL())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	resp, err = noFollow.Get(ts.BaseURL + resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	idp, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || idp.Query().Get("state") == "" {
		t.Fatalf("login did not redirect to the IdP: %q", resp.Header.Get("Location"))
	}
	resp, err = noFollow.Get(ts.BaseURL + "/login/callback?code=fake-code&state=" + url.QueryEscape(idp.Query().Get("state")))
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
