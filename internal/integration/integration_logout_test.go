//go:build integration

package integration

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

// These tests pin /end_session (OIDC RP-Initiated Logout 1.0) as authgate
// serves it: the only way for a browser stuck on one Google account to switch
// to another, since the session is otherwise reused silently.

// signedInBrowser completes a browser login and returns the client (whose jar
// holds the session cookie), a copy that does not follow redirects, the
// session cookie value and the issued tokens.
func signedInBrowser(t *testing.T, ts *TestServer) (*OAuthClient, *http.Client, string, *TokenResponse) {
	t.Helper()
	client := NewOAuthClient(t, ts.BaseURL)
	code := completeLoginFlowToCode(t, ts, client)
	tokens := client.ExchangeCode(code)
	if tokens.StatusCode != http.StatusOK || tokens.IDToken == "" {
		t.Fatalf("token exchange: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}
	noFollow := noFollowCopy(client)
	return client, noFollow, sessionCookieFromJar(t, ts, client), tokens
}

func noFollowCopy(client *OAuthClient) *http.Client {
	c := *client.Client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func sessionCookieFromJar(t *testing.T, ts *TestServer, client *OAuthClient) string {
	t.Helper()
	u, _ := url.Parse(ts.BaseURL)
	for _, c := range client.Client.Jar.Cookies(u) {
		if c.Name == "authgate_session" {
			return c.Value
		}
	}
	t.Fatal("no authgate_session cookie in the jar after login")
	return ""
}

type endSessionResult struct {
	status  int
	body    string
	header  http.Header
	cookies []*http.Cookie
}

func getEndSession(t *testing.T, c *http.Client, ts *TestServer, params url.Values) endSessionResult {
	t.Helper()
	resp, err := c.Get(ts.BaseURL + "/end_session?" + params.Encode())
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	return readEndSession(resp)
}

func postEndSession(t *testing.T, c *http.Client, ts *TestServer, form url.Values) endSessionResult {
	t.Helper()
	resp, err := c.PostForm(ts.BaseURL+"/end_session", form)
	if err != nil {
		t.Fatalf("POST /end_session: %v", err)
	}
	return readEndSession(resp)
}

func readEndSession(resp *http.Response) endSessionResult {
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return endSessionResult{status: resp.StatusCode, body: string(body), header: resp.Header, cookies: resp.Cookies()}
}

func (r endSessionResult) isConfirmPage() bool {
	return strings.Contains(r.body, `name="csrf_token"`) && strings.Contains(r.body, `name="confirm"`)
}

// csrfToken pulls the hidden csrf_token value out of the confirmation page.
func (r endSessionResult) csrfToken(t *testing.T) string {
	t.Helper()
	const marker = `name="csrf_token" value="`
	i := strings.Index(r.body, marker)
	if i < 0 {
		t.Fatalf("no csrf_token on the page:\n%s", r.body)
	}
	rest := r.body[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}

func (r endSessionResult) clearsSessionCookie() bool {
	for _, c := range r.cookies {
		if c.Name == "authgate_session" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func assertSessionValid(t *testing.T, ts *TestServer, sessionID string) {
	t.Helper()
	if _, err := ts.Store.GetValidSession(context.Background(), sessionID); err != nil {
		t.Fatalf("session should still be valid: %v", err)
	}
}

func assertSessionEnded(t *testing.T, ts *TestServer, sessionID string) {
	t.Helper()
	if _, err := ts.Store.GetValidSession(context.Background(), sessionID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("session should be revoked, GetValidSession err = %v", err)
	}
}

func countLogoutAudits(t *testing.T, ts *TestServer) int {
	t.Helper()
	var n int
	if err := ts.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_log WHERE event_type = 'auth.logout'`).Scan(&n); err != nil {
		t.Fatalf("count auth.logout: %v", err)
	}
	return n
}

// loginRedirectTarget starts a fresh /authorize with the browser's jar and
// returns where /login sends it: /authorize/callback when the session was
// reused silently, the IdP when the user has to sign in again.
func loginRedirectTarget(t *testing.T, ts *TestServer, client *OAuthClient) string {
	t.Helper()
	noFollow := noFollowCopy(client)
	resp, err := noFollow.Get(client.AuthorizeURL())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	loginLoc := resp.Header.Get("Location")
	if !strings.HasPrefix(loginLoc, "/login") {
		t.Fatalf("authorize redirected to %q, want /login", loginLoc)
	}
	resp, err = noFollow.Get(ts.BaseURL + loginLoc)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	return resp.Header.Get("Location")
}

// logout-001: nothing to end. No session and no hint renders the signed-out
// page and writes no audit row.
func TestEndSession_NoSessionNoHint_RendersSignedOut(t *testing.T) {
	ts := SetupTestServer(t)
	noFollow := noFollowCopy(NewOAuthClient(t, ts.BaseURL))

	res := getEndSession(t, noFollow, ts, url.Values{"state": {"s"}})

	if res.status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", res.status, res.body)
	}
	if res.isConfirmPage() || !strings.Contains(res.body, "You are signed out") {
		t.Fatalf("want the signed-out page, got:\n%s", res.body)
	}
	if loc := res.header.Get("Location"); loc != "" {
		t.Fatalf("redirected to %q with no validated post_logout_redirect_uri", loc)
	}
	if n := countLogoutAudits(t, ts); n != 0 {
		t.Fatalf("auth.logout rows = %d, want 0", n)
	}
}

// logout-002: a signed-in browser without id_token_hint must be asked (§2).
// The GET alone ends nothing.
func TestEndSession_SessionWithoutHint_ShowsConfirmation(t *testing.T) {
	ts := SetupTestServer(t)
	_, noFollow, sessionID, _ := signedInBrowser(t, ts)

	res := getEndSession(t, noFollow, ts, nil)

	if res.status != http.StatusOK || !res.isConfirmPage() {
		t.Fatalf("status = %d, want 200 confirmation page; body=%s", res.status, res.body)
	}
	if res.clearsSessionCookie() {
		t.Fatal("confirmation page cleared the session cookie")
	}
	assertSessionValid(t, ts, sessionID)
	if n := countLogoutAudits(t, ts); n != 0 {
		t.Fatalf("auth.logout rows = %d, want 0 before confirmation", n)
	}
}

// logout-003: confirming ends the session, clears the cookie, audits once, and
// the next sign-in goes to the IdP instead of reusing the old account.
func TestEndSession_ConfirmedLogout_EndsSessionAndForcesIdPLogin(t *testing.T) {
	ts := SetupTestServer(t)
	client, noFollow, sessionID, _ := signedInBrowser(t, ts)

	if loc := loginRedirectTarget(t, ts, client); !strings.HasPrefix(loc, "/authorize/callback") {
		t.Fatalf("precondition: signed-in browser should reuse its session, /login went to %q", loc)
	}

	page := getEndSession(t, noFollow, ts, nil)
	res := postEndSession(t, noFollow, ts, url.Values{"csrf_token": {page.csrfToken(t)}, "confirm": {"yes"}})

	if res.status != http.StatusOK || !strings.Contains(res.body, "You are signed out") {
		t.Fatalf("status = %d, want 200 signed-out page; body=%s", res.status, res.body)
	}
	if !res.clearsSessionCookie() {
		t.Fatalf("response does not expire authgate_session; cookies=%v", res.cookies)
	}
	assertSessionEnded(t, ts, sessionID)
	if n := countLogoutAudits(t, ts); n != 1 {
		t.Fatalf("auth.logout rows = %d, want 1", n)
	}
	if loc := loginRedirectTarget(t, ts, client); !strings.HasPrefix(loc, "/fake-auth") {
		t.Fatalf("after logout /login went to %q, want the IdP", loc)
	}
}

// logout-016: a sibling subdomain that already holds the CSRF token still
// cannot end the session — its POST carries Sec-Fetch-Site: same-site, which
// only authgate's own page ("same-origin") passes. This is the whole point of
// the same-origin check: cookies are same-site across sibling subdomains, so
// the double-submit token alone would not stop a subdomain that can write
// cookies.
func TestEndSession_ConfirmFromSiblingSubdomain_Forbidden(t *testing.T) {
	ts := SetupTestServer(t)
	_, noFollow, sessionID, _ := signedInBrowser(t, ts)

	page := getEndSession(t, noFollow, ts, nil)
	form := url.Values{"csrf_token": {page.csrfToken(t)}, "confirm": {"yes"}}
	req, err := http.NewRequest(http.MethodPost, ts.BaseURL+"/end_session", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("POST /end_session: %v", err)
	}
	res := readEndSession(resp)
	if res.status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", res.status, res.body)
	}
	if res.clearsSessionCookie() {
		t.Fatal("rejected confirmation cleared the session cookie")
	}
	assertSessionValid(t, ts, sessionID)
	if n := countLogoutAudits(t, ts); n != 0 {
		t.Fatalf("auth.logout rows = %d, want 0", n)
	}
}

// logout-004: a confirmation POST without the double-submit token is a CSRF
// attempt: 403 and the session survives.
func TestEndSession_ConfirmWithoutValidCSRF_Forbidden(t *testing.T) {
	ts := SetupTestServer(t)
	_, noFollow, sessionID, _ := signedInBrowser(t, ts)

	// Issue the csrf cookie, then submit without / with a wrong form token.
	_ = getEndSession(t, noFollow, ts, nil)
	for name, form := range map[string]url.Values{
		"missing":  {"confirm": {"yes"}},
		"mismatch": {"confirm": {"yes"}, "csrf_token": {"not-the-token"}},
	} {
		res := postEndSession(t, noFollow, ts, form)
		if res.status != http.StatusForbidden {
			t.Fatalf("%s: status = %d, want 403; body=%s", name, res.status, res.body)
		}
		if res.clearsSessionCookie() {
			t.Fatalf("%s: rejected confirmation cleared the session cookie", name)
		}
		assertSessionValid(t, ts, sessionID)
	}
	if n := countLogoutAudits(t, ts); n != 0 {
		t.Fatalf("auth.logout rows = %d, want 0", n)
	}
}

// logout-005: an id_token_hint for the user signed in to this browser is the
// proof §2 accepts in place of asking: logout is immediate.
func TestEndSession_HintForSignedInUser_EndsImmediately(t *testing.T) {
	ts := SetupTestServer(t)
	_, noFollow, sessionID, tokens := signedInBrowser(t, ts)

	res := getEndSession(t, noFollow, ts, url.Values{"id_token_hint": {tokens.IDToken}})

	if res.status != http.StatusOK || res.isConfirmPage() {
		t.Fatalf("status = %d, want 200 signed-out page without confirmation; body=%s", res.status, res.body)
	}
	if !res.clearsSessionCookie() {
		t.Fatal("response does not expire authgate_session")
	}
	assertSessionEnded(t, ts, sessionID)

	var clientID string
	if err := ts.DB.QueryRowContext(context.Background(),
		`SELECT metadata->>'client_id' FROM audit_log WHERE event_type = 'auth.logout'`).Scan(&clientID); err != nil {
		t.Fatalf("query auth.logout: %v", err)
	}
	if clientID != "test-client" {
		t.Fatalf("auth.logout client_id = %q, want the hint's azp test-client", clientID)
	}
}

// logout-006: an id_token_hint for someone other than the browser's user does
// not prove the browser's user asked, so the OP must confirm. Confirming ends
// the browser's own session only; the hint's user is not signed out.
func TestEndSession_HintForOtherUser_ShowsConfirmation(t *testing.T) {
	ts := SetupTestServer(t)
	_, _, sessionA, tokensA := signedInBrowser(t, ts)

	ts.Upstream.User = &upstream.UserInfo{Sub: "other-google-sub", Email: "other@example.com", EmailVerified: true, Name: "Other User"}
	_, noFollowB, sessionB, _ := signedInBrowser(t, ts)

	page := getEndSession(t, noFollowB, ts, url.Values{"id_token_hint": {tokensA.IDToken}})
	if page.status != http.StatusOK || !page.isConfirmPage() {
		t.Fatalf("status = %d, want 200 confirmation page; body=%s", page.status, page.body)
	}
	assertSessionValid(t, ts, sessionA)
	assertSessionValid(t, ts, sessionB)

	res := postEndSession(t, noFollowB, ts, url.Values{
		"id_token_hint": {tokensA.IDToken},
		"csrf_token":    {page.csrfToken(t)},
		"confirm":       {"yes"},
	})
	if res.status != http.StatusOK || !res.clearsSessionCookie() {
		t.Fatalf("status = %d, want 200 with session cookie cleared; body=%s", res.status, res.body)
	}
	assertSessionValid(t, ts, sessionA)
	assertSessionEnded(t, ts, sessionB)
	if n := countLogoutAudits(t, ts); n != 1 {
		t.Fatalf("auth.logout rows = %d, want 1 (the browser user only)", n)
	}
}

// logout-007: an id_token_hint that does not verify is an invalid request.
func TestEndSession_InvalidHint_BadRequest(t *testing.T) {
	ts := SetupTestServer(t)
	_, noFollow, sessionID, tokens := signedInBrowser(t, ts)

	parts := strings.Split(tokens.IDToken, ".")
	tampered := parts[0] + "." + parts[1] + ".AAAA"
	for name, hint := range map[string]string{"garbage": "not-a-jwt", "bad signature": tampered} {
		res := getEndSession(t, noFollow, ts, url.Values{"id_token_hint": {hint}})
		if res.status != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400; body=%s", name, res.status, res.body)
		}
	}
	assertSessionValid(t, ts, sessionID)
}

// logout-008: an id_token_hint without the browser's session cookie ends
// nothing. id_tokens are handed to relying parties and can be old; holding one
// is not a request from its owner to be signed out everywhere.
func TestEndSession_HintWithoutBrowserSession_EndsNothing(t *testing.T) {
	ts := SetupTestServer(t)
	_, _, sessionID, tokens := signedInBrowser(t, ts)
	stranger := noFollowCopy(NewOAuthClient(t, ts.BaseURL))

	res := getEndSession(t, stranger, ts, url.Values{"id_token_hint": {tokens.IDToken}})

	if res.status != http.StatusOK || res.isConfirmPage() {
		t.Fatalf("status = %d, want 200 signed-out page; body=%s", res.status, res.body)
	}
	assertSessionValid(t, ts, sessionID)
	if n := countLogoutAudits(t, ts); n != 0 {
		t.Fatalf("auth.logout rows = %d, want 0", n)
	}
}

// logout-009: a cross-site POST carries no Lax session cookie. The response
// must not send a deleting Set-Cookie for it, which the browser would honor on
// a top-level navigation and so sign the visitor out without confirmation.
func TestEndSession_PostWithoutCookies_DoesNotExpireSessionCookie(t *testing.T) {
	ts := SetupTestServer(t)
	stranger := noFollowCopy(NewOAuthClient(t, ts.BaseURL))

	res := postEndSession(t, stranger, ts, url.Values{})

	if res.status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", res.status, res.body)
	}
	for _, c := range res.cookies {
		if c.Name == "authgate_session" || c.Name == "end_session_csrf" {
			t.Fatalf("response sets %s on a request that did not carry it", c.Name)
		}
	}
}

// logout-010: a relying party may send the logout request as a POST. Without
// the confirm field it is a request, not a confirmation: show the page.
func TestEndSession_PostWithoutConfirm_ShowsConfirmation(t *testing.T) {
	ts := SetupTestServer(t)
	_, noFollow, sessionID, _ := signedInBrowser(t, ts)

	res := postEndSession(t, noFollow, ts, url.Values{"state": {"s"}})

	if res.status != http.StatusOK || !res.isConfirmPage() {
		t.Fatalf("status = %d, want 200 confirmation page; body=%s", res.status, res.body)
	}
	assertSessionValid(t, ts, sessionID)
}

// logout-011: client libraries send post_logout_redirect_uri by default. One
// the client did not register is never followed, but the logout still happens.
func TestEndSession_UnregisteredPostLogoutRedirect_StillLogsOut(t *testing.T) {
	ts := SetupTestServer(t)
	_, noFollow, sessionID, tokens := signedInBrowser(t, ts)

	res := getEndSession(t, noFollow, ts, url.Values{
		"id_token_hint":            {tokens.IDToken},
		"post_logout_redirect_uri": {"https://evil.test/after-logout"},
		"state":                    {"s"},
	})

	if res.status != http.StatusOK || !strings.Contains(res.body, "You are signed out") {
		t.Fatalf("status = %d, want 200 signed-out page; body=%s", res.status, res.body)
	}
	if loc := res.header.Get("Location"); loc != "" {
		t.Fatalf("followed an unregistered post_logout_redirect_uri: %q", loc)
	}
	assertSessionEnded(t, ts, sessionID)
}

// logout-012: client_id must match the hint's azp.
func TestEndSession_ClientIDNotMatchingHint_BadRequest(t *testing.T) {
	ts := SetupTestServer(t)
	_, noFollow, sessionID, tokens := signedInBrowser(t, ts)

	res := getEndSession(t, noFollow, ts, url.Values{"id_token_hint": {tokens.IDToken}, "client_id": {"mcp-client"}})

	if res.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", res.status, res.body)
	}
	assertSessionValid(t, ts, sessionID)
}

// logout-013: a session whose account has since been disabled is still ended.
func TestEndSession_DisabledAccountSession_IsEnded(t *testing.T) {
	ts := SetupTestServer(t)
	_, noFollow, sessionID, _ := signedInBrowser(t, ts)
	user, err := ts.Store.GetUserByProviderIdentity(context.Background(), "google", "test-google-sub")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if _, err := ts.DB.ExecContext(context.Background(), `UPDATE users SET status = 'disabled' WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	page := getEndSession(t, noFollow, ts, nil)
	if !page.isConfirmPage() {
		t.Fatalf("want a confirmation page for a disabled account's session; body=%s", page.body)
	}
	res := postEndSession(t, noFollow, ts, url.Values{"csrf_token": {page.csrfToken(t)}, "confirm": {"yes"}})
	if res.status != http.StatusOK || !res.clearsSessionCookie() {
		t.Fatalf("status = %d, want 200 with cookie cleared; body=%s", res.status, res.body)
	}
	var revoked int
	if err := ts.DB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NOT NULL`, user.ID).Scan(&revoked); err != nil {
		t.Fatalf("count revoked sessions: %v", err)
	}
	if revoked == 0 {
		t.Fatal("the disabled account's session was not revoked")
	}
	_ = sessionID
}

// logout-014: repeating a logout that ends nothing adds no audit rows.
func TestEndSession_RepeatedLogout_AuditedOnce(t *testing.T) {
	ts := SetupTestServer(t)
	_, noFollow, _, tokens := signedInBrowser(t, ts)

	for i := 0; i < 3; i++ {
		_ = getEndSession(t, noFollow, ts, url.Values{"id_token_hint": {tokens.IDToken}})
	}
	if n := countLogoutAudits(t, ts); n != 1 {
		t.Fatalf("auth.logout rows = %d, want 1 for one ended session", n)
	}
}
