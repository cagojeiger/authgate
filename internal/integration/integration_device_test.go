//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/storage"
)

func TestIntegration_DeviceCallback_NewUser_Rejected(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	// #186 made the device callback front-load the user_code lookup
	// before calling provider.Exchange. The "no user account" branch is
	// now post-Exchange and only reachable when the user_code is valid
	// and pending — seed one explicitly so this test still exercises
	// the account_not_found surface rather than tripping the new gate.
	if err := ts.Store.StoreDeviceAuthorization(ctx, "test-client", "fresh-dc", "TEST-CODE", ts.Clock.Now().Add(5*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("seed device_code: %v", err)
	}

	resp, err := http.Get(ts.BaseURL + "/device/auth/callback?code=fake-code&state=TEST-CODE")
	if err != nil {
		t.Fatalf("device callback: %v", err)
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

// device-003: pending_deletion user must be rejected on device callback path.
func TestIntegration_DeviceCallback_PendingDeletion_Rejected(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "device-pending@test.com", EmailVerified: true, Name: "Device Pending", Provider: "google", ProviderUserID: "test-google-sub"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := ts.DB.ExecContext(ctx, `UPDATE users SET status = 'pending_deletion' WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("set pending_deletion: %v", err)
	}

	// #186: seed a pending user_code so the front-load gate passes; the
	// account_inactive surface this test cares about is still post-Exchange.
	if err := ts.Store.StoreDeviceAuthorization(ctx, "test-client", "pending-dc", "TEST-CODE", ts.Clock.Now().Add(5*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("seed device_code: %v", err)
	}

	resp, err := http.Get(ts.BaseURL + "/device/auth/callback?code=fake-code&state=TEST-CODE")
	if err != nil {
		t.Fatalf("device callback: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want 403 body=%s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "account_inactive") {
		t.Fatalf("expected account_inactive in response, got body=%s", string(body))
	}
}

// mcp-002: MCP callback must reject non-existent user (no browser signup).
func TestIntegration_DeviceConsumed_RePolling(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	// Create user and approve device code
	user, _ := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "device-consumed@test.com", EmailVerified: true, Name: "Test", Provider: "google", ProviderUserID: "device-consumed-sub"})
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

func TestIntegration_DeviceFullFlow_TokenIssued(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "device-ok@test.com", EmailVerified: true, Name: "Device OK", Provider: "google", ProviderUserID: "test-google-sub"})
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

	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "device-race@test.com", EmailVerified: true, Name: "Device Race", Provider: "google", ProviderUserID: "test-google-sub"})
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

// device-008 / #185: tokens MUST NOT be issued for a user whose status flipped
// away from active (disabled, pending_deletion, deleted) between approve and
// poll. The device code MUST remain in "approved" rather than transitioning
// to "consumed", so polling continues to return an error rather than minting
// tokens once after the account is reactivated within the code's TTL.
func TestIntegration_DevicePolling_RechecksUserStatus(t *testing.T) {
	cases := []struct {
		name       string
		flipStatus string
	}{
		{"disabled", "disabled"},
		{"pending_deletion", "pending_deletion"},
		{"deleted", "deleted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := SetupTestServer(t)
			ctx := context.Background()

			user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
				Email: "device-" + tc.flipStatus + "@test.com", EmailVerified: true, Name: "Flipped Mid-Flow",
				Provider: "google", ProviderUserID: "test-google-sub-" + tc.flipStatus,
			})
			if err != nil {
				t.Fatalf("create user: %v", err)
			}

			authz := startDeviceAuthorization(t, ts)
			if err := ts.Store.ApproveDeviceCode(ctx, authz.UserCode, user.ID); err != nil {
				t.Fatalf("approve device code: %v", err)
			}

			// Operator flips the user status AFTER approval, BEFORE poll.
			if err := ts.Store.SetUserStatus(ctx, user.ID, tc.flipStatus); err != nil {
				t.Fatalf("set status %s: %v", tc.flipStatus, err)
			}

			result := pollDeviceToken(t, ts, authz.DeviceCode)
			if result.StatusCode == http.StatusOK {
				t.Fatalf("token exchange should reject %s user, got 200 body=%s", tc.flipStatus, result.RawBody)
			}
			// zitadel/oidc wraps our invalid_grant into access_denied at the
			// device endpoint (RFC 8628 §3.5 lists access_denied as a valid
			// device-grant error). Either signals the closed-account rejection.
			if !strings.Contains(result.RawBody, "invalid_grant") && !strings.Contains(result.RawBody, "access_denied") {
				t.Fatalf("expected invalid_grant or access_denied, got body=%s", result.RawBody)
			}

			// Device code MUST still be in "approved" — not silently consumed,
			// so the operator can still revoke or extend the approval, and the
			// caller is not locked out for the remainder of the code's TTL.
			dc, err := ts.Store.GetDeviceCodeByUserCode(ctx, authz.UserCode)
			if err != nil {
				t.Fatalf("re-read device code: %v", err)
			}
			if dc.State != "approved" {
				t.Errorf("device code state = %q, want %q (closed-account check must preserve approval)", dc.State, "approved")
			}
		})
	}
}

// #188 / RFC 8628 §3.5: when a device-flow client polls the token endpoint
// faster than the advertised `interval`, the AS MUST respond with
// `slow_down` so the client backs off. Authgate previously kept returning
// `authorization_pending` regardless of poll cadence, leaving aggressive
// or buggy clients free to hammer the DB.
//
// Cadence under test (FixedClock):
//
//	poll #1 (t=0)        — first poll seeds last_polled_at; expect authorization_pending
//	poll #2 (t=0)        — same instant; delta=0 < 5s interval; expect slow_down
//	advance clock +6s
//	poll #3 (t=6s)       — delta=6s >= 5s; expect authorization_pending again
func TestIntegration_DevicePolling_EnforcesSlowDown(t *testing.T) {
	ts := SetupTestServer(t)

	authz := startDeviceAuthorization(t, ts)

	first := pollDeviceToken(t, ts, authz.DeviceCode)
	if !strings.Contains(first.RawBody, "authorization_pending") {
		t.Fatalf("poll #1 want authorization_pending, got status=%d body=%s", first.StatusCode, first.RawBody)
	}

	second := pollDeviceToken(t, ts, authz.DeviceCode)
	if !strings.Contains(second.RawBody, "slow_down") {
		t.Fatalf("poll #2 (within interval) want slow_down, got status=%d body=%s", second.StatusCode, second.RawBody)
	}

	// Advance the test clock past the 5s interval and confirm polling
	// resumes its normal authorization_pending response — slow_down is a
	// back-off signal, not a permanent denial.
	ts.Clock.T = ts.Clock.T.Add(6 * time.Second)

	third := pollDeviceToken(t, ts, authz.DeviceCode)
	if !strings.Contains(third.RawBody, "authorization_pending") {
		t.Fatalf("poll #3 (after interval) want authorization_pending, got status=%d body=%s", third.StatusCode, third.RawBody)
	}
}

// #188 follow-up: slow_down must scope to `pending` polls only. After the
// user approves, the very next poll — even if it arrives within the same
// `interval` window that just produced a slow_down — must consume the
// device code and return tokens. This pins the pending-only scoping in
// GetDeviceAuthorizatonState so a future refactor cannot silently widen
// the gate to the approved branch.
func TestIntegration_DevicePolling_SlowDownThenApprove_Succeeds(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email: "device-slow-then-approve@test.com", EmailVerified: true, Name: "Slow Then Approve",
		Provider: "google", ProviderUserID: "test-google-sub",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	authz := startDeviceAuthorization(t, ts)

	first := pollDeviceToken(t, ts, authz.DeviceCode)
	if !strings.Contains(first.RawBody, "authorization_pending") {
		t.Fatalf("poll #1 want authorization_pending, got status=%d body=%s", first.StatusCode, first.RawBody)
	}
	second := pollDeviceToken(t, ts, authz.DeviceCode)
	if !strings.Contains(second.RawBody, "slow_down") {
		t.Fatalf("poll #2 want slow_down, got status=%d body=%s", second.StatusCode, second.RawBody)
	}

	if err := ts.Store.ApproveDeviceCode(ctx, authz.UserCode, user.ID); err != nil {
		t.Fatalf("approve device code: %v", err)
	}

	// Poll without advancing the clock — last_polled_at is still inside
	// the 5s interval from poll #2. The slow_down branch must not fire
	// because the row is now `approved`, and the consume transition must
	// proceed.
	third := pollDeviceToken(t, ts, authz.DeviceCode)
	if third.StatusCode != http.StatusOK {
		t.Fatalf("post-approve poll within interval should succeed, got status=%d body=%s", third.StatusCode, third.RawBody)
	}
	if third.AccessToken == "" {
		t.Fatal("post-approve poll should return access_token")
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

// device-samesite: the approve screen's CSRF cookie stays Strict.
//
// This is the other half of the session cookie being Lax. Loosening the
// session only widens top-level GET navigations; the state-changing form post
// is still double-submit gated, and this cookie is issued by a page on
// authgate's own origin, so Strict costs nothing and is kept.
func TestIntegration_DeviceApprovePage_CSRFCookieIsStrict(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email: "device-csrf@test.com", EmailVerified: true, Name: "Device CSRF",
		Provider: "google", ProviderUserID: "test-google-sub",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sessionID, err := ts.Store.CreateSession(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	authz := startDeviceAuthorization(t, ts)
	if authz.UserCode == "" {
		t.Fatal("device authorization returned an empty user_code; check op.UserCodeConfig in the test server")
	}

	req, err := http.NewRequest(http.MethodGet, ts.BaseURL+"/device?user_code="+url.QueryEscape(authz.UserCode), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: "authgate_session", Value: sessionID})

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatalf("device page: %v", err)
	}
	defer resp.Body.Close()

	// A live session must land on the consent screen, not bounce to the IdP.
	// The entry form and its error states also answer 200, so check the body:
	// only the consent screen carries the approve control.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device page status = %d, want 200 (redirect here means the session was not honoured)", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), `name="action"`) {
		t.Fatalf("did not reach the consent screen; page was:\n%s", string(body))
	}

	var csrf *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "csrf_token" {
			csrf = c
			break
		}
	}
	if csrf == nil {
		t.Fatal("approve page did not set a csrf_token cookie")
	}
	if csrf.SameSite != http.SameSiteStrictMode {
		t.Errorf("csrf_token SameSite = %v, want Strict", csrf.SameSite)
	}
	if !csrf.HttpOnly {
		t.Error("csrf_token HttpOnly = false, want true")
	}
}

// device-samesite-2: the device callback's session cookie must be Lax, and the
// redirect it issues must be the device page.
//
// This is the exact hop that failed in Safari: the callback mints the session
// and redirects to /device?user_code=…, and the browser only shows the consent
// screen if the cookie survives that redirect. WebKit drops a Strict cookie
// here because the chain was started cross-site by the IdP, so the device page
// saw no session and sent the user back to the IdP, forever.
//
// Go's client has no SameSite policy, so this cannot assert the browser
// behaviour — it pins the attribute that decides it.
func TestIntegration_DeviceCallback_SessionCookieIsLax(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	if _, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{
		Email: "device-lax@test.com", EmailVerified: true, Name: "Device Lax",
		Provider: "google", ProviderUserID: "test-google-sub",
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := ts.Store.StoreDeviceAuthorization(ctx, "test-client", "lax-dc", "LAX-CODE",
		ts.Clock.Now().Add(5*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("seed device_code: %v", err)
	}

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noFollow.Get(ts.BaseURL + "/device/auth/callback?code=fake-code&state=LAX-CODE")
	if err != nil {
		t.Fatalf("device callback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 302 body=%s", resp.StatusCode, string(body))
	}
	if loc := resp.Header.Get("Location"); loc != "/device?user_code=LAX-CODE" {
		t.Errorf("Location = %q, want /device?user_code=LAX-CODE", loc)
	}

	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "authgate_session" {
			session = c
			break
		}
	}
	if session == nil {
		t.Fatal("device callback did not set a session cookie")
	}
	if session.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite = %v, want Lax; Strict is dropped on the redirect that follows", session.SameSite)
	}
}
