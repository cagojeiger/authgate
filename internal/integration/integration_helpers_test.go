//go:build integration

package integration

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
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
