package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// MockProvider is a fake IdP for development/testing.
// It redirects to a mock IdP server that auto-approves and returns a fixed user.
type MockProvider struct {
	// MockIDPURL is the internal URL of the mock IdP server.
	MockIDPURL string
	// MockIDPPublicURL is the external URL users see (may differ in Docker).
	MockIDPPublicURL string
	// RedirectURI is the authgate callback URL.
	RedirectURI string
}

func (m *MockProvider) Name() string { return "mock" }

func (m *MockProvider) AuthURL(state string) string {
	params := url.Values{
		"redirect_uri": {m.RedirectURI},
		"state":        {state},
	}
	return m.MockIDPPublicURL + "/authorize?" + params.Encode()
}

func (m *MockProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	// Step 1: Exchange code for access_token (same as Google flow)
	data := url.Values{
		"code":       {code},
		"grant_type": {"authorization_code"},
	}
	tokenReq, err := http.NewRequestWithContext(ctx, "POST", m.MockIDPURL+"/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("mock token request: %w", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("mock token exchange: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mock token exchange status: %d", tokenResp.StatusCode)
	}

	var tokenResult struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenResult); err != nil {
		return nil, fmt.Errorf("decode mock token: %w", err)
	}

	// Step 2: Fetch userinfo with access_token (same as Google flow)
	uReq, err := http.NewRequestWithContext(ctx, "GET", m.MockIDPURL+"/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("mock userinfo request: %w", err)
	}
	uReq.Header.Set("Authorization", "Bearer "+tokenResult.AccessToken)

	uResp, err := http.DefaultClient.Do(uReq)
	if err != nil {
		return nil, fmt.Errorf("mock userinfo: %w", err)
	}
	defer uResp.Body.Close()

	if uResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mock userinfo status: %d", uResp.StatusCode)
	}

	var info UserInfo
	if err := json.NewDecoder(uResp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode mock userinfo: %w", err)
	}
	return &info, nil
}

// FakeProvider returns a hardcoded user without any HTTP calls. For unit tests only.
type FakeProvider struct {
	User *UserInfo
}

func (f *FakeProvider) Name() string { return "google" }

func (f *FakeProvider) AuthURL(state string) string {
	return "/fake-auth?state=" + state
}

func (f *FakeProvider) Exchange(_ context.Context, _ string) (*UserInfo, error) {
	if f.User == nil {
		return nil, fmt.Errorf("fake provider: no user configured")
	}
	return f.User, nil
}
