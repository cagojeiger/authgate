package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

func (m *MockProvider) AuthURL(state string) string {
	params := url.Values{
		"redirect_uri": {m.RedirectURI},
		"state":        {state},
	}
	return m.MockIDPPublicURL + "/authorize?" + params.Encode()
}

func (m *MockProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	// Exchange code with mock IdP
	resp, err := http.Get(m.MockIDPURL + "/userinfo?code=" + url.QueryEscape(code))
	if err != nil {
		return nil, fmt.Errorf("mock exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mock exchange status: %d", resp.StatusCode)
	}

	var info UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode mock userinfo: %w", err)
	}
	return &info, nil
}

// FakeProvider returns a hardcoded user without any HTTP calls. For unit tests only.
type FakeProvider struct {
	User *UserInfo
}

func (f *FakeProvider) AuthURL(state string) string {
	return "/fake-auth?state=" + state
}

func (f *FakeProvider) Exchange(_ context.Context, _ string) (*UserInfo, error) {
	if f.User == nil {
		return nil, fmt.Errorf("fake provider: no user configured")
	}
	return f.User, nil
}
