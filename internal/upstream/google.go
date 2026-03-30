package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type GoogleProvider struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string // e.g. https://auth.example.com/login/callback
	client       *http.Client
}

func (g *GoogleProvider) Name() string { return "google" }

func (g *GoogleProvider) httpClient() *http.Client {
	if g.client != nil {
		return g.client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (g *GoogleProvider) AuthURL(state string) string {
	params := url.Values{
		"client_id":     {g.ClientID},
		"redirect_uri":  {g.RedirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
	}
	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}

func (g *GoogleProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	// Exchange code for tokens
	data := url.Values{
		"code":          {code},
		"client_id":     {g.ClientID},
		"client_secret": {g.ClientSecret},
		"redirect_uri":  {g.RedirectURI},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange status: %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	// Fetch userinfo
	uReq, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}
	uReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	uResp, err := http.DefaultClient.Do(uReq)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer uResp.Body.Close()

	var info UserInfo
	if err := json.NewDecoder(uResp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	return &info, nil
}
