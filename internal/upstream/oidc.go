package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// OIDCProvider uses OIDC Discovery to connect to any OIDC-compliant IdP.
type OIDCProvider struct {
	name         string
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	discovery    *oidc.DiscoveryConfiguration
	httpClient   *http.Client
}

// NewOIDCProvider creates a provider by fetching the OIDC discovery document.
func NewOIDCProvider(ctx context.Context, issuerURL, clientID, clientSecret, redirectURI string) (*OIDCProvider, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	disc, err := client.Discover(ctx, issuerURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery from %s: %w", issuerURL, err)
	}

	// Derive provider name from issuer (e.g., "https://accounts.google.com" → "google")
	name := deriveProviderName(disc.Issuer)

	return &OIDCProvider{
		name:         name,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		scopes:       []string{"openid", "email", "profile"},
		discovery:    disc,
		httpClient:   httpClient,
	}, nil
}

func (p *OIDCProvider) Name() string { return p.name }

func (p *OIDCProvider) AuthURL(state string) string {
	params := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {p.redirectURI},
		"response_type": {"code"},
		"scope":         {strings.Join(p.scopes, " ")},
		"state":         {state},
	}
	return p.discovery.AuthorizationEndpoint + "?" + params.Encode()
}

func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	// Step 1: Exchange code for access_token at token_endpoint
	data := url.Values{
		"code":          {code},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"redirect_uri":  {p.redirectURI},
		"grant_type":    {"authorization_code"},
	}

	tokenReq, err := http.NewRequestWithContext(ctx, "POST", p.discovery.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := p.httpClient.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange status: %d", tokenResp.StatusCode)
	}

	var tokenResult struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenResult); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	// Step 2: Fetch userinfo with access_token
	uReq, err := http.NewRequestWithContext(ctx, "GET", p.discovery.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}
	uReq.Header.Set("Authorization", "Bearer "+tokenResult.AccessToken)

	uResp, err := p.httpClient.Do(uReq)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer uResp.Body.Close()

	if uResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo status: %d", uResp.StatusCode)
	}

	var info UserInfo
	if err := json.NewDecoder(uResp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	return &info, nil
}

// deriveProviderName extracts a short name from the issuer URL.
// "https://accounts.google.com" → "google"
// "http://localhost:8082" → "localhost"
func deriveProviderName(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return "unknown"
	}
	host := u.Hostname()
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		// e.g., accounts.google.com → "google"
		return parts[len(parts)-2]
	}
	return parts[0] // e.g., "localhost"
}
