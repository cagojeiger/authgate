package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

// OAuthClient automates the OAuth2 authorization code flow for testing.
type OAuthClient struct {
	t             *testing.T
	BaseURL       string
	ClientID      string
	RedirectURI   string
	AuthgateCallbackPath string
	CodeVerifier  string
	CodeChallenge string
	Client        *http.Client
}

// NewOAuthClient creates a test OAuth client with PKCE.
func NewOAuthClient(t *testing.T, baseURL string) *OAuthClient {
	return NewOAuthClientFor(t, baseURL, "test-client", "/login/callback")
}

// NewOAuthClientFor creates a test OAuth client with PKCE for a specific OAuth client/channel.
func NewOAuthClientFor(t *testing.T, baseURL, clientID, authgateCallbackPath string) *OAuthClient {
	t.Helper()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Stop at external redirects (our /callback)
			if strings.HasPrefix(req.URL.Path, "/callback") {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Generate PKCE
	verifier := make([]byte, 32)
	rand.Read(verifier)
	codeVerifier := base64.RawURLEncoding.EncodeToString(verifier)
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	return &OAuthClient{
		t:                   t,
		BaseURL:             baseURL,
		ClientID:            clientID,
		RedirectURI:         baseURL + "/callback",
		AuthgateCallbackPath: authgateCallbackPath,
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		Client:              client,
	}
}

// AuthorizeURL builds the /authorize URL with PKCE.
func (c *OAuthClient) AuthorizeURL() string {
	params := url.Values{
		"client_id":             {c.ClientID},
		"redirect_uri":          {c.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email offline_access"},
		"code_challenge":        {c.CodeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {"test-state"},
	}
	return c.BaseURL + "/authorize?" + params.Encode()
}

// AuthorizeURLNoPKCE builds /authorize without PKCE (should be rejected).
func (c *OAuthClient) AuthorizeURLNoPKCE() string {
	params := url.Values{
		"client_id":     {c.ClientID},
		"redirect_uri":  {c.RedirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"test-state"},
	}
	return c.BaseURL + "/authorize?" + params.Encode()
}

// StartAuthorize initiates the authorize flow and returns the redirect response.
func (c *OAuthClient) StartAuthorize() *http.Response {
	c.t.Helper()
	resp, err := c.Client.Get(c.AuthorizeURL())
	if err != nil {
		c.t.Fatalf("authorize: %v", err)
	}
	return resp
}

// ExchangeCode trades an authorization code for tokens.
func (c *OAuthClient) ExchangeCode(code string) *TokenResponse {
	c.t.Helper()
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.RedirectURI},
		"client_id":     {c.ClientID},
		"code_verifier": {c.CodeVerifier},
	}

	resp, err := http.Post(c.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		c.t.Fatalf("token exchange: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	tr := &TokenResponse{StatusCode: resp.StatusCode, RawBody: string(body)}

	if resp.StatusCode == 200 {
		json.Unmarshal(body, tr)
	}
	return tr
}

// RefreshToken exchanges a refresh token for new tokens.
func (c *OAuthClient) RefreshToken(refreshToken string) *TokenResponse {
	c.t.Helper()
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.ClientID},
	}

	resp, err := http.Post(c.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		c.t.Fatalf("refresh: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	tr := &TokenResponse{StatusCode: resp.StatusCode, RawBody: string(body)}

	if resp.StatusCode == 200 {
		json.Unmarshal(body, tr)
	}
	return tr
}

// ExtractCodeFromRedirect extracts the authorization code from a redirect Location header.
func ExtractCodeFromRedirect(resp *http.Response) string {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	return u.Query().Get("code")
}

type TokenResponse struct {
	StatusCode   int    `json:"-"`
	RawBody      string `json:"-"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}
