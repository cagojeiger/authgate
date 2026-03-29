package op

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	zop "github.com/zitadel/oidc/v3/pkg/op"
)

type Client struct {
	ID             string
	SecretHash     string
	ClientType     string
	Name           string
	RedirectURIs_  []string
	AllowedScopes_ []string
	DevMode_       bool
}

func (c *Client) GetID() string                { return c.ID }
func (c *Client) RedirectURIs() []string        { return c.RedirectURIs_ }
func (c *Client) PostLogoutRedirectURIs() []string { return nil }
func (c *Client) LoginURL(authRequestID string) string {
	return "/login?authRequestID=" + authRequestID
}

func (c *Client) ApplicationType() zop.ApplicationType {
	return zop.ApplicationTypeWeb
}

func (c *Client) AuthMethod() oidc.AuthMethod {
	if c.ClientType == "public" {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodPost
}

func (c *Client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *Client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{
		oidc.GrantTypeCode,
		oidc.GrantTypeRefreshToken,
		oidc.GrantTypeDeviceCode,
	}
}

func (c *Client) AccessTokenType() zop.AccessTokenType {
	return zop.AccessTokenTypeJWT
}

func (c *Client) IDTokenLifetime() time.Duration {
	return time.Hour
}

func (c *Client) DevMode() bool { return c.DevMode_ }

func (c *Client) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *Client) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *Client) IsScopeAllowed(scope string) bool {
	for _, s := range c.AllowedScopes_ {
		if s == scope {
			return true
		}
	}
	return false
}

func (c *Client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *Client) ClockSkew() time.Duration             { return 0 }
