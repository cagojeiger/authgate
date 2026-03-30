package upstream

import "context"

// UserInfo holds identity data returned from the upstream IdP.
type UserInfo struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}

// Provider abstracts the upstream OIDC IdP.
type Provider interface {
	// Name returns the provider identifier stored in user_identities.provider.
	Name() string

	// AuthURL returns the URL to redirect the user to for authentication.
	AuthURL(state string) string

	// Exchange trades an authorization code for user info.
	Exchange(ctx context.Context, code string) (*UserInfo, error)
}
