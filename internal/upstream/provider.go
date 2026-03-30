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

// Provider abstracts the upstream IdP (Google, Mock).
// 2 methods: AuthURL to start login, Exchange to complete it.
type Provider interface {
	// AuthURL returns the URL to redirect the user to for authentication.
	// state is passed through and returned in the callback.
	AuthURL(state string) string

	// Exchange trades an authorization code for user info.
	Exchange(ctx context.Context, code string) (*UserInfo, error)
}
