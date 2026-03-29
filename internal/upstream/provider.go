package upstream

import "context"

type Provider interface {
	AuthURL(state string) string
	Exchange(ctx context.Context, code string) (*UserInfo, error)
}

type UserInfo struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	Picture        string
}
