package mcp

import (
	"context"
	"errors"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kangheeyong/authgate/internal/storage"
)

type clientResolutionPolicy struct {
	base    storage.ClientResolutionPolicy
	fetcher storage.CIMDFetcher
}

func (p *clientResolutionPolicy) ResolveClient(ctx context.Context, clientID string) (*storage.ClientModel, error) {
	client, err := p.base.ResolveClient(ctx, clientID)
	if err == nil {
		return client, nil
	}
	if p.fetcher != nil && storage.IsCIMDClientID(clientID) && errors.Is(err, storage.ErrNotFound) {
		return p.fetcher.FetchClient(ctx, clientID)
	}
	return nil, err
}

type resourceBindingPolicy struct {
	base storage.ResourceBindingPolicy
}

// ValidateAuthorizeRequest enforces the channel × resource matrix per
// RFC 8707 §2.2 AS-side policy and authgate spec 004:
//   - login_channel='mcp'     ⇒ resource is REQUIRED (the token would
//                                otherwise have no audience to bind to)
//   - login_channel='browser' ⇒ resource MUST NOT be present (a browser
//                                client minting an MCP-audience token is a
//                                boundary-confusion attack — issue #184)
//
// Once /authorize rejects browser+resource here, the core policy's
// existing "unexpected resource" check at /oauth/token covers the
// follow-on token and refresh paths transitively (storedResource will
// be empty for browser-channel auth_requests / refresh_tokens).
func (p *resourceBindingPolicy) ValidateAuthorizeRequest(ctx context.Context, client *storage.ClientModel, requestResource string) error {
	if client != nil {
		if client.LoginChannel == "mcp" {
			if requestResource == "" {
				return &oidc.Error{ErrorType: "invalid_target", Description: "missing resource"}
			}
		} else {
			if requestResource != "" {
				return &oidc.Error{ErrorType: "invalid_target", Description: "resource parameter not permitted for this client"}
			}
		}
	}
	return p.base.ValidateAuthorizeRequest(ctx, client, requestResource)
}

func (p *resourceBindingPolicy) ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error {
	return p.base.ValidateTokenRequest(ctx, clientID, storedResource, requestResource)
}

func NewClientResolutionPolicy(base storage.ClientResolutionPolicy, fetcher storage.CIMDFetcher) storage.ClientResolutionPolicy {
	return &clientResolutionPolicy{base: base, fetcher: fetcher}
}

func NewResourceBindingPolicy(base storage.ResourceBindingPolicy) storage.ResourceBindingPolicy {
	return &resourceBindingPolicy{base: base}
}

