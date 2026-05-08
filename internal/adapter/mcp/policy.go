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
	base     storage.ResourceBindingPolicy
	resolver storage.ClientResolutionPolicy
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

// ValidateTokenRequest enforces the channel × resource matrix at the
// token endpoint. The /authorize gate is the primary enforcement point;
// this hook makes the fix self-healing for any data minted before the
// gate landed and is a defense-in-depth pass for direct token requests.
//
//   - A non-empty `storedResource` on a non-MCP client is a refresh
//     token (or auth_request) created before #184 closed the gate.
//     Reject with `invalid_grant` so the legacy binding fails closed
//     on first reuse rather than continuing to mint MCP-aud tokens
//     forever.
//   - A non-empty `requestResource` on a non-MCP client mirrors the
//     /authorize check on the off chance the request bypassed the
//     primary gate.
//
// `resolver` may be nil; in that case the wrapper degrades to base
// behavior (used by tests that don't need legacy-data coverage).
func (p *resourceBindingPolicy) ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error {
	if (storedResource != "" || requestResource != "") && p.resolver != nil {
		client, err := p.resolver.ResolveClient(ctx, clientID)
		if err == nil && client != nil && client.LoginChannel != "mcp" {
			if storedResource != "" {
				return &oidc.Error{ErrorType: "invalid_grant", Description: "persisted resource binding invalid for client channel"}
			}
			return &oidc.Error{ErrorType: "invalid_target", Description: "resource parameter not permitted for this client"}
		}
	}
	return p.base.ValidateTokenRequest(ctx, clientID, storedResource, requestResource)
}

func NewClientResolutionPolicy(base storage.ClientResolutionPolicy, fetcher storage.CIMDFetcher) storage.ClientResolutionPolicy {
	return &clientResolutionPolicy{base: base, fetcher: fetcher}
}

// NewResourceBindingPolicy returns the MCP-aware wrapper. `resolver` is
// used to look up the client's login_channel for the legacy-data and
// defense-in-depth checks at the token endpoint; it may be nil when the
// caller has no client registry (test-only).
func NewResourceBindingPolicy(base storage.ResourceBindingPolicy, resolver storage.ClientResolutionPolicy) storage.ResourceBindingPolicy {
	return &resourceBindingPolicy{base: base, resolver: resolver}
}

