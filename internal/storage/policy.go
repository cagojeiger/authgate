package storage

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type defaultClientResolutionPolicy struct {
	s *Storage
}

func (p defaultClientResolutionPolicy) ResolveClient(ctx context.Context, clientID string) (*ClientModel, error) {
	if v, ok := p.s.clients.Load(clientID); ok {
		return v.(*ClientModel), nil
	}
	if p.s.cimdFetcher != nil && isCIMDClientID(clientID) {
		return p.s.cimdFetcher.FetchClient(ctx, clientID)
	}
	return nil, ErrNotFound
}

type defaultResourceBindingPolicy struct{}

func (defaultResourceBindingPolicy) ValidateAuthorizeRequest(ctx context.Context, client *ClientModel, requestResource string) error {
	if requestResource == "" && client != nil && client.LoginChannel == "mcp" {
		return &oidc.Error{ErrorType: "invalid_target", Description: "missing resource"}
	}
	return nil
}

func (defaultResourceBindingPolicy) ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error {
	if storedResource != "" {
		if requestResource == "" {
			return &oidc.Error{ErrorType: "invalid_target", Description: "missing resource"}
		}
		if requestResource != storedResource {
			return &oidc.Error{ErrorType: "invalid_target", Description: "resource mismatch"}
		}
		return nil
	}
	if requestResource != "" {
		return &oidc.Error{ErrorType: "invalid_target", Description: "unexpected resource"}
	}
	return nil
}

