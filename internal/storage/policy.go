package storage

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type coreClientResolutionPolicy struct {
	s *Storage
}

func (p coreClientResolutionPolicy) ResolveClient(ctx context.Context, clientID string) (*ClientModel, error) {
	if v, ok := p.s.clients.Load(clientID); ok {
		return v.(*ClientModel), nil
	}
	return nil, ErrNotFound
}

type coreResourceBindingPolicy struct{}

func (coreResourceBindingPolicy) ValidateAuthorizeRequest(ctx context.Context, client *ClientModel, requestResource string) error {
	return nil
}

func (coreResourceBindingPolicy) ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error {
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

func NewCoreClientResolutionPolicy(s *Storage) ClientResolutionPolicy {
	return coreClientResolutionPolicy{s: s}
}

func NewCoreResourceBindingPolicy() ResourceBindingPolicy {
	return coreResourceBindingPolicy{}
}
