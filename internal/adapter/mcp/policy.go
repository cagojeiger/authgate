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

func (p *resourceBindingPolicy) ValidateAuthorizeRequest(ctx context.Context, client *storage.ClientModel, requestResource string) error {
	if requestResource == "" && client != nil && client.LoginChannel == "mcp" {
		return &oidc.Error{ErrorType: "invalid_target", Description: "missing resource"}
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

