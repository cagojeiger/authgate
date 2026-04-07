package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/kangheeyong/authgate/internal/storage"
)

type fakeClientPolicy struct {
	client *storage.ClientModel
	err    error
}

func (f fakeClientPolicy) ResolveClient(ctx context.Context, clientID string) (*storage.ClientModel, error) {
	return f.client, f.err
}

type fakeFetcher struct {
	client *storage.ClientModel
	err    error
	calls  int
}

func (f *fakeFetcher) FetchClient(ctx context.Context, clientID string) (*storage.ClientModel, error) {
	f.calls++
	return f.client, f.err
}

type fakeResourcePolicy struct {
	authorizeErr error
	tokenErr     error
	authCalls    int
	tokenCalls   int
}

func (f *fakeResourcePolicy) ValidateAuthorizeRequest(ctx context.Context, client *storage.ClientModel, requestResource string) error {
	f.authCalls++
	return f.authorizeErr
}

func (f *fakeResourcePolicy) ValidateTokenRequest(ctx context.Context, clientID, storedResource, requestResource string) error {
	f.tokenCalls++
	return f.tokenErr
}

func TestClientResolutionPolicy_UsesBaseFirst(t *testing.T) {
	baseClient := &storage.ClientModel{ID: "my-app"}
	fetcher := &fakeFetcher{client: &storage.ClientModel{ID: "fetched"}}
	p := NewClientResolutionPolicy(fakeClientPolicy{client: baseClient}, fetcher)

	client, err := p.ResolveClient(context.Background(), "my-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != "my-app" {
		t.Fatalf("client id = %s, want my-app", client.GetID())
	}
	if fetcher.calls != 0 {
		t.Fatalf("fetcher calls = %d, want 0", fetcher.calls)
	}
}

func TestClientResolutionPolicy_FallsBackToCIMD(t *testing.T) {
	fetcher := &fakeFetcher{client: &storage.ClientModel{ID: "https://mcp.example.com/client.json"}}
	p := NewClientResolutionPolicy(fakeClientPolicy{err: storage.ErrNotFound}, fetcher)

	clientID := "https://mcp.example.com/client.json"
	client, err := p.ResolveClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != clientID {
		t.Fatalf("client id = %s, want %s", client.GetID(), clientID)
	}
	if fetcher.calls != 1 {
		t.Fatalf("fetcher calls = %d, want 1", fetcher.calls)
	}
}

func TestClientResolutionPolicy_NoFallbackForNonCIMD(t *testing.T) {
	fetcher := &fakeFetcher{client: &storage.ClientModel{ID: "fetched"}}
	p := NewClientResolutionPolicy(fakeClientPolicy{err: storage.ErrNotFound}, fetcher)

	_, err := p.ResolveClient(context.Background(), "my-app")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	if fetcher.calls != 0 {
		t.Fatalf("fetcher calls = %d, want 0", fetcher.calls)
	}
}

func TestResourceBindingPolicy_EnforcesMCPResource(t *testing.T) {
	base := &fakeResourcePolicy{}
	p := NewResourceBindingPolicy(base)

	err := p.ValidateAuthorizeRequest(context.Background(), &storage.ClientModel{LoginChannel: "mcp"}, "")
	if err == nil {
		t.Fatal("expected invalid_target error")
	}
	var oidcErr *oidc.Error
	if !errors.As(err, &oidcErr) || oidcErr.ErrorType != "invalid_target" {
		t.Fatalf("error = %v, want oidc invalid_target", err)
	}
	if base.authCalls != 0 {
		t.Fatalf("base auth calls = %d, want 0", base.authCalls)
	}
}

func TestResourceBindingPolicy_DelegatesToBase(t *testing.T) {
	wantErr := errors.New("base authorize denied")
	base := &fakeResourcePolicy{authorizeErr: wantErr}
	p := NewResourceBindingPolicy(base)

	err := p.ValidateAuthorizeRequest(context.Background(), &storage.ClientModel{LoginChannel: "browser"}, "")
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if base.authCalls != 1 {
		t.Fatalf("base auth calls = %d, want 1", base.authCalls)
	}
}

func TestResourceBindingPolicy_TokenDelegatesToBase(t *testing.T) {
	wantErr := errors.New("base token denied")
	base := &fakeResourcePolicy{tokenErr: wantErr}
	p := NewResourceBindingPolicy(base)

	err := p.ValidateTokenRequest(context.Background(), "c1", "r1", "r1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if base.tokenCalls != 1 {
		t.Fatalf("base token calls = %d, want 1", base.tokenCalls)
	}
}

