package storage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

type testCIMDClientResolutionPolicy struct {
	s       *Storage
	fetcher CIMDFetcher
}

func (p testCIMDClientResolutionPolicy) ResolveClient(ctx context.Context, clientID string) (*ClientModel, error) {
	if v, ok := p.s.clients.Load(clientID); ok {
		return v.(*ClientModel), nil
	}
	if p.fetcher != nil && IsCIMDClientID(clientID) {
		return p.fetcher.FetchClient(ctx, clientID)
	}
	return nil, ErrNotFound
}

func TestGetClientByClientID_YAML(t *testing.T) {
	store := &Storage{}
	store.clients.Store("my-app", &ClientModel{
		ID:   "my-app",
		Name: "My App",
		Type: "public",
	})

	client, err := store.GetClientByClientID(context.Background(), "my-app")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != "my-app" {
		t.Errorf("client_id = %q, want %q", client.GetID(), "my-app")
	}
}

func TestGetClientByClientID_NotFound(t *testing.T) {
	store := &Storage{}

	_, err := store.GetClientByClientID(context.Background(), "nonexistent")
	if err != ErrNotFound {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestGetClientByClientID_CIMD(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := CIMDMetadata{
			ClientID:     serverURL + "/oauth/client.json",
			ClientName:   "CIMD Client",
			RedirectURIs: []string{"http://localhost:3000/callback"},
			GrantTypes:   []string{"authorization_code"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	defer srv.Close()
	serverURL = srv.URL

	store := &Storage{}
	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	store.SetClientResolutionPolicy(testCIMDClientResolutionPolicy{s: store, fetcher: fetcher})

	clientID := serverURL + "/oauth/client.json"
	client, err := store.GetClientByClientID(context.Background(), clientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != clientID {
		t.Errorf("client_id = %q, want %q", client.GetID(), clientID)
	}
}
