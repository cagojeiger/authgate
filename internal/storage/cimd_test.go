package storage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCIMDFetcher_Success(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := CIMDMetadata{
			ClientID:                serverURL + "/oauth/client.json",
			ClientName:              "Test MCP Client",
			RedirectURIs:            []string{"http://localhost:3000/callback"},
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{client: srv.Client()}
	clientID := serverURL + "/oauth/client.json"

	client, err := fetcher.FetchClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("FetchClient failed: %v", err)
	}
	if client.ID != clientID {
		t.Errorf("client_id = %q, want %q", client.ID, clientID)
	}
	if client.Name != "Test MCP Client" {
		t.Errorf("name = %q, want %q", client.Name, "Test MCP Client")
	}
	if client.LoginChannel != "mcp" {
		t.Errorf("login_channel = %q, want %q", client.LoginChannel, "mcp")
	}
	if client.Type != "public" {
		t.Errorf("type = %q, want %q", client.Type, "public")
	}
	if len(client.RedirectURIList) != 1 || client.RedirectURIList[0] != "http://localhost:3000/callback" {
		t.Errorf("redirect_uris = %v, want [http://localhost:3000/callback]", client.RedirectURIList)
	}
	if len(client.AllowedGrantTypeList) != 2 {
		t.Errorf("grant_types = %v, want 2 entries", client.AllowedGrantTypeList)
	}
}

func TestCIMDFetcher_ClientIDMismatch(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		meta := CIMDMetadata{
			ClientID:     "https://wrong.example.com/client.json",
			ClientName:   "Bad Client",
			RedirectURIs: []string{"http://localhost:3000/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	defer srv.Close()

	fetcher := &HTTPCIMDFetcher{client: srv.Client()}
	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/oauth/client.json")
	if err == nil {
		t.Fatal("expected error for client_id mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error = %q, want to contain 'mismatch'", err.Error())
	}
}

func TestCIMDFetcher_ServerDown(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	client := srv.Client()
	srv.Close()

	fetcher := &HTTPCIMDFetcher{client: client}
	_, err := fetcher.FetchClient(context.Background(), "https://localhost:99999/client.json")
	if err == nil {
		t.Fatal("expected error for server down, got nil")
	}
}

func TestCIMDFetcher_MissingClientName(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":    serverURL + "/client.json",
			"redirect_uris": []string{"http://localhost:3000/callback"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{client: srv.Client()}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for missing client_name, got nil")
	}
	if !strings.Contains(err.Error(), "client_name") {
		t.Errorf("error = %q, want to contain 'client_name'", err.Error())
	}
}

func TestCIMDFetcher_HTTP404(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	fetcher := &HTTPCIMDFetcher{client: srv.Client()}
	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/oauth/client.json")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestIsCIMDClientID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"https://app.example.com/oauth/client.json", true},
		{"https://app.example.com/client", true},
		{"https://app.example.com", false},
		{"http://app.example.com/client", false},
		{"my-app", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isCIMDClientID(tt.id); got != tt.want {
			t.Errorf("isCIMDClientID(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
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
	store.SetCIMDFetcher(&HTTPCIMDFetcher{client: srv.Client()})

	clientID := serverURL + "/oauth/client.json"
	client, err := store.GetClientByClientID(context.Background(), clientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != clientID {
		t.Errorf("client_id = %q, want %q", client.GetID(), clientID)
	}
}
