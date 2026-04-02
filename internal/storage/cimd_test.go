package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
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

	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
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

	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
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

	fetcher := &HTTPCIMDFetcher{client: client, clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
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
			"client_id":     serverURL + "/client.json",
			"redirect_uris": []string{"http://localhost:3000/callback"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
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

	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/oauth/client.json")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestCIMDFetcher_InvalidContentType(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/oauth/client.json")
	if err == nil {
		t.Fatal("expected error for invalid content-type, got nil")
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Errorf("error = %q, want to contain 'Content-Type'", err.Error())
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
		{"https:///oauth/client.json", false},
		{"https://user:pass@app.example.com/client.json", false},
		{"https://app.example.com/client.json?x=1", false},
		{"https://app.example.com/client.json#frag", false},
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

func TestCIMDFetcher_UnsupportedAuthMethod(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  serverURL + "/client.json",
			"client_name":                "Bad Auth",
			"redirect_uris":              []string{"http://localhost:3000/callback"},
			"token_endpoint_auth_method": "client_secret_post",
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for unsupported auth method, got nil")
	}
	if !strings.Contains(err.Error(), "token_endpoint_auth_method") {
		t.Errorf("error = %q, want to contain 'token_endpoint_auth_method'", err.Error())
	}
}

func TestCIMDFetcher_UnsupportedResponseType(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":      serverURL + "/client.json",
			"client_name":    "Bad RT",
			"redirect_uris":  []string{"http://localhost:3000/callback"},
			"response_types": []string{"token"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for unsupported response_type, got nil")
	}
	if !strings.Contains(err.Error(), "response_type") {
		t.Errorf("error = %q, want to contain 'response_type'", err.Error())
	}
}

func TestCIMDFetcher_OversizedDocument(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write 11KB of padding
		w.Write([]byte(`{"client_id":"x","padding":"`))
		for i := 0; i < 11*1024; i++ {
			w.Write([]byte("a"))
		}
		w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/client.json")
	if err == nil {
		t.Fatal("expected error for oversized document, got nil")
	}
	if !strings.Contains(err.Error(), "10KB") {
		t.Errorf("error = %q, want to contain '10KB'", err.Error())
	}
}

func TestCIMDFetcher_UnsupportedGrantType(t *testing.T) {
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     serverURL + "/client.json",
			"client_name":   "Bad Grant",
			"redirect_uris": []string{"http://localhost:3000/callback"},
			"grant_types":   []string{"client_credentials"},
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	_, err := fetcher.FetchClient(context.Background(), serverURL+"/client.json")
	if err == nil {
		t.Fatal("expected error for unsupported grant_type, got nil")
	}
	if !strings.Contains(err.Error(), "grant_type") {
		t.Errorf("error = %q, want to contain 'grant_type'", err.Error())
	}
}

func TestCIMDFetcher_RedirectRejected(t *testing.T) {
	// Target server that the redirect points to
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"client_id":"x","client_name":"x","redirect_uris":["http://localhost:3000/callback"]}`))
	}))
	defer target.Close()

	// Server that redirects to target
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/client.json", http.StatusFound)
	}))
	defer srv.Close()

	fetcher := &HTTPCIMDFetcher{
		client:   srv.Client(),
		clock:    clock.RealClock{},
		cacheTTL: 5 * time.Minute,
	}
	// CheckRedirect is only set in NewHTTPCIMDFetcher, so set it manually for test
	fetcher.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("cimd: redirects not allowed")
	}

	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/client.json")
	if err == nil {
		t.Fatal("expected error for redirect, got nil")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Errorf("error = %q, want to contain 'redirect'", err.Error())
	}
}

func TestCIMDFetcher_CacheHit(t *testing.T) {
	fetchCount := 0
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		meta := CIMDMetadata{
			ClientID:     serverURL + "/client.json",
			ClientName:   "Cached Client",
			RedirectURIs: []string{"http://localhost:3000/callback"},
			GrantTypes:   []string{"authorization_code"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	defer srv.Close()
	serverURL = srv.URL

	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}
	clientID := serverURL + "/client.json"

	// First fetch — network call
	_, err := fetcher.FetchClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	// Second fetch — should be cached
	_, err = fetcher.FetchClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}

	if fetchCount != 1 {
		t.Errorf("fetchCount = %d, want 1 (second call should be cached)", fetchCount)
	}
}

func TestCIMDFetcher_NegativeCache(t *testing.T) {
	fetchCount := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	clk := &clock.FixedClock{T: time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)}
	fetcher := &HTTPCIMDFetcher{
		client:           srv.Client(),
		clock:            clk,
		cacheTTL:         5 * time.Minute,
		negativeCacheTTL: 30 * time.Second,
	}

	_, err := fetcher.FetchClient(context.Background(), srv.URL+"/client.json")
	if err == nil {
		t.Fatal("expected first fetch to fail, got nil")
	}
	_, err = fetcher.FetchClient(context.Background(), srv.URL+"/client.json")
	if err == nil {
		t.Fatal("expected second fetch to fail from negative cache, got nil")
	}
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d, want 1 (second call should be negative cached)", fetchCount)
	}

	clk.T = clk.T.Add(31 * time.Second)
	_, err = fetcher.FetchClient(context.Background(), srv.URL+"/client.json")
	if err == nil {
		t.Fatal("expected third fetch to fail after negative cache expiry, got nil")
	}
	if fetchCount != 2 {
		t.Errorf("fetchCount = %d, want 2 (negative cache should have expired)", fetchCount)
	}
}

func TestCIMDFetcher_CacheExpiry(t *testing.T) {
	fetchCount := 0
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		meta := CIMDMetadata{
			ClientID:     serverURL + "/client.json",
			ClientName:   "Cached Client",
			RedirectURIs: []string{"http://localhost:3000/callback"},
			GrantTypes:   []string{"authorization_code"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	defer srv.Close()
	serverURL = srv.URL

	// Use FixedClock so we can advance time
	clk := &clock.FixedClock{T: time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)}
	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clk, cacheTTL: 5 * time.Minute}
	clientID := serverURL + "/client.json"

	// First fetch — network call
	_, err := fetcher.FetchClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}
	if fetchCount != 1 {
		t.Fatalf("fetchCount = %d, want 1", fetchCount)
	}

	// Second fetch — cached (same time)
	_, err = fetcher.FetchClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}
	if fetchCount != 1 {
		t.Fatalf("fetchCount = %d, want 1 (should be cached)", fetchCount)
	}

	// Advance clock past TTL
	clk.T = clk.T.Add(6 * time.Minute)

	// Third fetch — cache expired, should re-fetch
	_, err = fetcher.FetchClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("third fetch failed: %v", err)
	}
	if fetchCount != 2 {
		t.Errorf("fetchCount = %d, want 2 (cache should have expired)", fetchCount)
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
	store.SetCIMDFetcher(&HTTPCIMDFetcher{client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute})

	clientID := serverURL + "/oauth/client.json"
	client, err := store.GetClientByClientID(context.Background(), clientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetID() != clientID {
		t.Errorf("client_id = %q, want %q", client.GetID(), clientID)
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.1", true},
		{"169.254.1.1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"::ffff:127.0.0.1", true},
		{"8.8.8.8", false},
		{"2001:4860:4860::8888", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := isPrivateIP(ip); got != tt.want {
			t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
