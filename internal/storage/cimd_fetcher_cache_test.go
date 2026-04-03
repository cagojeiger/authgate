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
