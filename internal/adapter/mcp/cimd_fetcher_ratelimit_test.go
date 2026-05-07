package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

// TestCIMDFetcher_RateLimitsRepeatedFailures covers the per-client failure
// rate limit from #156: once a single `client_id` produces enough failures
// inside the failure window, further attempts must be rejected without
// issuing a new outbound HTTP request — even after the negative-cache TTL
// expires.
func TestCIMDFetcher_RateLimitsRepeatedFailures(t *testing.T) {
	fetchCount := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	clk := &clock.FixedClock{T: time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)}
	fetcher := &HTTPCIMDFetcher{
		client:   srv.Client(),
		clock:    clk,
		cacheTTL: 5 * time.Minute,
	}
	clientID := srv.URL + "/c.json"

	// Trip the limit. We advance past the negative-cache TTL between calls so
	// each attempt actually reaches fetchAndValidate and registers a failure.
	for i := 0; i < cimdFailureLimit; i++ {
		if _, err := fetcher.FetchClient(context.Background(), clientID); err == nil {
			t.Fatalf("call %d expected error, got nil", i+1)
		}
		clk.T = clk.T.Add(cimdNegativeCacheTTL + time.Second)
	}
	if fetchCount != cimdFailureLimit {
		t.Fatalf("fetchCount after limit = %d, want %d", fetchCount, cimdFailureLimit)
	}

	// Next attempt is still inside the failure window. It must be rejected
	// without an outbound call.
	prev := fetchCount
	_, err := fetcher.FetchClient(context.Background(), clientID)
	if err == nil {
		t.Fatal("rate-limited call expected error, got nil")
	}
	if fetchCount != prev {
		t.Errorf("fetchCount after rate-limited call = %d, want %d (must not issue HTTP)", fetchCount, prev)
	}

	// After the failure window passes the fetcher should accept new attempts.
	clk.T = clk.T.Add(cimdFailureWindow + time.Second)
	_, err = fetcher.FetchClient(context.Background(), clientID)
	if err == nil {
		t.Fatal("post-window call expected error, got nil")
	}
	if fetchCount != prev+1 {
		t.Errorf("fetchCount after window expiry = %d, want %d (window should reopen)", fetchCount, prev+1)
	}
}

// TestCIMDFetcher_RateLimitIsPerClientID confirms a flood against one
// `client_id` does not block lookups for a different `client_id`.
func TestCIMDFetcher_RateLimitIsPerClientID(t *testing.T) {
	failPath := "/bad.json"
	okPath := "/good.json"
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == failPath {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":"` + serverURL + okPath + `","client_name":"ok","redirect_uris":["http://localhost:3000/callback"]}`))
	}))
	defer srv.Close()
	serverURL = srv.URL

	clk := &clock.FixedClock{T: time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)}
	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clk, cacheTTL: 5 * time.Minute}

	failID := serverURL + failPath
	for i := 0; i < cimdFailureLimit+1; i++ {
		_, _ = fetcher.FetchClient(context.Background(), failID)
		clk.T = clk.T.Add(cimdNegativeCacheTTL + time.Second)
	}
	// Different client_id must succeed even when the failing one is rate-limited.
	if _, err := fetcher.FetchClient(context.Background(), serverURL+okPath); err != nil {
		t.Fatalf("unrelated client_id should succeed: %v", err)
	}
}
