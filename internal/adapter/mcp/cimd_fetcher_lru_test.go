package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

// TestCIMDFetcher_LRUEvictsOldest exercises the unbounded-cache OOM defense
// from #159: when the cache reaches its max-entries cap, the least-recently-
// used entry must be evicted instead of growing without bound.
func TestCIMDFetcher_LRUEvictsOldest(t *testing.T) {
	var fetchCount atomic.Int32
	var serverURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		meta := CIMDMetadata{
			ClientID:     serverURL + r.URL.Path,
			ClientName:   "x",
			RedirectURIs: []string{"http://localhost:3000/callback"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	}))
	defer srv.Close()
	serverURL = srv.URL

	const cap = 4
	fetcher := &HTTPCIMDFetcher{
		client:   srv.Client(),
		clock:    clock.RealClock{},
		cacheTTL: 5 * time.Minute,
		cacheMax: cap,
	}

	// Fill the cache to exactly cap+1 distinct entries; the first inserted
	// must be evicted.
	ids := make([]string, cap+1)
	for i := 0; i < cap+1; i++ {
		ids[i] = fmt.Sprintf("%s/c%d.json", serverURL, i)
	}
	for _, id := range ids {
		if _, err := fetcher.FetchClient(context.Background(), id); err != nil {
			t.Fatalf("fetch %s: %v", id, err)
		}
	}
	if got := fetchCount.Load(); got != int32(cap+1) {
		t.Fatalf("fetchCount after fill = %d, want %d", got, cap+1)
	}

	// The most-recent cap entries should still be cache hits.
	prev := fetchCount.Load()
	for i := 1; i <= cap; i++ {
		if _, err := fetcher.FetchClient(context.Background(), ids[i]); err != nil {
			t.Fatalf("recent re-fetch %s: %v", ids[i], err)
		}
	}
	if got := fetchCount.Load(); got != prev {
		t.Errorf("fetchCount after recent re-fetch = %d, want %d (recent should be cached)", got, prev)
	}

	// The oldest (ids[0]) must have been evicted; refetching triggers a new HTTP call.
	prev = fetchCount.Load()
	if _, err := fetcher.FetchClient(context.Background(), ids[0]); err != nil {
		t.Fatalf("oldest re-fetch: %v", err)
	}
	if got := fetchCount.Load(); got != prev+1 {
		t.Errorf("fetchCount after oldest re-fetch = %d, want %d (oldest must have been evicted)", got, prev+1)
	}
}
