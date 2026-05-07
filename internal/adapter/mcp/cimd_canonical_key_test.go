package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

func TestCanonicalCIMDKey(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://attacker.example/c.json", "https://attacker.example/c.json"},
		{"https://Attacker.EXAMPLE/c.json", "https://attacker.example/c.json"},
		{"https://attacker.example:443/c.json", "https://attacker.example/c.json"},
		{"https://attacker.example//c.json", "https://attacker.example/c.json"},
		{"https://attacker.example/x/../c.json", "https://attacker.example/c.json"},
	}
	for _, tc := range cases {
		if got := canonicalCIMDKey(tc.in); got != tc.want {
			t.Errorf("canonicalCIMDKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCIMDFetcher_NegativeCacheNormalizesURLAliases verifies the bypass
// closed in this PR's review: trivial URL aliases must share the negative
// cache (and rate-limit budget) so they cannot each get a fresh failure
// quota.
func TestCIMDFetcher_NegativeCacheNormalizesURLAliases(t *testing.T) {
	fetchCount := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	clk := &clock.FixedClock{T: time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)}
	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clk, cacheTTL: 5 * time.Minute}

	canonical := srv.URL + "/c.json"
	aliased := srv.URL + "/x/../c.json"

	if _, err := fetcher.FetchClient(context.Background(), canonical); err == nil {
		t.Fatal("first fetch should fail")
	}
	if fetchCount != 1 {
		t.Fatalf("after first fetch, fetchCount = %d, want 1", fetchCount)
	}

	if _, err := fetcher.FetchClient(context.Background(), aliased); err == nil {
		t.Fatal("aliased fetch should fail")
	}
	if fetchCount != 1 {
		t.Errorf("aliased fetch issued HTTP, fetchCount = %d, want 1 (negative cache must merge URL aliases)", fetchCount)
	}
}
