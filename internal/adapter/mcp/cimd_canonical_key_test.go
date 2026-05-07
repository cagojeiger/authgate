package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestIsCanonicalCIMDClientID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Already canonical.
		{"https://example.com/c.json", true},
		{"https://example.com/path/c.json", true},

		// Host case.
		{"https://Example.com/c.json", false},

		// Default port.
		{"https://example.com:443/c.json", false},

		// Path normalization.
		{"https://example.com//c.json", false},
		{"https://example.com/x/../c.json", false},

		// Percent-encoding (decodes to a different canonical form).
		{"https://example.com/a%2Fb/c.json", false},

		// Non-ASCII host (closes IDN/Unicode alias class).
		{"https://мирзоев.example/c.json", false},
	}
	for _, tc := range cases {
		if got := isCanonicalCIMDClientID(tc.in); got != tc.want {
			t.Errorf("isCanonicalCIMDClientID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestCIMDFetcher_RejectsNonCanonicalAtGate verifies the gate fix from the
// PR review: non-canonical inputs must be rejected before any cache,
// rate-limit, or HTTP work happens. This closes both the alias rate-limit
// bypass and the positive-cache mis-attribution between aliases sharing a
// canonical key.
func TestCIMDFetcher_RejectsNonCanonicalAtGate(t *testing.T) {
	fetchCount := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	clk := &clock.FixedClock{T: time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)}
	fetcher := &HTTPCIMDFetcher{client: srv.Client(), clock: clk, cacheTTL: 5 * time.Minute}

	// httptest URL is https://127.0.0.1:<port>/, so :443 stripping and host
	// case don't apply directly; exercise path-aliasing instead, which is
	// representative of the alias class.
	aliases := []string{
		srv.URL + "//c.json",
		srv.URL + "/x/../c.json",
		srv.URL + "/a%2Fb/c.json",
	}
	for _, alias := range aliases {
		_, err := fetcher.FetchClient(context.Background(), alias)
		if err == nil {
			t.Fatalf("FetchClient(%q) should reject non-canonical input", alias)
		}
		if !strings.Contains(err.Error(), "canonical") {
			t.Errorf("FetchClient(%q) error = %q, want to mention 'canonical'", alias, err.Error())
		}
	}
	if fetchCount != 0 {
		t.Errorf("fetchCount = %d, want 0 (gate must reject before HTTP)", fetchCount)
	}
}
