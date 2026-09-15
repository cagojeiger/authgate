package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

// anyCIMDHost lets fetcher tests serve documents from httptest's 127.0.0.1.
var anyCIMDHost = CIMDHostPolicy{any: true}

func TestNewCIMDHostPolicy_Rejects(t *testing.T) {
	cases := map[string][]string{
		"empty":              {},
		"wildcard mixed":     {"*", "claude.ai"},
		"wildcard subdomain": {"*.claude.ai"},
		"uppercase":          {"Claude.ai"},
		"scheme":             {"https://claude.ai"},
		"port":               {"claude.ai:443"},
		"path":               {"claude.ai/oauth"},
		"trailing dot":       {"claude.ai."},
		"blank":              {""},
	}
	for name, hosts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewCIMDHostPolicy(hosts); err == nil {
				t.Fatalf("NewCIMDHostPolicy(%q) accepted, want error", hosts)
			}
		})
	}
}

func TestCIMDHostPolicy_AllowsClientID(t *testing.T) {
	policy, err := NewCIMDHostPolicy(DefaultCIMDHosts)
	if err != nil {
		t.Fatalf("default hosts rejected: %v", err)
	}
	allowed := []string{
		"https://claude.ai/oauth/mcp-oauth-client-metadata",
		"https://claude.ai/oauth/claude-code-client-metadata",
		"https://chatgpt.com/oauth/9BWqfVvUDl53/client.json?token_endpoint_auth_method=none",
		"https://claude.ai:8443/oauth/client.json",
	}
	for _, id := range allowed {
		if !policy.allowsClientID(id) {
			t.Errorf("allowsClientID(%q) = false, want true", id)
		}
	}
	refused := []string{
		"https://evil.example.com/oauth/client.json",
		"https://evil.claude.ai/oauth/client.json",
		"https://claude.ai.evil.example.com/oauth/client.json",
		"https://notclaude.ai/oauth/client.json",
		"https://chatgpt.com@evil.example.com/client.json",
		"://bad",
	}
	for _, id := range refused {
		if policy.allowsClientID(id) {
			t.Errorf("allowsClientID(%q) = true, want false", id)
		}
	}

	if (CIMDHostPolicy{}).allowsClientID("https://claude.ai/oauth/client.json") {
		t.Error("zero CIMDHostPolicy admitted a host, want none")
	}
	star, err := NewCIMDHostPolicy([]string{AnyCIMDHost})
	if err != nil {
		t.Fatalf("\"*\" rejected: %v", err)
	}
	if !star.allowsClientID("https://evil.example.com/oauth/client.json") {
		t.Error("\"*\" policy refused a host, want every host admitted")
	}
}

// A client_id outside the allowlist must be refused before any network
// request, so an attacker's document is never even read.
func TestCIMDFetcher_RefusesHostOutsideAllowlistWithoutFetching(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	policy, err := NewCIMDHostPolicy([]string{"claude.ai"})
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &HTTPCIMDFetcher{hosts: policy, client: srv.Client(), clock: clock.RealClock{}, cacheTTL: 5 * time.Minute}

	for range 3 {
		_, err := fetcher.FetchClient(context.Background(), srv.URL+"/oauth/client.json")
		if !errors.Is(err, errCIMDHostNotAllowed) {
			t.Fatalf("FetchClient error = %v, want errCIMDHostNotAllowed", err)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("document server received %d requests, want 0", n)
	}
	if fetcher.ensureFailures().IsRateLimited(srv.URL+"/oauth/client.json", time.Now()) {
		t.Fatal("refused host was recorded as a fetch failure")
	}
}
