package mcp

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/storage"
	"golang.org/x/sync/singleflight"
)

// CIMDMetadata represents a Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document).
type CIMDMetadata struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

const (
	maxCIMDDocSize           = 10 * 1024
	maxCIMDClientIDLength    = 2048
	maxCIMDClientNameLength  = 256
	maxCIMDRedirectURICount  = 10
	maxCIMDRedirectURILength = 2048
	maxCIMDGrantTypeCount    = 8
	maxCIMDResponseTypeCount = 1

	// cimdCacheMaxEntries caps the in-memory cache so a flood of unique
	// client_id URLs cannot grow the cache without bound (see #159).
	cimdCacheMaxEntries = 4096

	// cimdNegativeCacheTTL short-circuits repeat lookups of a failing
	// client_id so a flood of identical requests cannot keep issuing fresh
	// outbound HTTP fetches (see #156).
	cimdNegativeCacheTTL = 30 * time.Second

	// cimdFloorTTL is the minimum positive-cache TTL applied to any
	// successful response. Server-stated max-age values smaller than this
	// (including `no-store` / `no-cache` / `max-age<=0`) are raised to the
	// floor so back-to-back identical fetches cannot keep stalling the
	// worker pool when the upstream is slow (see #158).
	cimdFloorTTL = 5 * time.Second

	// cimdCeilTTL caps the positive-cache TTL. A malicious or misbehaving CIMD
	// server sending e.g. `Cache-Control: max-age=99999999` would otherwise pin
	// stale client metadata (including redirect_uris) for years; clamping to a
	// day bounds how long a client's published document can go re-fetched.
	cimdCeilTTL = 24 * time.Hour
)

// HTTPCIMDFetcher fetches CIMD metadata via HTTP with SSRF protection and caching.
type HTTPCIMDFetcher struct {
	client    *http.Client
	clock     clock.Clock
	cache     *cimdCache
	cacheTTL  time.Duration
	cacheMax  int // overrides cimdCacheMaxEntries when > 0; primarily for tests.
	cacheOnce sync.Once
	sf        singleflight.Group

	failures     *failureTracker
	failuresOnce sync.Once
}

func (f *HTTPCIMDFetcher) ensureCache() *cimdCache {
	f.cacheOnce.Do(func() {
		max := f.cacheMax
		if max <= 0 {
			max = cimdCacheMaxEntries
		}
		f.cache = newCIMDCache(max)
	})
	return f.cache
}

func (f *HTTPCIMDFetcher) ensureFailures() *failureTracker {
	f.failuresOnce.Do(func() {
		max := f.cacheMax
		if max <= 0 {
			max = cimdCacheMaxEntries
		}
		f.failures = newFailureTracker(max)
	})
	return f.failures
}

// canonicalCIMDKey returns the canonical form of clientID:
//   - lowercase host
//   - default `:443` removed
//   - path.Clean (collapses `//`, resolves `..`)
//   - any percent-encoding in the path normalized to its decoded form
//
// Used by isCanonicalCIMDClientID to gate non-canonical inputs at the door
// so that an attacker cannot defeat the per-client_id rate limit (or
// silently mis-attribute a positive-cache entry to an alias) by mutating
// trivial parts of the URL.
func canonicalCIMDKey(clientID string) string {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return clientID
	}
	host := strings.ToLower(u.Hostname())
	if p := u.Port(); p != "" && p != "443" {
		host += ":" + p
	}
	u.Host = host
	if u.Path != "" {
		cleaned := path.Clean(u.Path)
		if cleaned == "." {
			cleaned = "/"
		}
		u.Path = cleaned
	}
	u.RawPath = ""
	u.Fragment = ""
	return u.String()
}

// isCanonicalCIMDClientID rejects non-ASCII inputs (closes the IDN/punycode
// alias class) and inputs that are not already in the canonical form
// produced by canonicalCIMDKey (closes host-case, default-port,
// path-segment, and percent-encoding alias classes).
//
// Rejecting at the gate means alias variants never enter the cache,
// rate-limit tracker, or singleflight, so no positive cache entry can be
// mis-attributed across two raw IDs that share a canonical form.
func isCanonicalCIMDClientID(clientID string) bool {
	for _, r := range clientID {
		if r > 127 {
			return false
		}
	}
	return canonicalCIMDKey(clientID) == clientID
}

// NewHTTPCIMDFetcher creates a CIMD fetcher with SSRF-safe HTTP client.
func NewHTTPCIMDFetcher() *HTTPCIMDFetcher {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("cimd: invalid address: %s", addr)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("cimd: DNS lookup failed: %w", err)
			}
			// Find first public IP and dial it directly (prevents DNS rebinding)
			for _, ip := range ips {
				if isPrivateIP(ip.IP) {
					continue
				}
				dialer := &net.Dialer{Timeout: 3 * time.Second}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			}
			return nil, fmt.Errorf("cimd: no public IP found for %s", host)
		},
		TLSHandshakeTimeout: 3 * time.Second,
	}
	return &HTTPCIMDFetcher{
		client: &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("cimd: redirects not allowed")
			},
		},
		clock:    clock.RealClock{},
		cacheTTL: 5 * time.Minute,
	}
}

func (f *HTTPCIMDFetcher) FetchClient(ctx context.Context, clientID string) (*storage.ClientModel, error) {
	if !storage.IsCIMDClientID(clientID) {
		return nil, fmt.Errorf("cimd: invalid client_id URL")
	}
	if !isCanonicalCIMDClientID(clientID) {
		return nil, fmt.Errorf("cimd: client_id must be in canonical form (lowercase ASCII host, no default port, clean path)")
	}

	cache := f.ensureCache()

	// Check cache (positive or negative entry).
	if client, cachedErr, hit := cache.Lookup(clientID, f.clock.Now()); hit {
		if cachedErr != nil {
			return nil, cachedErr
		}
		return client, nil
	}

	// Reject without an outbound call when this client_id is currently
	// rate-limited.
	if f.ensureFailures().IsRateLimited(clientID, f.clock.Now()) {
		return nil, errCIMDRateLimited
	}

	// Collapse concurrent cache-miss fetches for the same client_id.
	v, err, _ := f.sf.Do(clientID, func() (any, error) {
		client, ttl, fetchErr := f.fetchAndValidate(ctx, clientID)
		if fetchErr != nil {
			now := f.clock.Now()
			f.ensureFailures().Record(clientID, now)
			cache.PutNegative(clientID, fetchErr, now.Add(cimdNegativeCacheTTL))
			return nil, fetchErr
		}

		if ttl > 0 {
			cache.PutPositive(clientID, client, f.clock.Now().Add(ttl))
		}
		return client, nil
	})
	if err != nil {
		return nil, err
	}
	client := v.(*storage.ClientModel)

	return client, nil
}

func (f *HTTPCIMDFetcher) fetchAndValidate(ctx context.Context, clientID string) (*storage.ClientModel, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("cimd: invalid URL: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("cimd: fetch failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("cimd: HTTP %d from %s", resp.StatusCode, clientID)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, 0, fmt.Errorf("cimd: invalid Content-Type header: %w", err)
	}
	if mediaType != "application/json" {
		return nil, 0, fmt.Errorf("cimd: unsupported Content-Type: %q", mediaType)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDDocSize+1))
	if err != nil {
		return nil, 0, fmt.Errorf("cimd: read failed: %w", err)
	}
	if len(body) > maxCIMDDocSize {
		return nil, 0, fmt.Errorf("cimd: document exceeds 10KB limit")
	}

	client, err := validateCIMDMetadata(body, clientID)
	if err != nil {
		return nil, 0, err
	}
	return client, cacheTTLFromCacheControl(resp.Header.Get("Cache-Control"), f.cacheTTL), nil
}

// specialPurposeCIDRs are non-global special-use ranges that the net.IP
// helpers below do not cover. CGNAT 100.64.0.0/10 matters most: cloud pod
// networks (e.g. EKS VPC CNI) assign it to in-cluster workloads, so a CIMD
// client_id resolving there would let the fetcher reach internal services.
var specialPurposeCIDRs = mustParseCIDRs(
	"100.64.0.0/10",   // RFC 6598 CGNAT / shared address space
	"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
	"192.0.2.0/24",    // RFC 5737 TEST-NET-1
	"198.51.100.0/24", // RFC 5737 TEST-NET-2
	"203.0.113.0/24",  // RFC 5737 TEST-NET-3
	"198.18.0.0/15",   // RFC 2544 benchmarking
	"240.0.0.0/4",     // reserved (incl. limited broadcast)
	"64:ff9b::/96",    // RFC 6052 NAT64 (embeds IPv4)
	"100::/64",        // RFC 6666 discard-only
	"2001:db8::/32",   // RFC 3849 documentation
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("cimd: invalid builtin CIDR " + c)
		}
		nets = append(nets, n)
	}
	return nets
}

// isPrivateIP checks if an IP is private/loopback/link-local/multicast or in
// a special-purpose range that must never be a CIMD fetch target.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Normalize IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to IPv4.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	for _, n := range specialPurposeCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
