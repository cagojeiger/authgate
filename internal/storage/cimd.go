package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"golang.org/x/sync/singleflight"
)

// cimdCacheEntry holds a cached CIMD client with expiration.
type cimdCacheEntry struct {
	client    *ClientModel
	err       error
	expiresAt time.Time
}

// CIMDFetcher fetches and validates CIMD (Client ID Metadata Document) clients.
type CIMDFetcher interface {
	FetchClient(ctx context.Context, clientID string) (*ClientModel, error)
}

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
	maxCIMDGrantTypeCount    = 2
	maxCIMDResponseTypeCount = 1
)

// HTTPCIMDFetcher fetches CIMD metadata via HTTP with SSRF protection and caching.
type HTTPCIMDFetcher struct {
	client           *http.Client
	clock            clock.Clock
	cache            sync.Map // map[string]*cimdCacheEntry
	cacheTTL         time.Duration
	negativeCacheTTL time.Duration
	sf               singleflight.Group
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
		clock:            clock.RealClock{},
		cacheTTL:         5 * time.Minute,
		negativeCacheTTL: 30 * time.Second,
	}
}

func (f *HTTPCIMDFetcher) FetchClient(ctx context.Context, clientID string) (*ClientModel, error) {
	if !isCIMDClientID(clientID) {
		return nil, fmt.Errorf("cimd: invalid client_id URL")
	}

	// Check cache
	if entry, ok := f.cache.Load(clientID); ok {
		ce := entry.(*cimdCacheEntry)
		if f.clock.Now().Before(ce.expiresAt) {
			if ce.err != nil {
				return nil, ce.err
			}
			return ce.client, nil
		}
		f.cache.Delete(clientID)
	}

	// Collapse concurrent cache-miss fetches for the same client_id.
	v, err, _ := f.sf.Do(clientID, func() (any, error) {
		client, err := f.fetchAndValidate(ctx, clientID)
		if err != nil {
			f.cache.Store(clientID, &cimdCacheEntry{
				err:       err,
				expiresAt: f.clock.Now().Add(f.negativeCacheTTL),
			})
			return nil, err
		}

		f.cache.Store(clientID, &cimdCacheEntry{
			client:    client,
			expiresAt: f.clock.Now().Add(f.cacheTTL),
		})
		return client, nil
	})
	if err != nil {
		return nil, err
	}
	client := v.(*ClientModel)

	return client, nil
}

func (f *HTTPCIMDFetcher) fetchAndValidate(ctx context.Context, clientID string) (*ClientModel, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, fmt.Errorf("cimd: invalid URL: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cimd: fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cimd: HTTP %d from %s", resp.StatusCode, clientID)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("cimd: invalid Content-Type header: %w", err)
	}
	if mediaType != "application/json" {
		return nil, fmt.Errorf("cimd: unsupported Content-Type: %q", mediaType)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDDocSize+1))
	if err != nil {
		return nil, fmt.Errorf("cimd: read failed: %w", err)
	}
	if len(body) > maxCIMDDocSize {
		return nil, fmt.Errorf("cimd: document exceeds 10KB limit")
	}

	var meta CIMDMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("cimd: invalid JSON: %w", err)
	}

	// Validate: client_id in document must match the fetched URL
	if meta.ClientID != clientID {
		return nil, fmt.Errorf("cimd: client_id mismatch: document=%q, url=%q", meta.ClientID, clientID)
	}
	if len(meta.ClientID) > maxCIMDClientIDLength {
		return nil, fmt.Errorf("cimd: client_id exceeds %d chars", maxCIMDClientIDLength)
	}
	if meta.ClientName == "" {
		return nil, fmt.Errorf("cimd: client_name is required")
	}
	if len(meta.ClientName) > maxCIMDClientNameLength {
		return nil, fmt.Errorf("cimd: client_name exceeds %d chars", maxCIMDClientNameLength)
	}
	if len(meta.RedirectURIs) == 0 {
		return nil, fmt.Errorf("cimd: redirect_uris is required")
	}
	if len(meta.RedirectURIs) > maxCIMDRedirectURICount {
		return nil, fmt.Errorf("cimd: redirect_uris exceeds %d entries", maxCIMDRedirectURICount)
	}
	for _, uri := range meta.RedirectURIs {
		if len(uri) == 0 {
			return nil, fmt.Errorf("cimd: redirect_uri cannot be empty")
		}
		if len(uri) > maxCIMDRedirectURILength {
			return nil, fmt.Errorf("cimd: redirect_uri exceeds %d chars", maxCIMDRedirectURILength)
		}
	}

	// Defaults
	if len(meta.GrantTypes) == 0 {
		meta.GrantTypes = []string{"authorization_code"}
	}
	if meta.TokenEndpointAuthMethod == "" {
		meta.TokenEndpointAuthMethod = "none"
	}

	// Validate supported values
	if meta.TokenEndpointAuthMethod != "none" {
		return nil, fmt.Errorf("cimd: unsupported token_endpoint_auth_method: %q (only 'none' supported)", meta.TokenEndpointAuthMethod)
	}
	for _, rt := range meta.ResponseTypes {
		if rt != "code" {
			return nil, fmt.Errorf("cimd: unsupported response_type: %q (only 'code' supported)", rt)
		}
	}
	if len(meta.ResponseTypes) > maxCIMDResponseTypeCount {
		return nil, fmt.Errorf("cimd: response_types exceeds %d entries", maxCIMDResponseTypeCount)
	}
	if len(meta.GrantTypes) > maxCIMDGrantTypeCount {
		return nil, fmt.Errorf("cimd: grant_types exceeds %d entries", maxCIMDGrantTypeCount)
	}
	allowedGrants := map[string]bool{"authorization_code": true, "refresh_token": true}
	for _, gt := range meta.GrantTypes {
		if !allowedGrants[gt] {
			return nil, fmt.Errorf("cimd: unsupported grant_type: %q (only authorization_code, refresh_token supported)", gt)
		}
	}

	return &ClientModel{
		ID:                   meta.ClientID,
		Type:                 "public",
		LoginChannel:         "mcp",
		Name:                 meta.ClientName,
		RedirectURIList:      StringArray(meta.RedirectURIs),
		AllowedScopeList:     StringArray([]string{"openid", "profile", "email", "offline_access"}),
		AllowedGrantTypeList: StringArray(meta.GrantTypes),
	}, nil
}

// isCIMDClientID checks if a client_id is a CIMD URL (HTTPS with path component).
func isCIMDClientID(clientID string) bool {
	// ParseRequestURI doesn't parse fragments, check raw string
	if strings.Contains(clientID, "#") {
		return false
	}
	u, err := url.ParseRequestURI(clientID)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	if u.Host == "" || u.Hostname() == "" {
		return false
	}
	if u.User != nil {
		return false
	}
	if u.Path == "" || u.Path == "/" {
		return false
	}
	if u.RawQuery != "" {
		return false
	}
	return true
}

// isPrivateIP checks if an IP is private/loopback/link-local.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Normalize IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to IPv4.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}
