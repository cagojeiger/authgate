package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

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

// HTTPCIMDFetcher fetches CIMD metadata via HTTP with SSRF protection.
type HTTPCIMDFetcher struct {
	client *http.Client
}

// NewHTTPCIMDFetcher creates a CIMD fetcher with SSRF-safe HTTP client.
func NewHTTPCIMDFetcher() *HTTPCIMDFetcher {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("cimd: invalid address: %s", addr)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("cimd: DNS lookup failed: %w", err)
			}
			for _, ip := range ips {
				if isPrivateIP(ip.IP) {
					return nil, fmt.Errorf("cimd: private IP rejected: %s", ip.IP)
				}
			}
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &HTTPCIMDFetcher{
		client: &http.Client{
			Transport: transport,
			Timeout:   3 * time.Second,
		},
	}
}

func (f *HTTPCIMDFetcher) FetchClient(ctx context.Context, clientID string) (*ClientModel, error) {
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024)) // 10KB limit
	if err != nil {
		return nil, fmt.Errorf("cimd: read failed: %w", err)
	}

	var meta CIMDMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("cimd: invalid JSON: %w", err)
	}

	// Validate: client_id in document must match the fetched URL
	if meta.ClientID != clientID {
		return nil, fmt.Errorf("cimd: client_id mismatch: document=%q, url=%q", meta.ClientID, clientID)
	}
	if meta.ClientName == "" {
		return nil, fmt.Errorf("cimd: client_name is required")
	}
	if len(meta.RedirectURIs) == 0 {
		return nil, fmt.Errorf("cimd: redirect_uris is required")
	}

	// Defaults
	if len(meta.GrantTypes) == 0 {
		meta.GrantTypes = []string{"authorization_code"}
	}
	if meta.TokenEndpointAuthMethod == "" {
		meta.TokenEndpointAuthMethod = "none"
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
	return strings.HasPrefix(clientID, "https://") && strings.Contains(clientID[len("https://"):], "/")
}

// isPrivateIP checks if an IP is private/loopback/link-local.
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
