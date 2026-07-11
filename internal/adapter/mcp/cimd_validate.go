package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kangheeyong/authgate/internal/storage"
)

// validateCIMDMetadata parses a fetched CIMD document body and validates it
// against the requested clientID, returning the resolved public ClientModel.
//
// It is intentionally pure — no HTTP, cache or rate-limit machinery — so the
// CIMD schema/validation rules can be unit-tested in isolation (#303). The
// caller (HTTPCIMDFetcher.fetchAndValidate) owns the network fetch, size/
// content-type limits and cache-TTL derivation.
func validateCIMDMetadata(body []byte, clientID string) (*storage.ClientModel, error) {
	var meta CIMDMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("cimd: invalid JSON: %w", err)
	}

	// client_id in document must match the fetched URL. Real-world exception:
	// ChatGPT requests with a query-string client_id (e.g.
	// ?token_endpoint_auth_method=none) while its document publishes the URL
	// without the query — accept when the document value equals the fetch URL
	// minus its query. The requested client_id stays the identity everywhere
	// (cache key, rate limit, ClientModel.ID), so authorize/token remain
	// consistent and no alias gains a different redirect_uris set than the
	// document owner published.
	if meta.ClientID != clientID && meta.ClientID != stripCIMDQuery(clientID) {
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

	grantTypes, err := supportedCIMDGrantTypes(meta.GrantTypes)
	if err != nil {
		return nil, err
	}
	if meta.TokenEndpointAuthMethod == "" {
		meta.TokenEndpointAuthMethod = "none"
	}
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
	return &storage.ClientModel{
		ID:                   clientID,
		Type:                 "public",
		LoginChannel:         "mcp",
		Name:                 meta.ClientName,
		RedirectURIList:      storage.StringArray(meta.RedirectURIs),
		AllowedScopeList:     storage.StringArray([]string{"openid", "profile", "email", "offline_access"}),
		AllowedGrantTypeList: storage.StringArray(grantTypes),
	}, nil
}

// stripCIMDQuery returns clientID without its query string. Fragments are
// rejected before fetch (IsCIMDClientID), so cutting at '?' is exact.
func stripCIMDQuery(clientID string) string {
	if i := strings.IndexByte(clientID, '?'); i >= 0 {
		return clientID[:i]
	}
	return clientID
}

func supportedCIMDGrantTypes(grantTypes []string) ([]string, error) {
	if len(grantTypes) == 0 {
		return []string{"authorization_code"}, nil
	}
	if len(grantTypes) > maxCIMDGrantTypeCount {
		return nil, fmt.Errorf("cimd: grant_types exceeds %d entries", maxCIMDGrantTypeCount)
	}

	seen := make(map[string]bool, 2)
	var supported []string
	for _, gt := range grantTypes {
		switch gt {
		case "authorization_code", "refresh_token":
			if !seen[gt] {
				seen[gt] = true
				supported = append(supported, gt)
			}
		}
	}
	if !seen["authorization_code"] {
		return nil, fmt.Errorf("cimd: grant_types must include authorization_code")
	}
	return supported, nil
}
