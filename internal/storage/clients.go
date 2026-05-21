package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ClientConfigFile represents the YAML client configuration file.
type ClientConfigFile struct {
	Clients []ClientConfigEntry `yaml:"clients"`
}

// ClientConfigEntry represents a single OAuth client in the YAML config.
type ClientConfigEntry struct {
	ClientID          string   `yaml:"client_id"`
	ClientSecretHash  *string  `yaml:"client_secret_hash,omitempty"`
	ClientType        string   `yaml:"client_type"`
	LoginChannel      string   `yaml:"login_channel"`
	Name              string   `yaml:"name"`
	URL               string   `yaml:"url,omitempty"`
	RedirectURIs      []string `yaml:"redirect_uris"`
	AllowedScopes     []string `yaml:"allowed_scopes"`
	AllowedGrantTypes []string `yaml:"allowed_grant_types"`
}

const (
	maxYAMLClientIDLength    = 2048
	maxYAMLClientNameLength  = 256
	maxYAMLRedirectURICount  = 10
	maxYAMLRedirectURILength = 2048
	maxYAMLGrantTypeCount    = 3
)

// LoadClientConfig reads and parses a clients.yaml file.
func LoadClientConfig(path string) (*ClientConfigFile, error) {
	//nolint:gosec // Path is operator-controlled CLIENT_CONFIG, not user input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg ClientConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	seen := make(map[string]bool, len(cfg.Clients))
	allowedGrants := map[string]bool{
		"authorization_code": true,
		"refresh_token":      true,
		"urn:ietf:params:oauth:grant-type:device_code": true,
	}
	for i, c := range cfg.Clients {
		if c.ClientID == "" {
			return nil, fmt.Errorf("client[%d]: client_id is required", i)
		}
		// #190: surrounding whitespace is rejected up front so the
		// IsCIMDClientID check below — which delegates to url.ParseRequestURI
		// and fails on leading/trailing space — cannot be tricked into
		// admitting a CIMD-shaped value as an opaque static ID.
		if strings.TrimSpace(c.ClientID) != c.ClientID {
			return nil, fmt.Errorf("client[%d] %q: client_id must not have leading or trailing whitespace", i, c.ClientID)
		}
		if len(c.ClientID) > maxYAMLClientIDLength {
			return nil, fmt.Errorf("client[%d] %q: client_id exceeds %d chars", i, c.ClientID, maxYAMLClientIDLength)
		}
		// #190: a URL-form (CIMD-shaped) client_id MUST NOT be registered
		// statically. ResolveClient consults the in-memory map before the
		// CIMD fetcher fallback, so a static URL-form entry would bypass
		// every HTTPS / content-type / redirect / size validation that
		// CIMDFetcher applies on dynamic resolution. The check runs before
		// the duplicate-id guard so the actionable "use dynamic CIMD"
		// message wins over the generic "duplicate" error.
		if IsCIMDClientID(c.ClientID) {
			return nil, fmt.Errorf("client[%d] %q: URL-form (CIMD-shaped) client_id cannot be registered statically; remove this entry and rely on dynamic CIMD resolution", i, c.ClientID)
		}
		if seen[c.ClientID] {
			return nil, fmt.Errorf("client[%d] %q: duplicate client_id", i, c.ClientID)
		}
		seen[c.ClientID] = true
		if c.ClientType != "public" && c.ClientType != "confidential" {
			return nil, fmt.Errorf("client[%d] %q: client_type must be public or confidential", i, c.ClientID)
		}
		if c.ClientType == "confidential" && (c.ClientSecretHash == nil || strings.TrimSpace(*c.ClientSecretHash) == "") {
			return nil, fmt.Errorf("client[%d] %q: confidential client requires client_secret_hash", i, c.ClientID)
		}
		if c.LoginChannel == "" {
			cfg.Clients[i].LoginChannel = "browser"
		} else if c.LoginChannel != "browser" && c.LoginChannel != "mcp" {
			return nil, fmt.Errorf("client[%d] %q: login_channel must be browser or mcp", i, c.ClientID)
		}
		if c.Name == "" {
			return nil, fmt.Errorf("client[%d] %q: name is required", i, c.ClientID)
		}
		if len(c.Name) > maxYAMLClientNameLength {
			return nil, fmt.Errorf("client[%d] %q: name exceeds %d chars", i, c.ClientID, maxYAMLClientNameLength)
		}
		if len(c.RedirectURIs) == 0 {
			return nil, fmt.Errorf("client[%d] %q: at least one redirect_uri is required", i, c.ClientID)
		}
		if len(c.RedirectURIs) > maxYAMLRedirectURICount {
			return nil, fmt.Errorf("client[%d] %q: redirect_uris exceeds %d entries", i, c.ClientID, maxYAMLRedirectURICount)
		}
		for _, uri := range c.RedirectURIs {
			if strings.TrimSpace(uri) == "" {
				return nil, fmt.Errorf("client[%d] %q: redirect_uri cannot be empty", i, c.ClientID)
			}
			if len(uri) > maxYAMLRedirectURILength {
				return nil, fmt.Errorf("client[%d] %q: redirect_uri exceeds %d chars", i, c.ClientID, maxYAMLRedirectURILength)
			}
		}
		if len(c.AllowedScopes) == 0 {
			return nil, fmt.Errorf("client[%d] %q: at least one allowed_scope is required", i, c.ClientID)
		}
		if len(c.AllowedGrantTypes) == 0 {
			return nil, fmt.Errorf("client[%d] %q: at least one allowed_grant_type is required", i, c.ClientID)
		}
		if len(c.AllowedGrantTypes) > maxYAMLGrantTypeCount {
			return nil, fmt.Errorf("client[%d] %q: allowed_grant_types exceeds %d entries", i, c.ClientID, maxYAMLGrantTypeCount)
		}
		for _, gt := range c.AllowedGrantTypes {
			if !allowedGrants[gt] {
				return nil, fmt.Errorf("client[%d] %q: unsupported allowed_grant_type %q", i, c.ClientID, gt)
			}
		}
	}

	return &cfg, nil
}

// ValidateClientChannels enforces runtime channel constraints against loaded clients.
func ValidateClientChannels(clients []ClientConfigEntry, enableMCP bool) error {
	if enableMCP {
		return nil
	}
	for i, c := range clients {
		if c.LoginChannel == "mcp" {
			return fmt.Errorf("client[%d] %q: login_channel=mcp requires ENABLE_MCP=true", i, c.ClientID)
		}
	}
	return nil
}

// LoadClients loads client config entries into the in-memory client store.
//
// Production startup runs LoadClientConfig first, which already rejects
// URL-form (CIMD-shaped) client_ids per #190. The defense-in-depth
// re-check here protects test helpers and any future caller that bypasses
// LoadClientConfig — a URL-form entry in the static map would bypass
// every CIMDFetcher validation, so we log and skip rather than silently
// admit it.
func (s *Storage) LoadClients(clients []ClientConfigEntry) {
	for _, c := range clients {
		if IsCIMDClientID(c.ClientID) {
			slog.Warn("LoadClients: dropping URL-form client_id from static registry — use dynamic CIMD resolution instead",
				"client_id", c.ClientID)
			continue
		}
		cm := &ClientModel{
			ID:                   c.ClientID,
			SecretHash:           c.ClientSecretHash,
			Type:                 c.ClientType,
			LoginChannel:         c.LoginChannel,
			Name:                 c.Name,
			URL:                  c.URL,
			RedirectURIList:      StringArray(c.RedirectURIs),
			AllowedScopeList:     StringArray(c.AllowedScopes),
			AllowedGrantTypeList: StringArray(c.AllowedGrantTypes),
		}
		s.clients.Store(c.ClientID, cm)
	}
}

// SetClientResolutionPolicy overrides client resolution behavior for op.Storage lookups.
func (s *Storage) SetClientResolutionPolicy(policy ClientResolutionPolicy) {
	if policy == nil {
		s.clientPolicy = NewCoreClientResolutionPolicy(s)
		return
	}
	s.clientPolicy = policy
}

// SetResourceBindingPolicy overrides resource binding validation for authorize/token flows.
func (s *Storage) SetResourceBindingPolicy(policy ResourceBindingPolicy) {
	if policy == nil {
		s.resourcePolicy = NewCoreResourceBindingPolicy()
		return
	}
	s.resourcePolicy = policy
}

// ResolveClient looks up a client by ID through the configured client
// resolution policy (in-memory registry plus the optional MCP/CIMD
// fallback). Exported so service-layer audit helpers can fetch the
// human-readable client name without holding a Storage pointer.
func (s *Storage) ResolveClient(ctx context.Context, clientID string) (*ClientModel, error) {
	// Safety net for tests constructing Storage without New().
	if s.clientPolicy == nil {
		s.clientPolicy = NewCoreClientResolutionPolicy(s)
	}
	return s.clientPolicy.ResolveClient(ctx, clientID)
}

// GetClientLoginChannel returns the login_channel ("browser" or "mcp") for the
// given client. Used by service-layer channel-binding checks so that an
// auth_request issued for one channel cannot be completed via the other
// channel's login flow.
func (s *Storage) GetClientLoginChannel(ctx context.Context, clientID string) (string, error) {
	cm, err := s.ResolveClient(ctx, clientID)
	if err != nil {
		return "", err
	}
	return cm.LoginChannel, nil
}
