package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeClientConfigFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "clients.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write clients.yaml: %v", err)
	}
	return p
}

// #190: a URL-form static client_id (i.e. one that satisfies IsCIMDClientID)
// must be rejected at config-load time. Otherwise an operator can register
// a CIMD-shaped client_id in the static map, where ResolveClient hits the
// in-memory hit before the CIMD fallback ever runs — bypassing every
// HTTPS / content-type / redirect / size validation that CIMDFetcher
// applies on dynamic resolution. Two cases pinned: a typical CIMD URL
// and the canonical RFC example shape.
func TestLoadClientConfig_RejectsCIMDShapedClientID(t *testing.T) {
	cases := []struct {
		name     string
		clientID string
	}{
		{"https path", "https://app.example.com/oauth/client.json"},
		{"https deep path", "https://example.com/.well-known/oauth-client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeClientConfigFile(t, `
clients:
  - client_id: `+tc.clientID+`
    client_type: public
    login_channel: mcp
    name: CIMD-shaped
    redirect_uris: ["https://app.example.com/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)
			_, err := LoadClientConfig(path)
			if err == nil {
				t.Fatalf("expected URL-form client_id to be rejected, got nil")
			}
			if !strings.Contains(err.Error(), "CIMD") && !strings.Contains(err.Error(), "URL-form") {
				t.Fatalf("expected CIMD rejection error, got: %v", err)
			}
		})
	}
}

// #190 / Codex NIT-1: leading/trailing whitespace on client_id is rejected
// up front so the IsCIMDClientID guard — which delegates to
// url.ParseRequestURI and fails on space — cannot be tricked into admitting
// a CIMD-shaped value as an opaque static ID.
func TestLoadClientConfig_RejectsWhitespaceClientID(t *testing.T) {
	cases := []struct {
		name     string
		clientID string
	}{
		{"leading", " https-shaped"},
		{"trailing", "my-app "},
		{"both", " my-app "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeClientConfigFile(t, `
clients:
  - client_id: "`+tc.clientID+`"
    client_type: public
    login_channel: browser
    name: Whitespace
    redirect_uris: ["https://app.example.com/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)
			_, err := LoadClientConfig(path)
			if err == nil {
				t.Fatalf("expected whitespace client_id to be rejected, got nil")
			}
			if !strings.Contains(err.Error(), "whitespace") {
				t.Fatalf("expected whitespace rejection error, got: %v", err)
			}
		})
	}
}

func TestLoadClientConfig_DuplicateClientID(t *testing.T) {
	path := writeClientConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App B
    redirect_uris: ["http://localhost:3001/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	_, err := LoadClientConfig(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate client_id") {
		t.Fatalf("expected duplicate client_id error, got: %v", err)
	}
}

func TestLoadClientConfig_ConfidentialRequiresSecret(t *testing.T) {
	path := writeClientConfigFile(t, `
clients:
  - client_id: my-app
    client_type: confidential
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	_, err := LoadClientConfig(path)
	if err == nil || !strings.Contains(err.Error(), "requires client_secret_hash") {
		t.Fatalf("expected confidential secret error, got: %v", err)
	}
}

func TestLoadClientConfig_UnsupportedGrantType(t *testing.T) {
	path := writeClientConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [client_credentials]
`)

	_, err := LoadClientConfig(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported allowed_grant_type") {
		t.Fatalf("expected unsupported allowed_grant_type error, got: %v", err)
	}
}

func TestLoadClientConfig_NameTooLong(t *testing.T) {
	path := writeClientConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: `+strings.Repeat("a", maxYAMLClientNameLength+1)+`
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	_, err := LoadClientConfig(path)
	if err == nil || !strings.Contains(err.Error(), "name exceeds") {
		t.Fatalf("expected name exceeds error, got: %v", err)
	}
}

func TestLoadClientConfig_TooManyRedirectURIs(t *testing.T) {
	var b strings.Builder
	b.WriteString("clients:\n")
	b.WriteString("  - client_id: my-app\n")
	b.WriteString("    client_type: public\n")
	b.WriteString("    login_channel: browser\n")
	b.WriteString("    name: App A\n")
	b.WriteString("    redirect_uris:\n")
	for i := 0; i < maxYAMLRedirectURICount+1; i++ {
		b.WriteString("      - \"http://localhost:3000/callback")
		b.WriteString(strings.Repeat("a", i))
		b.WriteString("\"\n")
	}
	b.WriteString("    allowed_scopes: [openid]\n")
	b.WriteString("    allowed_grant_types: [authorization_code]\n")

	path := writeClientConfigFile(t, b.String())

	_, err := LoadClientConfig(path)
	if err == nil || !strings.Contains(err.Error(), "redirect_uris exceeds") {
		t.Fatalf("expected redirect_uris exceeds error, got: %v", err)
	}
}

func TestLoadClientConfig_TooManyGrantTypes(t *testing.T) {
	path := writeClientConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code, refresh_token, "urn:ietf:params:oauth:grant-type:device_code", refresh_token]
`)

	_, err := LoadClientConfig(path)
	if err == nil || !strings.Contains(err.Error(), "allowed_grant_types exceeds") {
		t.Fatalf("expected allowed_grant_types exceeds error, got: %v", err)
	}
}

func TestValidateClientChannels_MCPDisabledRejectsMCPClient(t *testing.T) {
	clients := []ClientConfigEntry{
		{
			ClientID:     "browser-client",
			LoginChannel: "browser",
		},
		{
			ClientID:     "mcp-client",
			LoginChannel: "mcp",
		},
	}

	err := ValidateClientChannels(clients, false)
	if err == nil || !strings.Contains(err.Error(), "requires ENABLE_MCP=true") {
		t.Fatalf("expected MCP disabled validation error, got: %v", err)
	}
}

func TestValidateClientChannels_MCPEnabledAllowsMCPClient(t *testing.T) {
	clients := []ClientConfigEntry{
		{
			ClientID:     "mcp-client",
			LoginChannel: "mcp",
		},
	}

	if err := ValidateClientChannels(clients, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// #190 / Codex NIT-3: LoadClients itself is a setter normally fed by the
// validated output of LoadClientConfig. As a belt-and-suspenders, the
// setter must drop URL-form client_ids if a future caller bypasses
// LoadClientConfig — otherwise the static-vs-dynamic invariant breaks
// silently for whatever test or admin path constructed the slice.
func TestLoadClients_DropsCIMDShapedClientID(t *testing.T) {
	s := &Storage{}
	s.LoadClients([]ClientConfigEntry{
		{ClientID: "static-ok", LoginChannel: "browser"},
		{ClientID: "https://app.example.com/oauth/client.json", LoginChannel: "mcp"},
	})

	if _, ok := s.registry.clients.Load("static-ok"); !ok {
		t.Errorf("non-URL static-ok client should be loaded")
	}
	if _, ok := s.registry.clients.Load("https://app.example.com/oauth/client.json"); ok {
		t.Errorf("URL-form client_id should NOT be loaded into static registry")
	}
}

func TestLoadClientConfig_SkipPKCERejectedForPublic(t *testing.T) {
	path := writeClientConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    skip_pkce: true
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	_, err := LoadClientConfig(path)
	if err == nil || !strings.Contains(err.Error(), "skip_pkce is only allowed for confidential") {
		t.Fatalf("expected skip_pkce error, got: %v", err)
	}
}

func TestLoadClientConfig_SkipPKCEAllowedForConfidential(t *testing.T) {
	path := writeClientConfigFile(t, `
clients:
  - client_id: my-app
    client_type: confidential
    client_secret_hash: "$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    skip_pkce: true
    login_channel: browser
    name: App A
    redirect_uris: ["https://app.example.com/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}
	if !cfg.Clients[0].SkipPKCE {
		t.Fatal("expected SkipPKCE to be true")
	}
}

func TestLoadClientConfig_SkipPKCEDefaultsToFalse(t *testing.T) {
	path := writeClientConfigFile(t, `
clients:
  - client_id: my-app
    client_type: public
    login_channel: browser
    name: App A
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}
	if cfg.Clients[0].SkipPKCE {
		t.Fatal("expected SkipPKCE to default to false")
	}
}

// skip_pkce must not reach the MCP channel. PKCE S256 is part of the MCP
// contract (spec 004), and the client_type guard alone does not cover it: a
// confidential client on login_channel: mcp would otherwise load fine and
// waive PKCE for a channel that requires it.
func TestLoadClientConfig_SkipPKCERejectedForMCPChannel(t *testing.T) {
	path := writeClientConfigFile(t, `
clients:
  - client_id: mcp-app
    client_type: confidential
    client_secret_hash: "$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    skip_pkce: true
    login_channel: mcp
    name: MCP App
    redirect_uris: ["https://app.example.com/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	_, err := LoadClientConfig(path)
	if err == nil || !strings.Contains(err.Error(), "skip_pkce is not allowed on the mcp channel") {
		t.Fatalf("expected mcp channel rejection, got: %v", err)
	}
}

// The browser channel is the one skip_pkce exists for, and it still loads when
// the channel is left implicit (login_channel defaults to browser). This pins
// the ordering: the guard reads the normalized value, so an omitted channel
// must not be mistaken for something other than browser.
func TestLoadClientConfig_SkipPKCEAllowedWithImplicitBrowserChannel(t *testing.T) {
	path := writeClientConfigFile(t, `
clients:
  - client_id: gitea
    client_type: confidential
    client_secret_hash: "$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"
    skip_pkce: true
    name: Gitea
    redirect_uris: ["https://git.example.com/user/oauth2/authgate/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`)

	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatalf("expected config to load, got: %v", err)
	}
	if !cfg.Clients[0].SkipPKCE {
		t.Fatal("expected SkipPKCE to be true")
	}
	if cfg.Clients[0].LoginChannel != "browser" {
		t.Fatalf("LoginChannel = %q, want browser", cfg.Clients[0].LoginChannel)
	}
}
