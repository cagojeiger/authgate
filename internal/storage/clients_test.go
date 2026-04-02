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
