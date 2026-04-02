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
