package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientConfig_DuplicateClientID(t *testing.T) {
	yaml := `
clients:
  - client_id: my-app
    client_type: public
    name: App 1
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
  - client_id: my-app
    client_type: public
    name: App 2
    redirect_uris: ["http://localhost:3001/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`
	path := writeTempYAML(t, yaml)
	_, err := LoadClientConfig(path)
	if err == nil {
		t.Fatal("expected error for duplicate client_id, got nil")
	}
}

func TestLoadClientConfig_ConfidentialWithoutSecret(t *testing.T) {
	yaml := `
clients:
  - client_id: my-app
    client_type: confidential
    name: App
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: [authorization_code]
`
	path := writeTempYAML(t, yaml)
	_, err := LoadClientConfig(path)
	if err == nil {
		t.Fatal("expected error for confidential without secret, got nil")
	}
}

func TestLoadClientConfig_EmptyGrantTypes(t *testing.T) {
	yaml := `
clients:
  - client_id: my-app
    client_type: public
    name: App
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid]
    allowed_grant_types: []
`
	path := writeTempYAML(t, yaml)
	_, err := LoadClientConfig(path)
	if err == nil {
		t.Fatal("expected error for empty grant_types, got nil")
	}
}

func TestLoadClientConfig_EmptyScopes(t *testing.T) {
	yaml := `
clients:
  - client_id: my-app
    client_type: public
    name: App
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: []
    allowed_grant_types: [authorization_code]
`
	path := writeTempYAML(t, yaml)
	_, err := LoadClientConfig(path)
	if err == nil {
		t.Fatal("expected error for empty scopes, got nil")
	}
}

func TestLoadClientConfig_Valid(t *testing.T) {
	yaml := `
clients:
  - client_id: my-app
    client_type: public
    name: App
    redirect_uris: ["http://localhost:3000/callback"]
    allowed_scopes: [openid, profile]
    allowed_grant_types: [authorization_code, refresh_token]
`
	path := writeTempYAML(t, yaml)
	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Clients) != 1 {
		t.Errorf("clients count = %d, want 1", len(cfg.Clients))
	}
}

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clients.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
