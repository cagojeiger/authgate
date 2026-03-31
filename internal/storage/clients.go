package storage

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ClientConfigFile represents the YAML client configuration file.
type ClientConfigFile struct {
	Clients []ClientConfigEntry `yaml:"clients"`
}

// ClientConfigEntry represents a single OAuth client in the YAML config.
type ClientConfigEntry struct {
	ClientID         string   `yaml:"client_id"`
	ClientSecretHash *string  `yaml:"client_secret_hash,omitempty"`
	ClientType       string   `yaml:"client_type"`
	LoginChannel     string   `yaml:"login_channel"`
	Name             string   `yaml:"name"`
	RedirectURIs     []string `yaml:"redirect_uris"`
	AllowedScopes    []string `yaml:"allowed_scopes"`
	AllowedGrantTypes []string `yaml:"allowed_grant_types"`
}

// LoadClientConfig reads and parses a clients.yaml file.
func LoadClientConfig(path string) (*ClientConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg ClientConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	for i, c := range cfg.Clients {
		if c.ClientID == "" {
			return nil, fmt.Errorf("client[%d]: client_id is required", i)
		}
		if c.ClientType != "public" && c.ClientType != "confidential" {
			return nil, fmt.Errorf("client[%d] %q: client_type must be public or confidential", i, c.ClientID)
		}
		if c.LoginChannel == "" {
			cfg.Clients[i].LoginChannel = "browser"
		} else if c.LoginChannel != "browser" && c.LoginChannel != "mcp" {
			return nil, fmt.Errorf("client[%d] %q: login_channel must be browser or mcp", i, c.ClientID)
		}
		if c.Name == "" {
			return nil, fmt.Errorf("client[%d] %q: name is required", i, c.ClientID)
		}
		if len(c.RedirectURIs) == 0 {
			return nil, fmt.Errorf("client[%d] %q: at least one redirect_uri is required", i, c.ClientID)
		}
	}

	return &cfg, nil
}

// UpsertClients inserts or updates OAuth clients from config. All in one transaction.
func (s *Storage) UpsertClients(ctx context.Context, clients []ClientConfigEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, c := range clients {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO oauth_clients (client_id, client_secret_hash, client_type, login_channel, name, redirect_uris, allowed_scopes, allowed_grant_types, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
			 ON CONFLICT (client_id) DO UPDATE SET
			   client_secret_hash = COALESCE(EXCLUDED.client_secret_hash, oauth_clients.client_secret_hash),
			   client_type = EXCLUDED.client_type,
			   login_channel = EXCLUDED.login_channel,
			   name = EXCLUDED.name,
			   redirect_uris = EXCLUDED.redirect_uris,
			   allowed_scopes = EXCLUDED.allowed_scopes,
			   allowed_grant_types = EXCLUDED.allowed_grant_types,
			   updated_at = NOW()`,
			c.ClientID, c.ClientSecretHash, c.ClientType, c.LoginChannel, c.Name,
			StringArray(c.RedirectURIs), StringArray(c.AllowedScopes), StringArray(c.AllowedGrantTypes),
		)
		if err != nil {
			return fmt.Errorf("upsert client %q: %w", c.ClientID, err)
		}
	}

	return tx.Commit()
}
