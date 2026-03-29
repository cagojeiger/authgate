package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	ServerPort    string `env:"PORT"             envDefault:"8080"`
	DatabaseURL   string `env:"DATABASE_URL"     envDefault:"postgres://authgate:authgate@localhost:5432/authgate?sslmode=disable"`
	SessionSecret string `env:"SESSION_SECRET"   envDefault:"dev-secret-change-in-production"`
	PublicURL     string `env:"PUBLIC_URL"       envDefault:"http://localhost:8080"`

	UpstreamProvider string `env:"UPSTREAM_PROVIDER" envDefault:"mock"`
	GoogleClientID   string `env:"GOOGLE_CLIENT_ID"`
	GoogleSecret     string `env:"GOOGLE_SECRET"`
	MockIDPURL       string `env:"MOCK_IDP_URL"       envDefault:"http://localhost:8082"`
	MockIDPPublicURL string `env:"MOCK_IDP_PUBLIC_URL" envDefault:"http://localhost:8082"`

	SessionTTL      int    `env:"SESSION_TTL"       envDefault:"86400"`
	AccessTokenTTL  int    `env:"ACCESS_TOKEN_TTL"  envDefault:"900"`
	RefreshTokenTTL int    `env:"REFRESH_TOKEN_TTL" envDefault:"2592000"`

	TermsVersion   string `env:"TERMS_VERSION"    envDefault:"2026-03-28"`
	PrivacyVersion string `env:"PRIVACY_VERSION"  envDefault:"2026-03-28"`
	DevMode        bool   `env:"DEV_MODE"         envDefault:"false"`
}

func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if cfg.UpstreamProvider == "google" && (cfg.GoogleClientID == "" || cfg.GoogleSecret == "") {
		return nil, fmt.Errorf("GOOGLE_CLIENT_ID and GOOGLE_SECRET required when UPSTREAM_PROVIDER=google")
	}

	return cfg, nil
}
