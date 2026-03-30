package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port             int
	DatabaseURL      string
	SessionSecret    string
	PublicURL        string
	UpstreamProvider string // "google" or "mock"
	GoogleClientID   string
	GoogleSecret     string
	MockIDPURL       string
	MockIDPPublicURL string
	SessionTTL       time.Duration
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	TermsVersion     string
	PrivacyVersion   string
	DevMode          bool
}

func Load() (*Config, error) {
	c := &Config{
		Port:             envInt("PORT", 8080),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		SessionSecret:    os.Getenv("SESSION_SECRET"),
		PublicURL:        os.Getenv("PUBLIC_URL"),
		UpstreamProvider: envDefault("UPSTREAM_PROVIDER", "mock"),
		GoogleClientID:   os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleSecret:     os.Getenv("GOOGLE_SECRET"),
		MockIDPURL:       envDefault("MOCK_IDP_URL", "http://localhost:8082"),
		MockIDPPublicURL: envDefault("MOCK_IDP_PUBLIC_URL", "http://localhost:8082"),
		SessionTTL:       time.Duration(envInt("SESSION_TTL", 86400)) * time.Second,
		AccessTokenTTL:   time.Duration(envInt("ACCESS_TOKEN_TTL", 900)) * time.Second,
		RefreshTokenTTL:  time.Duration(envInt("REFRESH_TOKEN_TTL", 2592000)) * time.Second,
		TermsVersion:     envDefault("TERMS_VERSION", "2026-03-28"),
		PrivacyVersion:   envDefault("PRIVACY_VERSION", "2026-03-28"),
		DevMode:          envBool("DEV_MODE", false),
	}

	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if c.SessionSecret == "" {
		return nil, fmt.Errorf("SESSION_SECRET is required")
	}
	if c.PublicURL == "" {
		return nil, fmt.Errorf("PUBLIC_URL is required")
	}

	// Production guards
	if !c.DevMode {
		if len(c.SessionSecret) < 32 {
			return nil, fmt.Errorf("DEV_MODE=false requires SESSION_SECRET of at least 32 characters")
		}
		if c.UpstreamProvider != "google" {
			return nil, fmt.Errorf("DEV_MODE=false requires UPSTREAM_PROVIDER=google (got %q)", c.UpstreamProvider)
		}
		if c.GoogleClientID == "" || c.GoogleSecret == "" {
			return nil, fmt.Errorf("DEV_MODE=false requires GOOGLE_CLIENT_ID and GOOGLE_SECRET")
		}
	}

	return c, nil
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
