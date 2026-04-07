package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port                  int
	DatabaseURL           string
	SessionSecret         string
	PublicURL             string
	OIDCIssuerURL         string
	OIDCInternalURL       string // optional: internal base URL for server-to-server OIDC calls (Docker/K8s)
	OIDCClientID          string
	OIDCClientSecret      string
	SessionTTL            time.Duration
	AccessTokenTTL        time.Duration
	RefreshTokenTTL       time.Duration
	DevMode               bool
	EnableMCP             bool
	ClientConfigPath      string
	HTTPReadHeaderTimeout time.Duration
	HTTPReadTimeout       time.Duration
	HTTPWriteTimeout      time.Duration
	HTTPIdleTimeout       time.Duration
}

func Load() (*Config, error) {
	c := &Config{
		Port:                  envInt("PORT", 8080),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		SessionSecret:         os.Getenv("SESSION_SECRET"),
		PublicURL:             os.Getenv("PUBLIC_URL"),
		OIDCIssuerURL:         envDefault("OIDC_ISSUER_URL", "http://localhost:8082"),
		OIDCInternalURL:       os.Getenv("OIDC_INTERNAL_URL"),
		OIDCClientID:          envDefault("OIDC_CLIENT_ID", "authgate"),
		OIDCClientSecret:      os.Getenv("OIDC_CLIENT_SECRET"),
		SessionTTL:            time.Duration(envInt("SESSION_TTL", 86400)) * time.Second,
		AccessTokenTTL:        time.Duration(envInt("ACCESS_TOKEN_TTL", 900)) * time.Second,
		RefreshTokenTTL:       time.Duration(envInt("REFRESH_TOKEN_TTL", 2592000)) * time.Second,
		DevMode:               envBool("DEV_MODE", false),
		EnableMCP:             envBool("ENABLE_MCP", true),
		ClientConfigPath:      envDefault("CLIENT_CONFIG", "/etc/authgate/clients.yaml"),
		HTTPReadHeaderTimeout: time.Duration(envInt("HTTP_READ_HEADER_TIMEOUT_SEC", 5)) * time.Second,
		HTTPReadTimeout:       time.Duration(envInt("HTTP_READ_TIMEOUT_SEC", 15)) * time.Second,
		HTTPWriteTimeout:      time.Duration(envInt("HTTP_WRITE_TIMEOUT_SEC", 30)) * time.Second,
		HTTPIdleTimeout:       time.Duration(envInt("HTTP_IDLE_TIMEOUT_SEC", 60)) * time.Second,
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
		if !strings.HasPrefix(c.OIDCIssuerURL, "https://") {
			return nil, fmt.Errorf("DEV_MODE=false requires OIDC_ISSUER_URL with https:// (got %q)", c.OIDCIssuerURL)
		}
		if c.OIDCClientID == "" || c.OIDCClientSecret == "" {
			return nil, fmt.Errorf("DEV_MODE=false requires OIDC_CLIENT_ID and OIDC_CLIENT_SECRET")
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
