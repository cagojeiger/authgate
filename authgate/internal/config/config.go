package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ServerPort    string
	DatabaseURL   string
	SessionSecret string
	BaseURL       string
	PublicURL     string

	UpstreamProvider string
	GoogleClientID   string
	GoogleSecret     string
	MockIDPURL       string
	MockIDPPublicURL string

	AccessTokenTTL  int
	RefreshTokenTTL int
	SessionTTL      int
}

func Load() (*Config, error) {
	cfg := &Config{
		ServerPort:       getEnv("PORT", "8080"),
		DatabaseURL:      getEnv("DATABASE_URL", "postgres://authgate:authgate@localhost:5432/authgate?sslmode=disable"),
		SessionSecret:    getEnv("SESSION_SECRET", "dev-secret-change-in-production"),
		BaseURL:          getEnv("BASE_URL", "http://localhost:8080"),
		PublicURL:        getEnv("PUBLIC_URL", "http://localhost:8080"),
		UpstreamProvider: getEnv("UPSTREAM_PROVIDER", "mock"),
		GoogleClientID:   getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleSecret:     getEnv("GOOGLE_SECRET", ""),
		MockIDPURL:       getEnv("MOCK_IDP_URL", "http://localhost:8082"),
		MockIDPPublicURL: getEnv("MOCK_IDP_PUBLIC_URL", "http://localhost:8082"),
		AccessTokenTTL:   getEnvInt("ACCESS_TOKEN_TTL", 900),
		RefreshTokenTTL:  getEnvInt("REFRESH_TOKEN_TTL", 2592000),
		SessionTTL:       getEnvInt("SESSION_TTL", 86400),
	}

	if cfg.UpstreamProvider == "google" && (cfg.GoogleClientID == "" || cfg.GoogleSecret == "") {
		return nil, fmt.Errorf("GOOGLE_CLIENT_ID and GOOGLE_SECRET required when UPSTREAM_PROVIDER=google")
	}

	return cfg, nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultVal
}

func (c *Config) GetJWKSURL() string {
	return c.BaseURL + "/.well-known/jwks.json"
}

func (c *Config) GetIssuer() string {
	return c.BaseURL
}

func (c *Config) AllowedRedirectURIs() []string {
	uris := getEnv("ALLOWED_REDIRECT_URIS", "http://localhost:8081/auth/callback")
	return strings.Split(uris, ",")
}
