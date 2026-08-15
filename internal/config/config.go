package config

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kangheeyong/authgate/internal/crypto"
)

type Config struct {
	Port              int
	DatabaseURL       string
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxLifetime time.Duration
	DBConnMaxIdleTime time.Duration
	SessionSecret     string
	PublicURL         string
	OIDCIssuerURL     string
	// OIDCIssuerHostAllowlist is an optional comma-separated list of hosts the
	// OIDC_ISSUER_URL is allowed to point at. When non-empty, the issuer URL's
	// host must match an entry exactly (host:port if a non-default port is in
	// the URL). Empty means no allowlist enforcement — the default for backward
	// compatibility, but operators are encouraged to set this in production to
	// fail-fast on misconfigured/compromised env vars that would otherwise
	// redirect every login through an attacker-controlled IdP.
	OIDCIssuerHostAllowlist []string
	OIDCInternalURL         string // optional: internal base URL for server-to-server OIDC calls (Docker/K8s)
	OIDCHTTPTimeout         time.Duration
	OIDCClientID            string
	OIDCClientSecret        string
	// PII at-rest encryption roots (ADR-002). Secrets are base64-encoded
	// (>=32 bytes). Optional: all four empty = encryption inert. The first
	// encrypting consumer (PR2) makes them required in production.
	EncRootKeyID          string
	EncRootSecret         string
	LookupRootKeyID       string
	LookupRootSecret      string
	SessionTTL            time.Duration
	AccessTokenTTL        time.Duration
	RefreshTokenTTL       time.Duration
	AuditLogPIIRetention  time.Duration
	DevMode               bool
	EnableMCP             bool
	ClientConfigPath      string
	MigrationsPath        string
	SigningKeyPath        string
	BrandName             string
	HTTPReadHeaderTimeout time.Duration
	HTTPReadTimeout       time.Duration
	HTTPWriteTimeout      time.Duration
	HTTPIdleTimeout       time.Duration
	ShutdownTimeout       time.Duration
	MetricsAddr           string
	RateLimitTokenRPS     float64
	RateLimitTokenBurst   int
	RateLimitAuthRPS      float64
	RateLimitAuthBurst    int
	// TrustedProxies is a comma-separated list of CIDRs whose source addresses
	// are allowed to set X-Forwarded-For. Empty means no proxy is trusted —
	// the safe default for a deployment without an explicitly configured edge.
	TrustedProxies string
}

func Load() (*Config, error) {
	if err := validateParseableEnv(); err != nil {
		return nil, err
	}

	c := &Config{
		Port:                    envInt("PORT", 8080),
		DatabaseURL:             os.Getenv("DATABASE_URL"),
		DBMaxOpenConns:          envInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:          envInt("DB_MAX_IDLE_CONNS", 25),
		DBConnMaxLifetime:       time.Duration(envInt("DB_CONN_MAX_LIFETIME_SEC", 300)) * time.Second,
		DBConnMaxIdleTime:       time.Duration(envInt("DB_CONN_MAX_IDLE_TIME_SEC", 120)) * time.Second,
		SessionSecret:           os.Getenv("SESSION_SECRET"),
		PublicURL:               os.Getenv("PUBLIC_URL"),
		OIDCIssuerURL:           envDefault("OIDC_ISSUER_URL", "http://localhost:8082"),
		OIDCIssuerHostAllowlist: envCommaList("OIDC_ISSUER_HOST_ALLOWLIST"),
		OIDCInternalURL:         os.Getenv("OIDC_INTERNAL_URL"),
		OIDCHTTPTimeout:         time.Duration(envInt("OIDC_HTTP_TIMEOUT_SEC", 10)) * time.Second,
		OIDCClientID:            envDefault("OIDC_CLIENT_ID", "authgate"),
		OIDCClientSecret:        os.Getenv("OIDC_CLIENT_SECRET"),
		EncRootKeyID:            os.Getenv("PII_ENC_ROOT_KEY_ID"),
		EncRootSecret:           os.Getenv("PII_ENC_ROOT_SECRET"),
		LookupRootKeyID:         os.Getenv("PII_LOOKUP_ROOT_KEY_ID"),
		LookupRootSecret:        os.Getenv("PII_LOOKUP_ROOT_SECRET"),
		SessionTTL:              time.Duration(envInt("SESSION_TTL", 86400)) * time.Second,
		AccessTokenTTL:          time.Duration(envInt("ACCESS_TOKEN_TTL", 900)) * time.Second,
		RefreshTokenTTL:         time.Duration(envInt("REFRESH_TOKEN_TTL", 2592000)) * time.Second,
		AuditLogPIIRetention:    time.Duration(envInt("AUDIT_LOG_PII_RETENTION_DAYS", 1095)) * 24 * time.Hour,
		DevMode:                 envBool("DEV_MODE", false),
		EnableMCP:               envBool("ENABLE_MCP", true),
		ClientConfigPath:        envDefault("CLIENT_CONFIG", "/etc/authgate/clients.yaml"),
		MigrationsPath:          envDefault("MIGRATIONS_PATH", "/migrations"),
		SigningKeyPath:          envDefault("SIGNING_KEY_PATH", "signing_key.pem"),
		BrandName:               envDefault("BRAND_NAME", "authgate"),
		HTTPReadHeaderTimeout:   time.Duration(envInt("HTTP_READ_HEADER_TIMEOUT_SEC", 5)) * time.Second,
		HTTPReadTimeout:         time.Duration(envInt("HTTP_READ_TIMEOUT_SEC", 15)) * time.Second,
		HTTPWriteTimeout:        time.Duration(envInt("HTTP_WRITE_TIMEOUT_SEC", 30)) * time.Second,
		HTTPIdleTimeout:         time.Duration(envInt("HTTP_IDLE_TIMEOUT_SEC", 60)) * time.Second,
		ShutdownTimeout:         time.Duration(envInt("SHUTDOWN_TIMEOUT_SEC", 10)) * time.Second,
		MetricsAddr:             os.Getenv("METRICS_ADDR"),
		RateLimitTokenRPS:       envFloat("RATE_LIMIT_TOKEN_RPS", 30),
		RateLimitTokenBurst:     envInt("RATE_LIMIT_TOKEN_BURST", 60),
		RateLimitAuthRPS:        envFloat("RATE_LIMIT_AUTH_RPS", 10),
		RateLimitAuthBurst:      envInt("RATE_LIMIT_AUTH_BURST", 20),
		TrustedProxies:          os.Getenv("TRUSTED_PROXIES"),
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
	if c.OIDCHTTPTimeout <= 0 {
		return nil, fmt.Errorf("OIDC_HTTP_TIMEOUT_SEC must be > 0")
	}
	if c.ShutdownTimeout <= 0 {
		return nil, fmt.Errorf("SHUTDOWN_TIMEOUT_SEC must be > 0")
	}
	if c.AuditLogPIIRetention < 365*24*time.Hour {
		return nil, fmt.Errorf("AUDIT_LOG_PII_RETENTION_DAYS must be >= 365")
	}
	if c.RateLimitTokenRPS <= 0 {
		return nil, fmt.Errorf("RATE_LIMIT_TOKEN_RPS must be > 0")
	}
	if c.RateLimitTokenBurst < 1 {
		return nil, fmt.Errorf("RATE_LIMIT_TOKEN_BURST must be >= 1")
	}
	if c.RateLimitAuthRPS <= 0 {
		return nil, fmt.Errorf("RATE_LIMIT_AUTH_RPS must be > 0")
	}
	if c.RateLimitAuthBurst < 1 {
		return nil, fmt.Errorf("RATE_LIMIT_AUTH_BURST must be >= 1")
	}
	// PII encryption roots are all-or-nothing: either fully configured
	// (encryption active) or fully absent (inert). A partial set is a
	// misconfiguration that must fail fast.
	if c.EncRootKeyID != "" || c.EncRootSecret != "" || c.LookupRootKeyID != "" || c.LookupRootSecret != "" {
		if c.EncRootKeyID == "" || c.EncRootSecret == "" || c.LookupRootKeyID == "" || c.LookupRootSecret == "" {
			return nil, fmt.Errorf("PII encryption requires all of PII_ENC_ROOT_KEY_ID, PII_ENC_ROOT_SECRET, PII_LOOKUP_ROOT_KEY_ID, PII_LOOKUP_ROOT_SECRET")
		}
		// Validate the secrets here so a bad base64/too-short root fails at the
		// config layer (which owns env correctness) rather than later at crypto
		// wiring. Decoded bytes are discarded — Config stays string-only.
		if err := validateRootSecret("PII_ENC_ROOT_SECRET", c.EncRootSecret); err != nil {
			return nil, err
		}
		if err := validateRootSecret("PII_LOOKUP_ROOT_SECRET", c.LookupRootSecret); err != nil {
			return nil, err
		}
	}
	if c.DBMaxOpenConns < 0 {
		return nil, fmt.Errorf("DB_MAX_OPEN_CONNS must be >= 0")
	}
	if c.DBMaxIdleConns < 0 {
		return nil, fmt.Errorf("DB_MAX_IDLE_CONNS must be >= 0")
	}
	if c.DBConnMaxLifetime < 0 {
		return nil, fmt.Errorf("DB_CONN_MAX_LIFETIME_SEC must be >= 0")
	}
	if c.DBConnMaxIdleTime < 0 {
		return nil, fmt.Errorf("DB_CONN_MAX_IDLE_TIME_SEC must be >= 0")
	}
	if c.DBMaxOpenConns > 0 && c.DBMaxIdleConns > c.DBMaxOpenConns {
		c.DBMaxIdleConns = c.DBMaxOpenConns
	}
	if c.MetricsAddr != "" {
		if _, _, err := net.SplitHostPort(c.MetricsAddr); err != nil {
			return nil, fmt.Errorf("METRICS_ADDR must be host:port when set: %w", err)
		}
	}

	if len(c.OIDCIssuerHostAllowlist) > 0 {
		issuerURL, err := url.Parse(c.OIDCIssuerURL)
		if err != nil {
			return nil, fmt.Errorf("OIDC_ISSUER_URL is not a valid URL: %w", err)
		}
		if !slices.Contains(c.OIDCIssuerHostAllowlist, issuerURL.Host) {
			return nil, fmt.Errorf("OIDC_ISSUER_URL host %q is not in OIDC_ISSUER_HOST_ALLOWLIST %v", issuerURL.Host, c.OIDCIssuerHostAllowlist)
		}
	}

	// Production guards
	if !c.DevMode {
		if len(c.SessionSecret) < 32 {
			return nil, fmt.Errorf("DEV_MODE=false requires SESSION_SECRET of at least 32 characters")
		}
		if !strings.HasPrefix(c.PublicURL, "https://") {
			return nil, fmt.Errorf("DEV_MODE=false requires PUBLIC_URL with https:// (got %q)", c.PublicURL)
		}
		if !strings.HasPrefix(c.OIDCIssuerURL, "https://") {
			return nil, fmt.Errorf("DEV_MODE=false requires OIDC_ISSUER_URL with https:// (got %q)", c.OIDCIssuerURL)
		}
		if c.OIDCClientID == "" || c.OIDCClientSecret == "" {
			return nil, fmt.Errorf("DEV_MODE=false requires OIDC_CLIENT_ID and OIDC_CLIENT_SECRET")
		}
		// PII at-rest encryption is mandatory in production (ADR-002): without
		// the roots, signups would persist plaintext PII.
		if c.EncRootKeyID == "" || c.EncRootSecret == "" || c.LookupRootKeyID == "" || c.LookupRootSecret == "" {
			return nil, fmt.Errorf("DEV_MODE=false requires PII_ENC_ROOT_KEY_ID, PII_ENC_ROOT_SECRET, PII_LOOKUP_ROOT_KEY_ID, PII_LOOKUP_ROOT_SECRET")
		}
		// Kept a warning rather than a hard requirement for backward
		// compatibility: an empty allowlist disables upstream issuer host
		// validation, so a misconfigured or compromised OIDC_ISSUER_URL would
		// not be caught (phishing-redirect risk). Recommended in production.
		if len(c.OIDCIssuerHostAllowlist) == 0 {
			slog.Warn("OIDC_ISSUER_HOST_ALLOWLIST is empty: upstream issuer host is not validated in production; set it to the expected IdP host(s) to fail-fast on a misconfigured OIDC_ISSUER_URL")
		}
	}

	return c, nil
}

// validateRootSecret checks that a PII root secret is valid base64 decoding to
// at least crypto.KeySize bytes — the same floor crypto.NewRoot enforces — so
// the failure surfaces from the config layer that owns env correctness.
func validateRootSecret(name, b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("%s must be base64: %w", name, err)
	}
	if len(raw) < crypto.KeySize {
		return fmt.Errorf("%s must decode to >= %d bytes, got %d", name, crypto.KeySize, len(raw))
	}
	return nil
}

func validateParseableEnv() error {
	for _, key := range []string{
		"PORT",
		"DB_MAX_OPEN_CONNS",
		"DB_MAX_IDLE_CONNS",
		"DB_CONN_MAX_LIFETIME_SEC",
		"DB_CONN_MAX_IDLE_TIME_SEC",
		"OIDC_HTTP_TIMEOUT_SEC",
		"SESSION_TTL",
		"ACCESS_TOKEN_TTL",
		"REFRESH_TOKEN_TTL",
		"AUDIT_LOG_PII_RETENTION_DAYS",
		"HTTP_READ_HEADER_TIMEOUT_SEC",
		"HTTP_READ_TIMEOUT_SEC",
		"HTTP_WRITE_TIMEOUT_SEC",
		"HTTP_IDLE_TIMEOUT_SEC",
		"SHUTDOWN_TIMEOUT_SEC",
		"RATE_LIMIT_TOKEN_BURST",
		"RATE_LIMIT_AUTH_BURST",
	} {
		if v := os.Getenv(key); v != "" {
			if _, err := strconv.Atoi(v); err != nil {
				return fmt.Errorf("%s must be an integer", key)
			}
		}
	}
	for _, key := range []string{"DEV_MODE", "ENABLE_MCP"} {
		if v := os.Getenv(key); v != "" {
			if _, err := strconv.ParseBool(v); err != nil {
				return fmt.Errorf("%s must be a boolean", key)
			}
		}
	}
	for _, key := range []string{"RATE_LIMIT_TOKEN_RPS", "RATE_LIMIT_AUTH_RPS"} {
		if v := os.Getenv(key); v != "" {
			if _, err := strconv.ParseFloat(v, 64); err != nil {
				return fmt.Errorf("%s must be a number", key)
			}
		}
	}
	return nil
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

// envCommaList returns the comma-separated values of an environment variable,
// trimmed of surrounding whitespace, with empty entries dropped. Empty or unset
// returns nil.
func envCommaList(key string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envFloat(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}
