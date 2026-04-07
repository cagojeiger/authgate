package config

import (
	"os"
	"testing"
)

func clearEnv() {
	for _, key := range []string{
		"PORT", "DATABASE_URL", "SESSION_SECRET", "PUBLIC_URL",
		"OIDC_ISSUER_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET",
		"SESSION_TTL", "ACCESS_TOKEN_TTL", "REFRESH_TOKEN_TTL",
		"DEV_MODE", "ENABLE_MCP",
		"DB_MAX_OPEN_CONNS", "DB_MAX_IDLE_CONNS",
		"DB_CONN_MAX_LIFETIME_SEC", "DB_CONN_MAX_IDLE_TIME_SEC",
		"HTTP_READ_HEADER_TIMEOUT_SEC", "HTTP_READ_TIMEOUT_SEC",
		"HTTP_WRITE_TIMEOUT_SEC", "HTTP_IDLE_TIMEOUT_SEC",
	} {
		os.Unsetenv(key)
	}
}

func setMinimal() {
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "test-secret-32-chars-long-enough!")
	os.Setenv("PUBLIC_URL", "http://localhost:8080")
	os.Setenv("DEV_MODE", "true")
}

func TestLoad_MissingDatabaseURL(t *testing.T) {
	clearEnv()
	os.Setenv("SESSION_SECRET", "secret")
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "true")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing DATABASE_URL")
	}
}

func TestLoad_MissingSessionSecret(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "true")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing SESSION_SECRET")
	}
}

func TestLoad_MissingPublicURL(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "secret")
	os.Setenv("DEV_MODE", "true")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing PUBLIC_URL")
	}
}

func TestLoad_DevModeFalseRequiresHTTPS(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "test-secret-32-chars-long-enough!")
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("OIDC_ISSUER_URL", "http://localhost:8082")
	os.Setenv("OIDC_CLIENT_ID", "id")
	os.Setenv("OIDC_CLIENT_SECRET", "secret")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: DEV_MODE=false requires https:// OIDC_ISSUER_URL")
	}
}

func TestLoad_DevModeFalseRequiresOIDCCredentials(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "test-secret-32-chars-long-enough!")
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("OIDC_ISSUER_URL", "https://accounts.google.com")
	// Missing OIDC_CLIENT_SECRET

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: DEV_MODE=false requires OIDC credentials")
	}
}

func TestLoad_Defaults(t *testing.T) {
	clearEnv()
	setMinimal()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.OIDCIssuerURL != "http://localhost:8082" {
		t.Errorf("OIDCIssuerURL = %q, want http://localhost:8082", cfg.OIDCIssuerURL)
	}
	if cfg.OIDCClientID != "authgate" {
		t.Errorf("OIDCClientID = %q, want authgate", cfg.OIDCClientID)
	}
	if cfg.SessionTTL.Seconds() != 86400 {
		t.Errorf("SessionTTL = %v, want 86400s", cfg.SessionTTL)
	}
	if cfg.AccessTokenTTL.Seconds() != 900 {
		t.Errorf("AccessTokenTTL = %v, want 900s", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL.Seconds() != 2592000 {
		t.Errorf("RefreshTokenTTL = %v, want 2592000s", cfg.RefreshTokenTTL)
	}
	if !cfg.EnableMCP {
		t.Error("EnableMCP = false, want true by default")
	}
	if cfg.HTTPReadHeaderTimeout.Seconds() != 5 {
		t.Errorf("HTTPReadHeaderTimeout = %v, want 5s", cfg.HTTPReadHeaderTimeout)
	}
	if cfg.HTTPReadTimeout.Seconds() != 15 {
		t.Errorf("HTTPReadTimeout = %v, want 15s", cfg.HTTPReadTimeout)
	}
	if cfg.HTTPWriteTimeout.Seconds() != 30 {
		t.Errorf("HTTPWriteTimeout = %v, want 30s", cfg.HTTPWriteTimeout)
	}
	if cfg.HTTPIdleTimeout.Seconds() != 60 {
		t.Errorf("HTTPIdleTimeout = %v, want 60s", cfg.HTTPIdleTimeout)
	}
	if cfg.DBMaxOpenConns != 25 {
		t.Errorf("DBMaxOpenConns = %d, want 25", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 25 {
		t.Errorf("DBMaxIdleConns = %d, want 25", cfg.DBMaxIdleConns)
	}
	if cfg.DBConnMaxLifetime.Seconds() != 300 {
		t.Errorf("DBConnMaxLifetime = %v, want 300s", cfg.DBConnMaxLifetime)
	}
	if cfg.DBConnMaxIdleTime.Seconds() != 120 {
		t.Errorf("DBConnMaxIdleTime = %v, want 120s", cfg.DBConnMaxIdleTime)
	}
}

func TestLoad_DevModeFalseShortSessionSecret(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "short") // < 32 chars
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("OIDC_ISSUER_URL", "https://accounts.google.com")
	os.Setenv("OIDC_CLIENT_ID", "id")
	os.Setenv("OIDC_CLIENT_SECRET", "secret")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: SESSION_SECRET < 32 chars in production")
	}
}

func TestLoad_DevModeTrueAllowsShortSecret(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "short")
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "true")

	_, err := Load()
	if err != nil {
		t.Fatalf("dev mode should allow short secret: %v", err)
	}
}

func TestLoad_Success(t *testing.T) {
	clearEnv()
	setMinimal()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.DevMode {
		t.Error("DevMode should be true")
	}
}

func TestLoad_EnableMCPFalse(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("ENABLE_MCP", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnableMCP {
		t.Fatal("EnableMCP should be false")
	}
}

func TestLoad_HTTPTimeoutsFromEnv(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("HTTP_READ_HEADER_TIMEOUT_SEC", "7")
	os.Setenv("HTTP_READ_TIMEOUT_SEC", "20")
	os.Setenv("HTTP_WRITE_TIMEOUT_SEC", "40")
	os.Setenv("HTTP_IDLE_TIMEOUT_SEC", "120")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.HTTPReadHeaderTimeout.Seconds() != 7 {
		t.Errorf("HTTPReadHeaderTimeout = %v, want 7s", cfg.HTTPReadHeaderTimeout)
	}
	if cfg.HTTPReadTimeout.Seconds() != 20 {
		t.Errorf("HTTPReadTimeout = %v, want 20s", cfg.HTTPReadTimeout)
	}
	if cfg.HTTPWriteTimeout.Seconds() != 40 {
		t.Errorf("HTTPWriteTimeout = %v, want 40s", cfg.HTTPWriteTimeout)
	}
	if cfg.HTTPIdleTimeout.Seconds() != 120 {
		t.Errorf("HTTPIdleTimeout = %v, want 120s", cfg.HTTPIdleTimeout)
	}
}

func TestLoad_DBPoolFromEnv(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("DB_MAX_OPEN_CONNS", "40")
	os.Setenv("DB_MAX_IDLE_CONNS", "12")
	os.Setenv("DB_CONN_MAX_LIFETIME_SEC", "600")
	os.Setenv("DB_CONN_MAX_IDLE_TIME_SEC", "90")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DBMaxOpenConns != 40 {
		t.Errorf("DBMaxOpenConns = %d, want 40", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 12 {
		t.Errorf("DBMaxIdleConns = %d, want 12", cfg.DBMaxIdleConns)
	}
	if cfg.DBConnMaxLifetime.Seconds() != 600 {
		t.Errorf("DBConnMaxLifetime = %v, want 600s", cfg.DBConnMaxLifetime)
	}
	if cfg.DBConnMaxIdleTime.Seconds() != 90 {
		t.Errorf("DBConnMaxIdleTime = %v, want 90s", cfg.DBConnMaxIdleTime)
	}
}

func TestLoad_DBPoolClampIdleToOpen(t *testing.T) {
	clearEnv()
	setMinimal()
	os.Setenv("DB_MAX_OPEN_CONNS", "10")
	os.Setenv("DB_MAX_IDLE_CONNS", "30")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DBMaxIdleConns != 10 {
		t.Errorf("DBMaxIdleConns = %d, want clamped 10", cfg.DBMaxIdleConns)
	}
}
