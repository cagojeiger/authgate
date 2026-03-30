package config

import (
	"os"
	"testing"
)

func clearEnv() {
	for _, key := range []string{
		"PORT", "DATABASE_URL", "SESSION_SECRET", "PUBLIC_URL",
		"UPSTREAM_PROVIDER", "GOOGLE_CLIENT_ID", "GOOGLE_SECRET",
		"MOCK_IDP_URL", "MOCK_IDP_PUBLIC_URL",
		"SESSION_TTL", "ACCESS_TOKEN_TTL", "REFRESH_TOKEN_TTL",
		"TERMS_VERSION", "PRIVACY_VERSION", "DEV_MODE",
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

func TestLoad_DevModeFalseRequiresGoogle(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "secret")
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("UPSTREAM_PROVIDER", "mock")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: DEV_MODE=false requires google provider")
	}
}

func TestLoad_DevModeFalseRequiresGoogleCredentials(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "secret")
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("UPSTREAM_PROVIDER", "google")
	// Missing GOOGLE_CLIENT_ID and GOOGLE_SECRET

	_, err := Load()
	if err == nil {
		t.Fatal("expected error: DEV_MODE=false requires Google credentials")
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
	if cfg.UpstreamProvider != "mock" {
		t.Errorf("UpstreamProvider = %q, want mock", cfg.UpstreamProvider)
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
	if cfg.TermsVersion != "2026-03-28" {
		t.Errorf("TermsVersion = %q, want 2026-03-28", cfg.TermsVersion)
	}
}

func TestLoad_DevModeFalseShortSessionSecret(t *testing.T) {
	clearEnv()
	os.Setenv("DATABASE_URL", "postgres://localhost/test")
	os.Setenv("SESSION_SECRET", "short") // < 32 chars
	os.Setenv("PUBLIC_URL", "http://localhost")
	os.Setenv("DEV_MODE", "false")
	os.Setenv("UPSTREAM_PROVIDER", "google")
	os.Setenv("GOOGLE_CLIENT_ID", "id")
	os.Setenv("GOOGLE_SECRET", "secret")

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
