package config

import (
	"os"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear any env vars that might interfere
	os.Unsetenv("PORT")
	os.Unsetenv("DATABASE_URL")
	os.Unsetenv("UPSTREAM_PROVIDER")
	os.Unsetenv("DEV_MODE")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ServerPort != "8080" {
		t.Errorf("ServerPort = %q, want 8080", cfg.ServerPort)
	}
	if cfg.UpstreamProvider != "mock" {
		t.Errorf("UpstreamProvider = %q, want mock", cfg.UpstreamProvider)
	}
	if cfg.SessionTTL != 86400 {
		t.Errorf("SessionTTL = %d, want 86400", cfg.SessionTTL)
	}
	if cfg.AccessTokenTTL != 900 {
		t.Errorf("AccessTokenTTL = %d, want 900", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 2592000 {
		t.Errorf("RefreshTokenTTL = %d, want 2592000", cfg.RefreshTokenTTL)
	}
	if cfg.DevMode != false {
		t.Error("DevMode should default to false")
	}
}

func TestLoad_GoogleRequiresCredentials(t *testing.T) {
	os.Setenv("UPSTREAM_PROVIDER", "google")
	os.Unsetenv("GOOGLE_CLIENT_ID")
	os.Unsetenv("GOOGLE_SECRET")
	defer os.Unsetenv("UPSTREAM_PROVIDER")

	_, err := Load()
	if err == nil {
		t.Error("Load() should fail when google provider has no credentials")
	}
}

func TestLoad_GoogleWithCredentials(t *testing.T) {
	os.Setenv("UPSTREAM_PROVIDER", "google")
	os.Setenv("GOOGLE_CLIENT_ID", "test-id")
	os.Setenv("GOOGLE_SECRET", "test-secret")
	defer func() {
		os.Unsetenv("UPSTREAM_PROVIDER")
		os.Unsetenv("GOOGLE_CLIENT_ID")
		os.Unsetenv("GOOGLE_SECRET")
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.GoogleClientID != "test-id" {
		t.Errorf("GoogleClientID = %q, want test-id", cfg.GoogleClientID)
	}
}

func TestLoad_DevModeOverride(t *testing.T) {
	os.Setenv("DEV_MODE", "true")
	defer os.Unsetenv("DEV_MODE")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.DevMode {
		t.Error("DevMode should be true when DEV_MODE=true")
	}
}
