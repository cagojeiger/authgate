package app

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/idgen"
)

// Storage defaults the refresh reuse grace to off, so the configured value only
// takes effect through this wiring.
func TestMustBuildStore_AppliesRefreshReuseGrace(t *testing.T) {
	cfg := &config.Config{
		RefreshTokenReuseGrace: 7 * time.Second,
		SigningKeyPath:         filepath.Join(t.TempDir(), "signing_key.pem"),
	}

	store := mustBuildStore(cfg, nil, clock.RealClock{}, idgen.CryptoGenerator{})

	if got := store.RefreshReuseGrace(); got != 7*time.Second {
		t.Fatalf("RefreshReuseGrace = %v, want 7s from config", got)
	}
}
