package app

import (
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"os"

	mcpadapter "github.com/kangheeyong/authgate/internal/adapter/mcp"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/middleware"
	"github.com/kangheeyong/authgate/internal/storage"
)

func newStateChecker() func(*storage.User) error {
	return func(user *storage.User) error {
		if user.Status != "active" {
			return fmt.Errorf("account not active: %s", user.Status)
		}
		return nil
	}
}

func mustBuildStore(cfg *config.Config, db *sql.DB, clk clock.Clock, gen idgen.CryptoGenerator) *storage.Storage {
	store := storage.New(db, clk, gen, newStateChecker(), cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	store.SetIssuer(cfg.PublicURL)
	store.SetDevicePollInterval(devicePollInterval)
	mustConfigureSigningKey(store, cfg.SigningKeyPath)
	configureMCPPoliciesIfEnabled(cfg, store)
	return store
}

func mustConfigureSigningKey(store *storage.Storage, path string) {
	key, err := storage.LoadOrGenerateKey(path)
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	store.SetSigningKey(key, "authgate-key-1")
}

func loadClientConfigIfPresent(cfg *config.Config, store *storage.Storage) []string {
	if cfg.ClientConfigPath == "" {
		return nil
	}

	clientCfg, err := storage.LoadClientConfig(cfg.ClientConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("client config not found, skipping", "path", cfg.ClientConfigPath)
			return nil
		}
		log.Fatalf("client config: %v", err)
	}
	if err := storage.ValidateClientChannels(clientCfg.Clients, cfg.EnableMCP); err != nil {
		log.Fatalf("client config: %v", err)
	}
	store.LoadClients(clientCfg.Clients)
	slog.Info("client config loaded", "path", cfg.ClientConfigPath, "count", len(clientCfg.Clients))

	// Collect allowed CORS origins from all client redirect URIs.
	var allURIs []string
	for _, c := range clientCfg.Clients {
		allURIs = append(allURIs, c.RedirectURIs...)
	}
	return middleware.OriginsFromRedirectURIs(allURIs)
}

func configureMCPPoliciesIfEnabled(cfg *config.Config, store *storage.Storage) {
	if !cfg.EnableMCP {
		return
	}
	cimdFetcher := mcpadapter.NewHTTPCIMDFetcher()
	clientPolicy := mcpadapter.NewClientResolutionPolicy(storage.NewCoreClientResolutionPolicy(store), cimdFetcher)
	store.SetClientResolutionPolicy(clientPolicy)
	store.SetResourceBindingPolicy(mcpadapter.NewResourceBindingPolicy(storage.NewCoreResourceBindingPolicy(), clientPolicy))
}
