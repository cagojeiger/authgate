package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/time/rate"
	"github.com/zitadel/oidc/v3/pkg/op"

	mcpadapter "github.com/kangheeyong/authgate/internal/adapter/mcp"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/db/migrator"
	"github.com/kangheeyong/authgate/internal/handler"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/observability"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/middleware"
	"github.com/kangheeyong/authgate/internal/upstream"
)

func main() {
	cfg := mustLoadConfig()
	db := mustOpenDB(cfg)
	defer db.Close()

	if err := migrator.Run(db, cfg.MigrationsPath); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	// Components
	clk := clock.RealClock{}
	gen := idgen.CryptoGenerator{}
	store := mustBuildStore(cfg, db, clk, gen)
	provider := mustBuildOIDCProvider(cfg, store)

	// Upstream IdP (OIDC Discovery)
	ctx := context.Background()
	upstreamOpts := buildUpstreamOptions(cfg)
	browserProvider := mustBuildUpstreamProvider(ctx, cfg, "/login/callback", upstreamOpts)
	deviceProvider := mustBuildUpstreamProvider(ctx, cfg, "/device/auth/callback", upstreamOpts)

	// Service layer
	loginService := service.NewLoginService(store, browserProvider, cfg.SessionTTL)

	// Device service
	deviceService := service.NewDeviceService(store, deviceProvider, cfg.PublicURL, cfg.SessionTTL, clk)

	// Account service
	accountService := service.NewAccountService(store)

	// Console service
	consoleService := service.NewConsoleService(store)

	// Handler layer
	loginHandler := handler.NewLoginHandler(loginService, cfg.DevMode)
	deviceHandler := handler.NewDeviceHandler(deviceService, cfg.DevMode)
	accountHandler := handler.NewAccountHandler(accountService, cfg.PublicURL)
	consoleHandler := handler.NewConsoleHandler(consoleService)

	var mcpLoginHandler *handler.MCPLoginHandler
	if cfg.EnableMCP {
		mcpProvider := mustBuildUpstreamProvider(ctx, cfg, "/mcp/callback", upstreamOpts)
		mcpLoginService := service.NewMCPLoginService(store, mcpProvider, cfg.SessionTTL)
		mcpLoginHandler = handler.NewMCPLoginHandler(mcpLoginService, cfg.DevMode)
	}

	// Load client config and derive CORS allowed origins.
	allowedOrigins := loadClientConfigIfPresent(cfg, store)

	mux := http.NewServeMux()
	httpMetrics := observability.NewHTTPMetrics()
	registerRoutes(mux, cfg, db, store, provider, loginHandler, deviceHandler, accountHandler, mcpLoginHandler, consoleHandler, httpMetrics)

	// Wrap the mux with CORS middleware so all endpoints benefit.
	corsHandler := middleware.NewCORSMiddleware(allowedOrigins)(mux)
	// RequestIDMiddleware runs first so every handler has a request ID in context.
	requestIDHandler := middleware.RequestIDMiddleware(corsHandler)

	var inflightRequests int64
	srv, addr := buildHTTPServer(cfg, requestIDHandler, httpMetrics, &inflightRequests)

	cleanupCancel := startCleanupService(db, clk)
	defer cleanupCancel()
	installGracefulShutdown(srv, cfg, &inflightRequests, cleanupCancel)

	slog.Info("authgate starting", "addr", addr, "dev", cfg.DevMode, "mcp", cfg.EnableMCP, "issuer", cfg.OIDCIssuerURL, "provider", browserProvider.Name())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}

func mustLoadConfig() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	return cfg
}

func mustOpenDB(cfg *config.Config) *sql.DB {
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}

	db.SetMaxOpenConns(cfg.DBMaxOpenConns)
	db.SetMaxIdleConns(cfg.DBMaxIdleConns)
	db.SetConnMaxLifetime(cfg.DBConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.DBConnMaxIdleTime)

	if err := db.Ping(); err != nil {
		log.Fatalf("db ping: %v", err)
	}
	return db
}

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
	mustConfigureSigningKey(store)
	configureMCPPoliciesIfEnabled(cfg, store)
	return store
}

func mustConfigureSigningKey(store *storage.Storage) {
	key, err := storage.LoadOrGenerateKey("signing_key.pem")
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
	store.SetClientResolutionPolicy(mcpadapter.NewClientResolutionPolicy(storage.NewCoreClientResolutionPolicy(store), cimdFetcher))
	store.SetResourceBindingPolicy(mcpadapter.NewResourceBindingPolicy(storage.NewCoreResourceBindingPolicy()))
}

func mustBuildOIDCProvider(cfg *config.Config, store *storage.Storage) http.Handler {
	provider, err := op.NewProvider(
		buildOPConfig(cfg),
		store,
		op.StaticIssuer(cfg.PublicURL),
		buildOPOptions(cfg)...,
	)
	if err != nil {
		log.Fatalf("oidc provider: %v", err)
	}
	return provider
}

func buildOPConfig(cfg *config.Config) *op.Config {
	cryptoKey := sha256.Sum256([]byte(cfg.SessionSecret))
	return &op.Config{
		CryptoKey:             cryptoKey,
		CodeMethodS256:        true,
		AuthMethodPost:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       []string{"openid", "profile", "email", "offline_access"},
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode: op.UserCodeConfig{
				CharSet:      "BCDFGHJKLMNPQRSTVWXZ",
				CharAmount:   8,
				DashInterval: 4,
			},
		},
	}
}

func buildOPOptions(cfg *config.Config) []op.Option {
	opts := []op.Option{}
	if cfg.DevMode {
		opts = append(opts, op.WithAllowInsecure())
	}
	opts = append(opts,
		op.WithCustomTokenEndpoint(op.NewEndpoint("oauth/token")),
		op.WithCustomRevocationEndpoint(op.NewEndpoint("oauth/revoke")),
		op.WithCustomDeviceAuthorizationEndpoint(op.NewEndpoint("oauth/device/authorize")),
	)
	return opts
}

func buildUpstreamOptions(cfg *config.Config) []upstream.Option {
	opts := []upstream.Option{}
	if cfg.OIDCInternalURL != "" {
		opts = append(opts, upstream.WithInternalURL(cfg.OIDCInternalURL))
	}
	opts = append(opts, upstream.WithHTTPTimeout(cfg.OIDCHTTPTimeout))
	return opts
}

func mustBuildUpstreamProvider(ctx context.Context, cfg *config.Config, callbackPath string, upstreamOpts []upstream.Option) upstream.Provider {
	p, err := upstream.NewOIDCProvider(
		ctx,
		cfg.OIDCIssuerURL,
		cfg.OIDCClientID,
		cfg.OIDCClientSecret,
		cfg.PublicURL+callbackPath,
		upstreamOpts...,
	)
	if err != nil {
		log.Fatalf("upstream provider (%s): %v", callbackPath, err)
	}
	return p
}

func registerRoutes(
	mux *http.ServeMux,
	cfg *config.Config,
	db *sql.DB,
	store *storage.Storage,
	provider http.Handler,
	loginHandler *handler.LoginHandler,
	deviceHandler *handler.DeviceHandler,
	accountHandler *handler.AccountHandler,
	mcpLoginHandler *handler.MCPLoginHandler,
	consoleHandler *handler.ConsoleHandler,
	httpMetrics *observability.HTTPMetrics,
) {
	registerOAuthMetadataRoute(mux, cfg)
	registerProviderRoutes(mux, cfg, store, provider)
	registerAuthgateRoutes(mux, cfg, loginHandler, deviceHandler, accountHandler, mcpLoginHandler, consoleHandler)
	registerHealthRoutes(mux, db, httpMetrics)
}

func registerOAuthMetadataRoute(mux *http.ServeMux, cfg *config.Config) {
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]any{
			"issuer":                                cfg.PublicURL,
			"authorization_endpoint":                cfg.PublicURL + "/authorize",
			"token_endpoint":                        cfg.PublicURL + "/oauth/token",
			"revocation_endpoint":                   cfg.PublicURL + "/oauth/revoke",
			"device_authorization_endpoint":         cfg.PublicURL + "/oauth/device/authorize",
			"userinfo_endpoint":                     cfg.PublicURL + "/userinfo",
			"end_session_endpoint":                  cfg.PublicURL + "/end_session",
			"jwks_uri":                              cfg.PublicURL + "/keys",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
			"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
			"client_id_metadata_document_supported": cfg.EnableMCP,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	})
}

func registerProviderRoutes(mux *http.ServeMux, cfg *config.Config, store *storage.Storage, provider http.Handler) {
	// Rate limiters: strict for token endpoints, moderate for auth/login
	tokenLimiter := middleware.NewRateLimiter(rate.Limit(cfg.RateLimitTokenRPS), cfg.RateLimitTokenBurst)
	authLimiter := middleware.NewRateLimiter(rate.Limit(cfg.RateLimitAuthRPS), cfg.RateLimitAuthBurst)

	mux.Handle("/authorize", authLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource := storage.ResourceFromRequest(r)
		provider.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})))
	mux.Handle("/oauth/token", tokenLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource := storage.ResourceFromRequest(r)
		provider.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})))
	mux.Handle("/oauth/revoke", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.EnableMCP {
			provider.ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err == nil {
			clientID := strings.TrimSpace(r.Form.Get("client_id"))
			if storage.IsCIMDClientID(clientID) {
				if _, err := store.GetClientByClientID(r.Context(), clientID); err != nil {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}
		provider.ServeHTTP(w, r)
	}))
	mux.Handle("/oauth/device/authorize", tokenLimiter(provider))
	mux.Handle("/", provider)
}

func registerAuthgateRoutes(
	mux *http.ServeMux,
	cfg *config.Config,
	loginHandler *handler.LoginHandler,
	deviceHandler *handler.DeviceHandler,
	accountHandler *handler.AccountHandler,
	mcpLoginHandler *handler.MCPLoginHandler,
	consoleHandler *handler.ConsoleHandler,
) {
	tokenLimiter := middleware.NewRateLimiter(rate.Limit(cfg.RateLimitTokenRPS), cfg.RateLimitTokenBurst)
	authLimiter := middleware.NewRateLimiter(rate.Limit(cfg.RateLimitAuthRPS), cfg.RateLimitAuthBurst)

	mux.Handle("/login", authLimiter(http.HandlerFunc(loginHandler.HandleLogin)))
	mux.HandleFunc("/login/callback", loginHandler.HandleCallback)
	if cfg.EnableMCP {
		mux.HandleFunc("/mcp/login", mcpLoginHandler.HandleLogin)
		mux.HandleFunc("/mcp/callback", mcpLoginHandler.HandleCallback)
	}
	mux.HandleFunc("/account", accountHandler.HandleDeleteAccount)
	mux.HandleFunc("/device", deviceHandler.HandleDevicePage)
	mux.Handle("/device/approve", tokenLimiter(http.HandlerFunc(deviceHandler.HandleDeviceApprove)))
	mux.HandleFunc("/device/auth/callback", deviceHandler.HandleDeviceCallback)
	mux.HandleFunc("/console/clients", consoleHandler.HandleListClients)
	mux.HandleFunc("/console/me/connections", consoleHandler.HandleListConnections)
}

func registerHealthRoutes(mux *http.ServeMux, db *sql.DB, httpMetrics *observability.HTTPMetrics) {
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := db.PingContext(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not ready"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	mux.Handle("/metrics", httpMetrics.MetricsHandler())
}

func buildHTTPServer(cfg *config.Config, mux http.Handler, httpMetrics *observability.HTTPMetrics, inflightRequests *int64) (*http.Server, string) {
	addr := fmt.Sprintf(":%d", cfg.Port)
	observedHandler := httpMetrics.Middleware(mux)
	trackedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(inflightRequests, 1)
		defer atomic.AddInt64(inflightRequests, -1)
		observedHandler.ServeHTTP(w, r)
	})

	return &http.Server{
		Addr:              addr,
		Handler:           trackedHandler,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
	}, addr
}

func startCleanupService(db *sql.DB, clk clock.Clock) context.CancelFunc {
	cleanupRunner := storage.NewCleanupRunner(db)
	cleanupSvc := service.NewCleanupService(cleanupRunner, clk, 10*time.Minute)
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	go cleanupSvc.Start(cleanupCtx)
	return cleanupCancel
}

func installGracefulShutdown(srv *http.Server, cfg *config.Config, inflightRequests *int64, cleanupCancel context.CancelFunc) {
	go func() {
		sigCh := make(chan os.Signal, 2)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("shutdown signal received", "inflight_requests", atomic.LoadInt64(inflightRequests))

		go func() {
			<-sigCh
			slog.Warn("second shutdown signal received; forcing close")
			_ = srv.Close()
		}()

		cleanupCancel()
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
		}
		signal.Stop(sigCh)
		slog.Info("shutdown completed", "inflight_requests", atomic.LoadInt64(inflightRequests))
	}()
}
