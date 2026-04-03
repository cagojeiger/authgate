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
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/handler"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/upstream"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Database
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("db ping: %v", err)
	}

	// Components
	clk := clock.RealClock{}
	gen := idgen.CryptoGenerator{}

	// StateChecker: shared final gate for token issuance on code/refresh lookups.
	stateChecker := func(user *storage.User) error {
		if user.Status != "active" {
			return fmt.Errorf("account not active: %s", user.Status)
		}
		return nil
	}

	store := storage.New(db, clk, gen, stateChecker, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	// Signing key
	key, err := storage.LoadOrGenerateKey("signing_key.pem")
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}
	store.SetSigningKey(key, "authgate-key-1")

	// Client config (YAML → memory)
	if cfg.ClientConfigPath != "" {
		clientCfg, err := storage.LoadClientConfig(cfg.ClientConfigPath)
		if err != nil {
			if os.IsNotExist(err) {
				slog.Warn("client config not found, skipping", "path", cfg.ClientConfigPath)
			} else {
				log.Fatalf("client config: %v", err)
			}
		} else {
			store.LoadClients(clientCfg.Clients)
			slog.Info("client config loaded", "path", cfg.ClientConfigPath, "count", len(clientCfg.Clients))
		}
	}

	// CIMD fetcher for MCP clients (URL-based client_id)
	store.SetCIMDFetcher(storage.NewHTTPCIMDFetcher())

	// zitadel OP config
	cryptoKey := sha256.Sum256([]byte(cfg.SessionSecret))
	opConfig := &op.Config{
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

	// OP options
	opts := []op.Option{}
	if cfg.DevMode {
		opts = append(opts, op.WithAllowInsecure())
	}

	// Custom endpoints to match our spec
	opts = append(opts,
		op.WithCustomTokenEndpoint(op.NewEndpoint("oauth/token")),
		op.WithCustomRevocationEndpoint(op.NewEndpoint("oauth/revoke")),
		op.WithCustomDeviceAuthorizationEndpoint(op.NewEndpoint("oauth/device/authorize")),
	)

	// Create zitadel OP
	provider, err := op.NewProvider(
		opConfig,
		store,
		op.StaticIssuer(cfg.PublicURL),
		opts...,
	)
	if err != nil {
		log.Fatalf("oidc provider: %v", err)
	}

	// Upstream IdP (OIDC Discovery)
	ctx := context.Background()
	var upstreamOpts []upstream.Option
	if cfg.OIDCInternalURL != "" {
		upstreamOpts = append(upstreamOpts, upstream.WithInternalURL(cfg.OIDCInternalURL))
	}
	browserProvider, err := upstream.NewOIDCProvider(ctx, cfg.OIDCIssuerURL, cfg.OIDCClientID, cfg.OIDCClientSecret, cfg.PublicURL+"/login/callback", upstreamOpts...)
	if err != nil {
		log.Fatalf("browser provider: %v", err)
	}
	mcpProvider, err := upstream.NewOIDCProvider(ctx, cfg.OIDCIssuerURL, cfg.OIDCClientID, cfg.OIDCClientSecret, cfg.PublicURL+"/mcp/callback", upstreamOpts...)
	if err != nil {
		log.Fatalf("mcp provider: %v", err)
	}
	deviceProvider, err := upstream.NewOIDCProvider(ctx, cfg.OIDCIssuerURL, cfg.OIDCClientID, cfg.OIDCClientSecret, cfg.PublicURL+"/device/auth/callback", upstreamOpts...)
	if err != nil {
		log.Fatalf("device provider: %v", err)
	}

	// Service layer
	loginService := service.NewLoginService(store, browserProvider, mcpProvider, cfg.SessionTTL)

	// Device service
	deviceService := service.NewDeviceService(store, deviceProvider, cfg.PublicURL, cfg.SessionTTL, clk)

	// Account service
	accountService := service.NewAccountService(store)

	// Handler layer
	loginHandler := handler.NewLoginHandler(loginService, cfg.DevMode)
	deviceHandler := handler.NewDeviceHandler(deviceService, cfg.DevMode)
	accountHandler := handler.NewAccountHandler(accountService, cfg.PublicURL)

	// Mux: zitadel owns /.well-known/*, /authorize, /oauth/*, etc.
	// authgate adds /login, /device, /account, /health, /ready
	mux := http.NewServeMux()

	// RFC 8414: OAuth Authorization Server Metadata
	// This must be registered before the provider catch-all
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
			"client_id_metadata_document_supported": true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	// Capture MCP resource hints before handing off to zitadel.
	mux.Handle("/authorize", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource := storage.ResourceFromRequest(r)
		provider.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	}))
	mux.Handle("/oauth/token", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource := storage.ResourceFromRequest(r)
		provider.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	}))
	mux.Handle("/oauth/revoke", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFC 7009: revocation endpoint should still return 200 even if a CIMD
		// client metadata document is temporarily unavailable.
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

	// zitadel provider handles all OIDC routes (including /.well-known/openid-configuration)
	mux.Handle("/", provider)

	// authgate login routes
	mux.HandleFunc("/login", loginHandler.HandleLogin)
	mux.HandleFunc("/login/callback", loginHandler.HandleCallback)
	mux.HandleFunc("/mcp/login", loginHandler.HandleMCPLogin)
	mux.HandleFunc("/mcp/callback", loginHandler.HandleMCPCallback)

	// authgate account routes
	mux.HandleFunc("/account", accountHandler.HandleDeleteAccount)

	// authgate device routes
	mux.HandleFunc("/device", deviceHandler.HandleDevicePage)
	mux.HandleFunc("/device/approve", deviceHandler.HandleDeviceApprove)
	mux.HandleFunc("/device/auth/callback", deviceHandler.HandleDeviceCallback)

	// Health endpoints
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := db.PingContext(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"not ready"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ready"}`))
	})

	// Server
	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Cleanup service
	cleanupSvc := service.NewCleanupService(db, clk, 10*time.Minute)
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()
	go cleanupSvc.Start(cleanupCtx)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		slog.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	slog.Info("authgate starting", "addr", addr, "dev", cfg.DevMode, "issuer", cfg.OIDCIssuerURL, "provider", browserProvider.Name())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}
