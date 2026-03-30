package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/guard"
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

	// StateChecker: guard function injected into storage (storage never imports guard)
	stateChecker := func(user *storage.User) error {
		ui := &guard.UserInfo{
			Status:            user.Status,
			TermsAcceptedAt:   user.TermsAcceptedAt,
			PrivacyAcceptedAt: user.PrivacyAcceptedAt,
		}
		if user.TermsVersion != nil {
			ui.TermsVersion = *user.TermsVersion
		}
		if user.PrivacyVersion != nil {
			ui.PrivacyVersion = *user.PrivacyVersion
		}
		state := guard.DeriveLoginState(ui, cfg.TermsVersion, cfg.PrivacyVersion)
		if state != guard.OnboardingComplete {
			return fmt.Errorf("login state: %s", state)
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

	// Upstream IdP
	var browserProvider upstream.Provider
	var mcpProvider upstream.Provider
	var deviceProvider upstream.Provider
	if cfg.UpstreamProvider == "google" {
		browserProvider = &upstream.GoogleProvider{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleSecret,
			RedirectURI:  cfg.PublicURL + "/login/callback",
		}
		mcpProvider = &upstream.GoogleProvider{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleSecret,
			RedirectURI:  cfg.PublicURL + "/mcp/callback",
		}
		deviceProvider = &upstream.GoogleProvider{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleSecret,
			RedirectURI:  cfg.PublicURL + "/device/auth/callback",
		}
	} else {
		browserProvider = &upstream.MockProvider{
			MockIDPURL:       cfg.MockIDPURL,
			MockIDPPublicURL: cfg.MockIDPPublicURL,
			RedirectURI:      cfg.PublicURL + "/login/callback",
		}
		mcpProvider = &upstream.MockProvider{
			MockIDPURL:       cfg.MockIDPURL,
			MockIDPPublicURL: cfg.MockIDPPublicURL,
			RedirectURI:      cfg.PublicURL + "/mcp/callback",
		}
		deviceProvider = &upstream.MockProvider{
			MockIDPURL:       cfg.MockIDPURL,
			MockIDPPublicURL: cfg.MockIDPPublicURL,
			RedirectURI:      cfg.PublicURL + "/device/auth/callback",
		}
	}

	// Service layer
	loginService := service.NewLoginService(store, browserProvider, mcpProvider, cfg.TermsVersion, cfg.PrivacyVersion, cfg.SessionTTL)

	// Device service
	deviceService := service.NewDeviceService(store, deviceProvider, cfg.TermsVersion, cfg.PrivacyVersion, cfg.PublicURL, cfg.SessionTTL)

	// Account service
	accountService := service.NewAccountService(db, clk)

	// Handler layer
	loginHandler := handler.NewLoginHandler(loginService, cfg.DevMode)
	deviceHandler := handler.NewDeviceHandler(deviceService, cfg.DevMode)
	accountHandler := handler.NewAccountHandler(accountService, store)

	// Mux: zitadel owns /.well-known/*, /authorize, /oauth/*, etc.
	// authgate adds /login, /device, /account, /health, /ready
	mux := http.NewServeMux()

	// zitadel provider handles all OIDC routes
	mux.Handle("/", provider)

	// authgate login routes
	mux.HandleFunc("/login", loginHandler.HandleLogin)
	mux.HandleFunc("/login/callback", loginHandler.HandleCallback)
	mux.HandleFunc("/mcp/login", loginHandler.HandleMCPLogin)
	mux.HandleFunc("/mcp/callback", loginHandler.HandleMCPCallback)
	mux.HandleFunc("/login/terms", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			loginHandler.HandleTermsPage(w, r)
		} else {
			loginHandler.HandleTermsSubmit(w, r)
		}
	})

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

	slog.Info("authgate starting", "addr", addr, "dev", cfg.DevMode, "provider", cfg.UpstreamProvider)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}
