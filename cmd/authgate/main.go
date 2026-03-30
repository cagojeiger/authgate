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
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/storage"
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

	store := storage.New(db, clk, gen, stateChecker)

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

	// Mux: zitadel owns /.well-known/*, /authorize, /oauth/*, etc.
	// authgate adds /login, /device, /account, /health, /ready
	mux := http.NewServeMux()

	// zitadel provider handles all OIDC routes
	mux.Handle("/", provider)

	// Health endpoints
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
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
