package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/zitadel/oidc/v3/pkg/op"

	"authgate/internal/config"
	"authgate/internal/login"
	authop "authgate/internal/op"
	"authgate/internal/storage"
	"authgate/internal/upstream"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := storage.New(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := runMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Upstream provider
	var up upstream.Provider
	if cfg.UpstreamProvider == "google" {
		up = upstream.NewGoogleProvider(cfg.GoogleClientID, cfg.GoogleSecret, cfg.PublicURL+"/login/callback")
	} else {
		up = upstream.NewMockProvider(cfg.MockIDPURL, cfg.MockIDPPublicURL)
	}

	// RSA signing key — load from file or generate
	rsaKey, err := loadOrGenerateKey("signing_key.pem")
	if err != nil {
		log.Fatalf("Failed to load/generate RSA key: %v", err)
	}

	// Storage
	// Validate production config
	if !cfg.DevMode && cfg.SessionSecret == "dev-secret-change-in-production" {
		log.Fatalf("SESSION_SECRET must be set in production (DEV_MODE=false)")
	}
	if !cfg.DevMode && cfg.UpstreamProvider != "google" {
		log.Fatalf("UPSTREAM_PROVIDER must be 'google' in production (DEV_MODE=false)")
	}

	store := authop.NewStorage(db, rsaKey, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.DevMode)

	// OP config
	cryptoKey := sha256.Sum256([]byte(cfg.SessionSecret))
	opConfig := &op.Config{
		CryptoKey:             cryptoKey,
		CodeMethodS256:        true,
		AuthMethodPost:        true,
		GrantTypeRefreshToken: true,
		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
	}

	opOpts := []op.Option{}
	if cfg.DevMode {
		opOpts = append(opOpts, op.WithAllowInsecure())
	}
	provider, err := op.NewOpenIDProvider(cfg.PublicURL, opConfig, store, opOpts...)
	if err != nil {
		log.Fatalf("Failed to create OP: %v", err)
	}

	// Templates for device flow
	tmpl := template.Must(template.ParseGlob("internal/login/templates/*.html"))

	// Structured logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	// Router
	router := chi.NewRouter()
	router.Use(login.RequestLogger)
	router.Use(httprate.LimitByIP(100, 1*time.Minute))

	// Login handler
	loginHandler := login.NewHandler(db, store, up, op.AuthCallbackURL(provider), cfg.UpstreamProvider, cfg.SessionTTL, cfg.TermsVersion, cfg.PrivacyVersion, cfg.DevMode)
	router.Mount("/login/", http.StripPrefix("/login", loginHandler))

	// Device flow UI
	deviceHandler := login.NewDeviceHandler(store, db, tmpl)

	router.Mount("/device", deviceHandler)

	// Account API (deletion, cancel deletion)
	router.Mount("/account", login.NewAccountHandler(db))


	// Health endpoints
	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "timestamp": time.Now().Format(time.RFC3339)})
	})
	router.Get("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := db.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "not ready"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})

	// Mount OP last (handles /.well-known/*, /oauth/*, etc.)
	router.Mount("/", provider)

	// Server with graceful shutdown
	httpServer := &http.Server{
		Addr:    ":" + cfg.ServerPort,
		Handler: router,
	}

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
	}()

	// Start background cleanup for expired transient data
	go cleanupExpiredData(db)

	log.Printf("authgate starting on :%s (issuer: %s, upstream: %s)", cfg.ServerPort, cfg.PublicURL, cfg.UpstreamProvider)

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

func runMigrations(db *storage.DB) error {
	data, err := os.ReadFile("migrations/001_init.sql")
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}
	if err := db.Exec(context.Background(), string(data)); err != nil {
		return fmt.Errorf("exec migration: %w", err)
	}
	return nil
}

// loadOrGenerateKey loads an RSA key from file, or generates and saves one.
func loadOrGenerateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				slog.Info("signing_key.loaded", "path", path)
				return key, nil
			}
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		slog.Warn("signing_key.save_failed", "err", err, "path", path)
		// Continue with in-memory key — not fatal
	} else {
		slog.Info("signing_key.generated", "path", path)
	}

	return key, nil
}

// cleanupExpiredData periodically removes expired transient data.
func cleanupExpiredData(db *storage.DB) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := db.Exec(ctx, `DELETE FROM auth_requests WHERE expires_at < NOW() - INTERVAL '1 hour'`); err != nil {
			slog.Error("cleanup.auth_requests", "err", err)
		}
		if err := db.Exec(ctx, `DELETE FROM device_codes WHERE expires_at < NOW() - INTERVAL '1 hour'`); err != nil {
			slog.Error("cleanup.device_codes", "err", err)
		}
		if err := db.Exec(ctx, `DELETE FROM refresh_tokens WHERE revoked_at < NOW() - INTERVAL '30 days'`); err != nil {
			slog.Error("cleanup.refresh_tokens", "err", err)
		}
		if err := db.Exec(ctx, `UPDATE users SET email = 'deleted-' || id::text || '@deleted.invalid', name = NULL, avatar_url = NULL, status = 'deleted', deleted_at = NOW() WHERE status = 'pending_deletion' AND deletion_scheduled_at < NOW()`); err != nil {
			slog.Error("cleanup.user_deletion", "err", err)
		}
		cancel()
	}
}
