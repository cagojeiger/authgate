package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
)

//go:embed static/*
var staticFS embed.FS

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	cfg := loadAppConfig()
	srv := buildServer(cfg)

	slog.Info("sample-app starting", "addr", cfg.ListenAddr, "client_id", cfg.ClientID, "authgate", cfg.AuthgateBrowser)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(fmt.Errorf("server: %w", err))
	}
}

type appConfig struct {
	ListenAddr       string
	ClientID         string
	AuthgateInternal string
	AuthgateBrowser  string
	SelfURL          string
}

func loadAppConfig() appConfig {
	return appConfig{
		ListenAddr:       envDefault("LISTEN_ADDR", ":9090"),
		ClientID:         envDefault("CLIENT_ID", "sample-app"),
		AuthgateInternal: envDefault("AUTHGATE_ISSUER", "http://localhost:8080"),
		AuthgateBrowser:  envDefault("AUTHGATE_BROWSER_URL", "http://localhost:8080"),
		SelfURL:          envDefault("SELF_URL", "http://localhost:9090"),
	}
}

func buildServer(cfg appConfig) *http.Server {
	redirectURI := cfg.SelfURL + "/auth/callback"
	authorizeURL := cfg.AuthgateBrowser + "/authorize"
	tokenURL := cfg.AuthgateInternal + "/oauth/token"
	userinfoURL := cfg.AuthgateInternal + "/userinfo"
	jwksURL := cfg.AuthgateInternal + "/keys"

	sessions := NewSessionStore()
	verifier := NewJWKSVerifier(jwksURL, cfg.AuthgateBrowser, cfg.ClientID)
	authHandler := NewAuthHandler(sessions, cfg.ClientID, redirectURI, authorizeURL, tokenURL, userinfoURL)
	authMiddleware := RequireAuth(verifier, authHandler)

	mux := newWebAppMux(authHandler, authMiddleware)
	return &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
	}
}

func newWebAppMux(authHandler *AuthHandler, authMiddleware func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()

	// Auth routes (registered before catch-all)
	mux.HandleFunc("GET /auth/login", authHandler.HandleLogin)
	mux.HandleFunc("GET /auth/callback", authHandler.HandleCallback)
	mux.HandleFunc("GET /auth/logout", authHandler.HandleLogout)

	// Protected API routes
	mux.Handle("GET /api/me", authMiddleware(http.HandlerFunc(HandleMe)))
	mux.Handle("GET /api/data", authMiddleware(http.HandlerFunc(HandleData)))

	// Static files (catch-all, must be last)
	staticContent, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(staticContent)))
	return mux
}
