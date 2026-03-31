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
	listenAddr := envDefault("LISTEN_ADDR", ":9090")
	clientID := envDefault("CLIENT_ID", "sample-app")
	authgateInternal := envDefault("AUTHGATE_ISSUER", "http://localhost:8080")      // server-to-server
	authgateBrowser := envDefault("AUTHGATE_BROWSER_URL", "http://localhost:8080")   // browser-facing
	selfURL := envDefault("SELF_URL", "http://localhost:9090")

	redirectURI := selfURL + "/auth/callback"
	authorizeURL := authgateBrowser + "/authorize"
	tokenURL := authgateInternal + "/oauth/token"
	userinfoURL := authgateInternal + "/userinfo"
	jwksURL := authgateInternal + "/keys"

	sessions := NewSessionStore()
	verifier := NewJWKSVerifier(jwksURL, authgateBrowser, clientID)
	authHandler := NewAuthHandler(sessions, clientID, redirectURI, authorizeURL, tokenURL, userinfoURL)
	authMiddleware := RequireAuth(verifier, authHandler)

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

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	slog.Info("sample-app starting", "addr", listenAddr, "client_id", clientID, "authgate", authgateBrowser)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(fmt.Errorf("server: %w", err))
	}
}
