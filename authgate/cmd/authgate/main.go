package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"authgate/internal/config"
	httphandlers "authgate/internal/http"
	"authgate/internal/storage"
	"authgate/internal/tokens"
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

	// Run migrations
	if err := runMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	tokenMgr, err := tokens.NewManager(cfg.PublicURL, cfg.AccessTokenTTL)
	if err != nil {
		log.Fatalf("Failed to create token manager: %v", err)
	}

	// Create upstream provider based on config
	var upstream httphandlers.UpstreamProvider
	if cfg.UpstreamProvider == "google" {
		upstream = NewGoogleProvider(cfg)
	} else {
		upstream = NewMockProvider(cfg)
	}

	server, err := httphandlers.NewServer(cfg, db, tokenMgr, upstream)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	httpServer := &http.Server{
		Addr:    ":" + cfg.ServerPort,
		Handler: server,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	}()

	log.Printf("authgate server starting on :%s", cfg.ServerPort)
	log.Printf("Using upstream provider: %s", cfg.UpstreamProvider)

	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

func runMigrations(db *storage.DB) error {
	// Read and execute migration file
	data, err := os.ReadFile("migrations/001_init.sql")
	if err != nil {
		return fmt.Errorf("failed to read migration file: %w", err)
	}

	ctx := context.Background()
	if err := db.Exec(ctx, string(data)); err != nil {
		return fmt.Errorf("failed to execute migration: %w", err)
	}

	return nil
}

// Placeholder providers - will be implemented in separate files
type GoogleProvider struct {
	cfg *config.Config
}

func NewGoogleProvider(cfg *config.Config) *GoogleProvider {
	return &GoogleProvider{cfg: cfg}
}

func (p *GoogleProvider) GetAuthorizeURL(state, nonce, redirectURI string) string {
	return fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+email+profile&state=%s",
		p.cfg.GoogleClientID, redirectURI, state)
}

func (p *GoogleProvider) ExchangeCode(ctx context.Context, code string) (*httphandlers.UserInfo, error) {
	// TODO: Implement Google OAuth exchange
	return nil, fmt.Errorf("Google provider not yet implemented")
}

type MockProvider struct {
	cfg *config.Config
}

func NewMockProvider(cfg *config.Config) *MockProvider {
	return &MockProvider{cfg: cfg}
}

func (p *MockProvider) GetAuthorizeURL(state, nonce, redirectURI string) string {
	return fmt.Sprintf("%s/authorize?state=%s&redirect_uri=%s",
		p.cfg.MockIDPPublicURL, state, url.QueryEscape(redirectURI))
}

func (p *MockProvider) ExchangeCode(ctx context.Context, code string) (*httphandlers.UserInfo, error) {
	// Call mock-idp to exchange code
	data := url.Values{}
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")

	resp, err := http.PostForm(p.cfg.MockIDPURL+"/token", data)
	if err != nil {
		return nil, fmt.Errorf("failed to call mock-idp: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("mock-idp returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		UserInfo struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
			Picture       string `json:"picture"`
		} `json:"user_info"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &httphandlers.UserInfo{
		ProviderUserID: result.UserInfo.Sub,
		Email:          result.UserInfo.Email,
		EmailVerified:  result.UserInfo.EmailVerified,
		Name:           result.UserInfo.Name,
		Picture:        result.UserInfo.Picture,
	}, nil
}
