package http

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"authgate/internal/config"
	"authgate/internal/pages"
	"authgate/internal/service"
	"authgate/internal/tokens"

	"github.com/gorilla/mux"
)

type Server struct {
	config    *config.Config
	store     service.Store
	tokens    *tokens.Manager
	router    *mux.Router
	templates *template.Template
	pages     *pages.Renderer
	upstream  UpstreamProvider
}

type UpstreamProvider interface {
	GetAuthorizeURL(state, nonce, redirectURI string) string
	ExchangeCode(ctx context.Context, code string) (*UserInfo, error)
}

type UserInfo struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	Picture        string
}

func NewServer(cfg *config.Config, store service.Store, tokenMgr *tokens.Manager, upstream UpstreamProvider) (*Server, error) {
	s := &Server{
		config:   cfg,
		store:    store,
		tokens:   tokenMgr,
		router:   mux.NewRouter(),
		upstream: upstream,
	}

	tmpl, err := template.ParseGlob("templates/*.html")
	if err != nil {
		log.Printf("Warning: Failed to parse templates: %v", err)
		tmpl = template.New("dummy")
	}
	s.templates = tmpl
	s.pages = pages.NewRenderer(tmpl)

	s.setupRoutes()
	return s, nil
}

func (s *Server) setupRoutes() {
	s.router.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery).Methods("GET")
	s.router.HandleFunc("/.well-known/jwks.json", s.handleJWKS).Methods("GET")

	s.router.HandleFunc("/oauth/authorize", s.handleAuthorize).Methods("GET")
	s.router.HandleFunc("/oauth/callback", s.handleCallback).Methods("GET")
	s.router.HandleFunc("/oauth/token", s.handleToken).Methods("POST")
	s.router.HandleFunc("/oauth/consent", s.handleConsent).Methods("POST")
	s.router.HandleFunc("/oauth/logout", s.handleLogout).Methods("GET")

	s.router.HandleFunc("/oauth/device/authorize", s.handleDeviceAuthorize).Methods("POST")

	s.router.HandleFunc("/device", s.handleDevicePage).Methods("GET")
	s.router.HandleFunc("/device/approve", s.handleDeviceApprove).Methods("POST")

	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
	s.router.HandleFunc("/ready", s.handleReady).Methods("GET")

	s.router.PathPrefix("/").HandlerFunc(s.handleHome)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"issuer":                                s.config.PublicURL,
		"authorization_endpoint":                s.config.PublicURL + "/oauth/authorize",
		"token_endpoint":                        s.config.PublicURL + "/oauth/token",
		"jwks_uri":                              s.config.PublicURL + "/.well-known/jwks.json",
		"end_session_endpoint":                  s.config.PublicURL + "/oauth/logout",
		"device_authorization_endpoint":         s.config.PublicURL + "/oauth/device/authorize",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name", "preferred_username"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.tokens.GetJWKS())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "not ready",
			"checks": map[string]string{
				"database": "disconnected",
			},
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ready",
		"checks": map[string]string{
			"database": "connected",
		},
	})
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>authgate</title></head>
<body>
<h1>authgate</h1>
<p>Central authentication service</p>
<ul>
<li><a href="/.well-known/openid-configuration">OIDC Discovery</a></li>
<li><a href="/.well-known/jwks.json">JWKS</a></li>
<li><a href="/health">Health</a></li>
</ul>
</body>
</html>`)
}
