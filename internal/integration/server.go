package integration

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	mcpadapter "github.com/kangheeyong/authgate/internal/adapter/mcp"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/handler"
	"github.com/kangheeyong/authgate/internal/idgen"
	"golang.org/x/time/rate"

	"github.com/kangheeyong/authgate/internal/middleware"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
	"github.com/kangheeyong/authgate/internal/upstream"
)

// TestServer holds everything needed for integration tests.
type TestServer struct {
	Server  *httptest.Server
	Store   *storage.Storage
	DB      *sql.DB
	Clock   *clock.FixedClock
	BaseURL string
}

// SetupTestServer creates a full authgate server with testcontainers PostgreSQL.
func SetupTestServer(t *testing.T) *TestServer {
	return SetupTestServerWithOptions(t, SetupOptions{EnableMCP: true})
}

type SetupOptions struct {
	EnableMCP           bool
	RateLimitAuthRPS    float64
	RateLimitAuthBurst  int
	RateLimitTokenRPS   float64
	RateLimitTokenBurst int
}

// SetupTestServerWithOptions creates a full authgate server with selectable optional adapters.
func SetupTestServerWithOptions(t *testing.T, opts SetupOptions) *TestServer {
	t.Helper()

	if opts.RateLimitAuthRPS == 0 {
		opts.RateLimitAuthRPS = 1000.0
	}
	if opts.RateLimitAuthBurst == 0 {
		opts.RateLimitAuthBurst = 1000
	}
	if opts.RateLimitTokenRPS == 0 {
		opts.RateLimitTokenRPS = 1000.0
	}
	if opts.RateLimitTokenBurst == 0 {
		opts.RateLimitTokenBurst = 1000
	}

	db := testutil.SetupPostgres(t)
	clk := &clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}

	stateChecker := func(user *storage.User) error {
		if user.Status != "active" {
			return fmt.Errorf("account not active: %s", user.Status)
		}
		return nil
	}

	store := storage.New(db, clk, gen, stateChecker, 15*time.Minute, 30*24*time.Hour)
	if opts.EnableMCP {
		cimdFetcher := mcpadapter.NewHTTPCIMDFetcher()
		store.SetClientResolutionPolicy(mcpadapter.NewClientResolutionPolicy(storage.NewCoreClientResolutionPolicy(store), cimdFetcher))
		store.SetResourceBindingPolicy(mcpadapter.NewResourceBindingPolicy(storage.NewCoreResourceBindingPolicy()))
	}

	// Generate signing key
	key, err := storage.LoadOrGenerateKey(t.TempDir() + "/signing_key.pem")
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	store.SetSigningKey(key, "test-key-1")

	// We need to create the server first to know the URL, then set the issuer.
	// Use a 2-pass approach: create mux, wrap in httptest, then set issuer.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Register test clients in memory
	store.LoadClients([]storage.ClientConfigEntry{
		{
			ClientID:          "test-client",
			ClientType:        "public",
			LoginChannel:      "browser",
			Name:              "Test",
			RedirectURIs:      []string{srv.URL + "/callback"},
			AllowedScopes:     []string{"openid", "profile", "email", "offline_access"},
			AllowedGrantTypes: []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		},
	})
	if opts.EnableMCP {
		store.LoadClients([]storage.ClientConfigEntry{
			{
				ClientID:          "mcp-client",
				ClientType:        "public",
				LoginChannel:      "mcp",
				Name:              "MCP Test",
				RedirectURIs:      []string{srv.URL + "/callback"},
				AllowedScopes:     []string{"openid", "profile", "email", "offline_access"},
				AllowedGrantTypes: []string{"authorization_code", "refresh_token"},
			},
		})
	}

	// zitadel OP
	cryptoKey := sha256.Sum256([]byte("test-secret-32-chars-long-enough!"))
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
		},
	}

	provider, err := op.NewProvider(opConfig, store, op.StaticIssuer(srv.URL),
		op.WithAllowInsecure(),
		op.WithCustomTokenEndpoint(op.NewEndpoint("oauth/token")),
		op.WithCustomRevocationEndpoint(op.NewEndpoint("oauth/revoke")),
		op.WithCustomDeviceAuthorizationEndpoint(op.NewEndpoint("oauth/device/authorize")),
	)
	if err != nil {
		t.Fatalf("oidc provider: %v", err)
	}

	// Fake upstream that auto-approves
	fakeProvider := &upstream.FakeProvider{ProviderName: "google",
		User: &upstream.UserInfo{Sub: "test-google-sub", Email: "test@example.com", EmailVerified: true, Name: "Test User"},
	}

	// Services
	loginSvc := service.NewLoginService(store, fakeProvider, 24*time.Hour)
	deviceSvc := service.NewDeviceService(store, fakeProvider, srv.URL, 24*time.Hour, clk)
	accountSvc := service.NewAccountService(store)
	consoleSvc := service.NewConsoleService(store)

	// Handlers
	loginHandler := handler.NewLoginHandler(loginSvc, true, "authgate")
	deviceHandler := handler.NewDeviceHandler(deviceSvc, true, "authgate")
	accountHandler := handler.NewAccountHandler(accountSvc, srv.URL)
	consoleHandler := handler.NewConsoleHandler(consoleSvc)
	var mcpLoginHandler *handler.MCPLoginHandler
	if opts.EnableMCP {
		mcpLoginSvc := service.NewMCPLoginService(store, fakeProvider, 24*time.Hour)
		mcpLoginHandler = handler.NewMCPLoginHandler(mcpLoginSvc, true, "authgate")
	}

	// Routes
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/oauth/token",
			"revocation_endpoint":                   srv.URL + "/oauth/revoke",
			"device_authorization_endpoint":         srv.URL + "/oauth/device/authorize",
			"userinfo_endpoint":                     srv.URL + "/userinfo",
			"end_session_endpoint":                  srv.URL + "/end_session",
			"jwks_uri":                              srv.URL + "/keys",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
			"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
			"client_id_metadata_document_supported": opts.EnableMCP,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})
	authRateLimiter := middleware.NewRateLimiter(rate.Limit(opts.RateLimitAuthRPS), opts.RateLimitAuthBurst)
	tokenRateLimiter := middleware.NewRateLimiter(rate.Limit(opts.RateLimitTokenRPS), opts.RateLimitTokenBurst)
	mux.Handle("/authorize", authRateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource := storage.ResourceFromRequest(r)
		provider.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})))
	mux.Handle("/oauth/token", tokenRateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource := storage.ResourceFromRequest(r)
		provider.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})))
	mux.Handle("/oauth/revoke", tokenRateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !opts.EnableMCP {
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
	})))
	mux.Handle("/oauth/device/authorize", tokenRateLimiter(provider))
	mux.Handle("/", provider)
	mux.Handle("/login", authRateLimiter(http.HandlerFunc(loginHandler.HandleLogin)))
	mux.Handle("/login/callback", authRateLimiter(http.HandlerFunc(loginHandler.HandleCallback)))
	if opts.EnableMCP {
		mux.Handle("/mcp/login", authRateLimiter(http.HandlerFunc(mcpLoginHandler.HandleLogin)))
		mux.Handle("/mcp/callback", authRateLimiter(http.HandlerFunc(mcpLoginHandler.HandleCallback)))
	}
	mux.Handle("/device", tokenRateLimiter(http.HandlerFunc(deviceHandler.HandleDevicePage)))
	mux.Handle("/device/approve", tokenRateLimiter(http.HandlerFunc(deviceHandler.HandleDeviceApprove)))
	mux.Handle("/device/auth/callback", tokenRateLimiter(http.HandlerFunc(deviceHandler.HandleDeviceCallback)))
	mux.Handle("/account", authRateLimiter(http.HandlerFunc(accountHandler.HandleDeleteAccount)))
	mux.Handle("/console/clients", authRateLimiter(http.HandlerFunc(consoleHandler.HandleListClients)))
	mux.Handle("/console/me/connections", authRateLimiter(http.HandlerFunc(consoleHandler.HandleListConnections)))
	mux.Handle("/console/me/connections/{client_id}", authRateLimiter(http.HandlerFunc(consoleHandler.HandleRevokeConnection)))
	mux.Handle("/console/me/sessions", authRateLimiter(http.HandlerFunc(consoleHandler.HandleListSessions)))
	mux.Handle("/console/me/sessions/{id}", authRateLimiter(http.HandlerFunc(consoleHandler.HandleRevokeSession)))
	mux.Handle("/console/me/sessions/revoke-others", authRateLimiter(http.HandlerFunc(consoleHandler.HandleRevokeOtherSessions)))
	mux.Handle("/console/me/audit-log", authRateLimiter(http.HandlerFunc(consoleHandler.HandleGetAuditLog)))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Apply CORS middleware: allowed origin is derived from the test client's redirect URI (srv.URL).
	corsOrigins := middleware.OriginsFromRedirectURIs([]string{srv.URL + "/callback"})
	corsMW := middleware.NewCORSMiddleware(corsOrigins)
	srv.Config.Handler = middleware.RequestIDMiddleware(corsMW(mux))

	return &TestServer{
		Server:  srv,
		Store:   store,
		DB:      db,
		Clock:   clk,
		BaseURL: srv.URL,
	}
}
