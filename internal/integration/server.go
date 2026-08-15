package integration

import (
	"context"
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
	"github.com/kangheeyong/authgate/internal/crypto"
	"github.com/kangheeyong/authgate/internal/handler"
	"github.com/kangheeyong/authgate/internal/idgen"
	"golang.org/x/time/rate"

	"github.com/kangheeyong/authgate/internal/middleware"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
	"github.com/kangheeyong/authgate/internal/upstream"
)

// devicePollInterval mirrors the production constant in cmd/authgate/main.go
// so the integration server advertises and enforces the same RFC 8628 §3.5
// poll cadence the binary ships with.
const devicePollInterval = 5 * time.Second

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
	EnableMCP bool
}

// setupCryptoKeys derives test crypto keys and registers their epochs.
func setupCryptoKeys(t *testing.T, store *storage.Storage) {
	t.Helper()
	mk := func(b byte) []byte {
		s := make([]byte, crypto.KeySize)
		for i := range s {
			s[i] = b
		}
		return s
	}
	enc, err := crypto.NewRoot(crypto.DomainEnc, "enc-test-1", mk(0x31))
	if err != nil {
		t.Fatalf("enc root: %v", err)
	}
	lookup, err := crypto.NewRoot(crypto.DomainLookup, "lkp-test-1", mk(0x32))
	if err != nil {
		t.Fatalf("lookup root: %v", err)
	}
	keys, err := crypto.NewKeys(enc, lookup)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	store.SetKeys(keys)
	if err := store.EnsureCryptoEpochs(context.Background()); err != nil {
		t.Fatalf("ensure epochs: %v", err)
	}
}

// SetupTestServerWithOptions creates a full authgate server with selectable optional adapters.
func SetupTestServerWithOptions(t *testing.T, opts SetupOptions) *TestServer {
	t.Helper()

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
	store.SetDevicePollInterval(devicePollInterval)
	// PII at-rest encryption keys are mandatory after the plaintext-PII cleanup
	// (ADR-002): signup/lookup require them, so every test server wires them.
	setupCryptoKeys(t, store)
	if opts.EnableMCP {
		cimdFetcher := mcpadapter.NewHTTPCIMDFetcher()
		clientPolicy := mcpadapter.NewClientResolutionPolicy(storage.NewCoreClientResolutionPolicy(store), cimdFetcher)
		store.SetClientResolutionPolicy(clientPolicy)
		store.SetResourceBindingPolicy(mcpadapter.NewResourceBindingPolicy(storage.NewCoreResourceBindingPolicy(), clientPolicy))
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
			PollInterval: devicePollInterval,
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
	loginSvc := service.NewLoginService(store, fakeProvider.Name(), 24*time.Hour)
	deviceSvc := service.NewDeviceService(store, fakeProvider.Name(), srv.URL, 24*time.Hour, clk)
	accountSvc := service.NewAccountService(store)

	// Handlers
	loginHandler := handler.NewLoginHandler(loginSvc, fakeProvider, true, "authgate")
	deviceHandler := handler.NewDeviceHandler(deviceSvc, fakeProvider, true, "authgate")
	accountHandler := handler.NewAccountHandler(accountSvc, srv.URL)
	var mcpLoginHandler *handler.MCPLoginHandler
	if opts.EnableMCP {
		mcpLoginSvc := service.NewMCPLoginService(store, fakeProvider.Name(), 24*time.Hour)
		mcpLoginHandler = handler.NewMCPLoginHandler(mcpLoginSvc, fakeProvider, true, "authgate")
	}

	// Routes
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]any{
			"issuer":                           srv.URL,
			"authorization_endpoint":           srv.URL + "/authorize",
			"token_endpoint":                   srv.URL + "/oauth/token",
			"revocation_endpoint":              srv.URL + "/oauth/revoke",
			"introspection_endpoint":           srv.URL + "/oauth/introspect",
			"device_authorization_endpoint":    srv.URL + "/oauth/device/authorize",
			"userinfo_endpoint":                srv.URL + "/userinfo",
			"end_session_endpoint":             srv.URL + "/end_session",
			"jwks_uri":                         srv.URL + "/keys",
			"response_types_supported":         []string{"code"},
			"grant_types_supported":            []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			"code_challenge_methods_supported": []string{"S256"},
			// Mirror the production metadata contract: advertise every auth
			// method the underlying op accepts (#189 / RFC 8414 §2).
			// Introspection only authenticates via Basic (see comment in
			// cmd/authgate/main.go), so its set is narrower.
			"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_basic", "client_secret_post"},
			"revocation_endpoint_auth_methods_supported":     []string{"none", "client_secret_basic", "client_secret_post"},
			"introspection_endpoint_auth_methods_supported":  []string{"client_secret_basic"},
			"scopes_supported":                               []string{"openid", "profile", "email", "offline_access"},
			"authorization_response_iss_parameter_supported": true,
			"client_id_metadata_document_supported":          opts.EnableMCP,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})
	authorize := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource, err := storage.ResourceFromRequestStrict(r)
		if err != nil {
			writeInvalidTargetError(w, err)
			return
		}
		provider.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})
	mux.Handle("/authorize", middleware.AuthorizationResponseIssuer(srv.URL, authorize))
	mux.Handle("/authorize/callback", middleware.AuthorizationResponseIssuer(srv.URL, provider))
	tokenRateLimiter := middleware.NewRateLimiter(rate.Limit(5), 5)
	tokenWithAtJWT := storage.WrapAccessTokenJWTType(provider, store)
	mux.Handle("/oauth/token", tokenRateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource, err := storage.ResourceFromRequestStrict(r)
		if err != nil {
			writeInvalidTargetError(w, err)
			return
		}
		tokenWithAtJWT.ServeHTTP(w, r.WithContext(storage.WithResource(r.Context(), resource)))
	})))
	mux.Handle("/oauth/revoke", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	mux.Handle("/", provider)
	mux.HandleFunc("/login", loginHandler.HandleLogin)
	mux.HandleFunc("/login/callback", loginHandler.HandleCallback)
	if opts.EnableMCP {
		mux.HandleFunc("/mcp/login", mcpLoginHandler.HandleLogin)
		mux.HandleFunc("/mcp/callback", mcpLoginHandler.HandleCallback)
	}
	mux.HandleFunc("/device", deviceHandler.HandleDevicePage)
	mux.HandleFunc("/device/approve", deviceHandler.HandleDeviceApprove)
	mux.HandleFunc("/device/auth/callback", deviceHandler.HandleDeviceCallback)
	mux.HandleFunc("/account", accountHandler.HandleDeleteAccount)
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

// writeInvalidTargetError writes the canonical OAuth invalid_target error
// JSON body for HTTP-layer rejections (e.g. duplicate resource params).
func writeInvalidTargetError(w http.ResponseWriter, cause error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_target",
		"error_description": cause.Error(),
	})
}
