package integration

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/guard"
	"github.com/kangheeyong/authgate/internal/handler"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/testutil"
	"github.com/kangheeyong/authgate/internal/upstream"
)

const (
	TestTermsVersion   = "2026-03-28"
	TestPrivacyVersion = "2026-03-28"
)

// TestServer holds everything needed for integration tests.
type TestServer struct {
	Server  *httptest.Server
	Store   *storage.Storage
	DB      *sql.DB
	Clock   clock.FixedClock
	BaseURL string
}

// SetupTestServer creates a full authgate server with testcontainers PostgreSQL.
func SetupTestServer(t *testing.T) *TestServer {
	t.Helper()

	db := testutil.SetupPostgres(t)
	clk := clock.FixedClock{T: time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)}
	gen := idgen.CryptoGenerator{}

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
		state := guard.DeriveLoginState(ui, TestTermsVersion, TestPrivacyVersion)
		if state != guard.OnboardingComplete {
			return fmt.Errorf("login state: %s", state)
		}
		return nil
	}

	store := storage.New(db, clk, gen, stateChecker, 15*time.Minute, 30*24*time.Hour)

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

	// Register test client in DB
	db.Exec(`INSERT INTO oauth_clients (client_id, client_type, login_channel, name, redirect_uris, allowed_scopes, allowed_grant_types)
		VALUES ('test-client', 'public', 'browser', 'Test', $1, '{openid,profile,email,offline_access}', '{authorization_code,refresh_token,urn:ietf:params:oauth:grant-type:device_code}')
		ON CONFLICT (client_id) DO NOTHING`,
		storage.StringArray{srv.URL + "/callback"})
	db.Exec(`INSERT INTO oauth_clients (client_id, client_type, login_channel, name, redirect_uris, allowed_scopes, allowed_grant_types)
		VALUES ('mcp-client', 'public', 'mcp', 'MCP Test', $1, '{openid,profile,email,offline_access}', '{authorization_code,refresh_token}')
		ON CONFLICT (client_id) DO NOTHING`,
		storage.StringArray{srv.URL + "/callback"})

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
	fakeProvider := &upstream.FakeProvider{
		User: &upstream.UserInfo{Sub: "test-google-sub", Email: "test@example.com", EmailVerified: true, Name: "Test User"},
	}

	// Services
	loginSvc := service.NewLoginService(store, fakeProvider, fakeProvider, TestTermsVersion, TestPrivacyVersion, 24*time.Hour)
	deviceSvc := service.NewDeviceService(store, fakeProvider, TestTermsVersion, TestPrivacyVersion, srv.URL, 24*time.Hour)
	accountSvc := service.NewAccountService(db, clk)

	// Handlers
	loginHandler := handler.NewLoginHandler(loginSvc, true)
	deviceHandler := handler.NewDeviceHandler(deviceSvc, true)
	accountHandler := handler.NewAccountHandler(accountSvc, store)

	// Routes
	mux.Handle("/", provider)
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
	mux.HandleFunc("/device", deviceHandler.HandleDevicePage)
	mux.HandleFunc("/device/approve", deviceHandler.HandleDeviceApprove)
	mux.HandleFunc("/device/auth/callback", deviceHandler.HandleDeviceCallback)
	mux.HandleFunc("/account", accountHandler.HandleDeleteAccount)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"healthy"}`))
	})

	return &TestServer{
		Server:  srv,
		Store:   store,
		DB:      db,
		Clock:   clk,
		BaseURL: srv.URL,
	}
}
