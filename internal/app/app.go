package app

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kangheeyong/authgate/internal/clientinfo"
	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/db/migrator"
	"github.com/kangheeyong/authgate/internal/handler"
	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/kangheeyong/authgate/internal/middleware"
	"github.com/kangheeyong/authgate/internal/service"
)

// devicePollInterval is the minimum gap between successive device-flow
// polls. Wired into both `op.DeviceAuthorizationConfig.PollInterval` (the
// value advertised to clients in the device-authorization response) and
// `Storage.SetDevicePollInterval` (the server-side `slow_down` enforcement
// per RFC 8628 §3.5) so the two stay in lockstep.
const devicePollInterval = 5 * time.Second

func Run() {
	cfg := mustLoadConfig()
	db := mustOpenDB(cfg)
	defer func() { _ = db.Close() }()

	if err := migrator.Run(db, cfg.MigrationsPath); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	// Components
	clk := clock.RealClock{}
	gen := idgen.CryptoGenerator{}
	store := mustBuildStore(cfg, db, clk, gen)
	mustSetupCrypto(cfg, store)
	provider := mustBuildOIDCProvider(cfg, store)

	// Upstream IdP (OIDC Discovery)
	ctx := context.Background()
	upstreamOpts := buildUpstreamOptions(cfg)
	browserProvider := mustBuildUpstreamProvider(ctx, cfg, "/login/callback", upstreamOpts)
	deviceProvider := mustBuildUpstreamProvider(ctx, cfg, "/device/auth/callback", upstreamOpts)

	// Service layer
	loginService := service.NewLoginService(store, browserProvider.Name(), cfg.SessionTTL)

	// Device service
	deviceService := service.NewDeviceService(store, deviceProvider.Name(), cfg.PublicURL, cfg.SessionTTL, clk)

	// Handler layer
	loginHandler := handler.NewLoginHandler(loginService, browserProvider, cfg.DevMode, cfg.BrandName)
	deviceHandler := handler.NewDeviceHandler(deviceService, deviceProvider, cfg.DevMode, cfg.BrandName)

	var mcpLoginHandler *handler.MCPLoginHandler
	if cfg.EnableMCP {
		mcpProvider := mustBuildUpstreamProvider(ctx, cfg, "/mcp/callback", upstreamOpts)
		mcpLoginService := service.NewMCPLoginService(store, mcpProvider.Name(), cfg.SessionTTL)
		mcpLoginHandler = handler.NewMCPLoginHandler(mcpLoginService, mcpProvider, cfg.DevMode, cfg.BrandName)
	}

	// Load client config and derive CORS allowed origins.
	allowedOrigins := loadClientConfigIfPresent(cfg, store)

	var isShuttingDown atomic.Bool
	mux := http.NewServeMux()
	registerRoutes(mux, cfg, db, store, provider, loginHandler, deviceHandler, mcpLoginHandler, &isShuttingDown)

	trustedProxies, err := clientinfo.ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		log.Fatalf("config: TRUSTED_PROXIES: %v", err)
	}

	// clientinfo wraps the mux so every handler/middleware downstream reads
	// IP/UA from request context instead of r.RemoteAddr/r.UserAgent() directly.
	clientInfoHandler := clientinfo.Middleware(trustedProxies)(mux)
	// CORS sits outside clientinfo because it inspects only the Origin header.
	corsHandler := middleware.NewCORSMiddleware(allowedOrigins)(clientInfoHandler)
	// RequestIDMiddleware runs first so every handler has a request ID in context.
	requestIDHandler := middleware.RequestIDMiddleware(corsHandler)
	// SecurityHeaders is the outermost wrapper so baseline headers (CSP,
	// X-Frame-Options, nosniff, Referrer-Policy, and HSTS in prod) are present
	// on every response, including error and CORS-preflight replies.
	securityHeadersHandler := middleware.SecurityHeaders(cfg.DevMode)(requestIDHandler)

	var inflightRequests int64
	srv, addr := buildHTTPServer(cfg, securityHeadersHandler, &inflightRequests)

	cleanupCancel := startCleanupService(db, clk, cfg)
	metricsCancel := startMetricsServer(cfg)
	var stopOnce sync.Once
	stopBackground := func() {
		stopOnce.Do(func() {
			cleanupCancel()
			metricsCancel()
		})
	}
	defer stopBackground()
	installGracefulShutdown(srv, cfg, &inflightRequests, stopBackground, &isShuttingDown)

	slog.Info("authgate starting", "addr", addr, "dev", cfg.DevMode, "mcp", cfg.EnableMCP, "issuer", cfg.OIDCIssuerURL, "provider", browserProvider.Name())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}
