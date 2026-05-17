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
	defer db.Close()

	if err := migrator.Run(db, cfg.MigrationsPath); err != nil {
		log.Fatalf("migrations: %v", err)
	}

	// Components
	clk := clock.RealClock{}
	gen := idgen.CryptoGenerator{}
	store := mustBuildStore(cfg, db, clk, gen)
	provider := mustBuildOIDCProvider(cfg, store)

	// Upstream IdP (OIDC Discovery)
	ctx := context.Background()
	upstreamOpts := buildUpstreamOptions(cfg)
	browserProvider := mustBuildUpstreamProvider(ctx, cfg, "/login/callback", upstreamOpts)
	deviceProvider := mustBuildUpstreamProvider(ctx, cfg, "/device/auth/callback", upstreamOpts)

	// Service layer
	loginService := service.NewLoginService(store, browserProvider, cfg.SessionTTL)

	// Device service
	deviceService := service.NewDeviceService(store, deviceProvider, cfg.PublicURL, cfg.SessionTTL, clk)

	// Account service
	accountService := service.NewAccountService(store)

	// Console service
	consoleService := service.NewConsoleService(store)

	// Handler layer
	loginHandler := handler.NewLoginHandler(loginService, cfg.DevMode, cfg.BrandName)
	deviceHandler := handler.NewDeviceHandler(deviceService, cfg.DevMode, cfg.BrandName)
	accountHandler := handler.NewAccountHandler(accountService, cfg.PublicURL)
	consoleHandler := handler.NewConsoleHandler(consoleService)

	var mcpLoginHandler *handler.MCPLoginHandler
	if cfg.EnableMCP {
		mcpProvider := mustBuildUpstreamProvider(ctx, cfg, "/mcp/callback", upstreamOpts)
		mcpLoginService := service.NewMCPLoginService(store, mcpProvider, cfg.SessionTTL)
		mcpLoginHandler = handler.NewMCPLoginHandler(mcpLoginService, cfg.DevMode, cfg.BrandName)
	}

	// Load client config and derive CORS allowed origins.
	allowedOrigins := loadClientConfigIfPresent(cfg, store)

	var isShuttingDown atomic.Bool
	mux := http.NewServeMux()
	registerRoutes(mux, cfg, db, store, provider, loginHandler, deviceHandler, accountHandler, mcpLoginHandler, consoleHandler, &isShuttingDown)

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

	var inflightRequests int64
	srv, addr := buildHTTPServer(cfg, requestIDHandler, &inflightRequests)

	cleanupCancel := startCleanupService(db, clk, cfg.AuditLogPIIRetention)
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
