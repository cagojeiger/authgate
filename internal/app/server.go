package app

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
	"github.com/kangheeyong/authgate/internal/telemetry"
)

// maxHeaderBytes caps request header size on both the main and metrics servers.
// authgate's requests carry only OAuth params, a session cookie and normal
// proxy headers, so 64 KiB is generous; the explicit cap avoids relying on
// net/http's 1 MB default and bounds per-connection header memory.
const maxHeaderBytes = 64 << 10

func buildHTTPServer(cfg *config.Config, mux http.Handler, inflightRequests *int64) (*http.Server, string) {
	addr := fmt.Sprintf(":%d", cfg.Port)
	trackedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(inflightRequests, 1)
		defer atomic.AddInt64(inflightRequests, -1)
		mux.ServeHTTP(w, r)
	})

	return &http.Server{
		Addr:              addr,
		Handler:           trackedHandler,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}, addr
}

func startCleanupService(db *sql.DB, clk clock.Clock, auditLogPIIRetention time.Duration) context.CancelFunc {
	cleanupRunner := storage.NewCleanupRunner(db)
	cleanupSvc := service.NewCleanupService(cleanupRunner, clk, 10*time.Minute)
	cleanupSvc.SetAuditLogPIIRetention(auditLogPIIRetention)
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	go cleanupSvc.Start(cleanupCtx)
	return cleanupCancel
}

func startMetricsServer(cfg *config.Config) context.CancelFunc {
	if cfg.MetricsAddr == "" {
		return func() {}
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", cfg.MetricsAddr)
	if err != nil {
		log.Fatalf("metrics listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", telemetry.NewRuntimeHandler())
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	go func() {
		slog.Info("metrics server starting", "addr", cfg.MetricsAddr)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server failed", "error", err)
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("metrics server shutdown failed", "error", err)
		}
	}
}

func installGracefulShutdown(srv *http.Server, cfg *config.Config, inflightRequests *int64, cleanupCancel context.CancelFunc, isShuttingDown *atomic.Bool) {
	go func() {
		sigCh := make(chan os.Signal, 2)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		isShuttingDown.Store(true)
		slog.Info("shutdown signal received", "inflight_requests", atomic.LoadInt64(inflightRequests))

		go func() {
			<-sigCh
			slog.Warn("second shutdown signal received; forcing close")
			_ = srv.Close()
		}()

		cleanupCancel()
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
		}
		signal.Stop(sigCh)
		slog.Info("shutdown completed", "inflight_requests", atomic.LoadInt64(inflightRequests))
	}()
}
