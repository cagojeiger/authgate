package app

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
	"github.com/kangheeyong/authgate/internal/config"
	"github.com/kangheeyong/authgate/internal/observability"
	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
)

func buildHTTPServer(cfg *config.Config, mux http.Handler, httpMetrics *observability.HTTPMetrics, inflightRequests *int64) (*http.Server, string) {
	addr := fmt.Sprintf(":%d", cfg.Port)
	observedHandler := httpMetrics.Middleware(mux)
	trackedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(inflightRequests, 1)
		defer atomic.AddInt64(inflightRequests, -1)
		observedHandler.ServeHTTP(w, r)
	})

	return &http.Server{
		Addr:              addr,
		Handler:           trackedHandler,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
	}, addr
}

func startCleanupService(db *sql.DB, clk clock.Clock, auditLogPIIRetention time.Duration, metrics service.CleanupMetricsRecorder) context.CancelFunc {
	cleanupRunner := storage.NewCleanupRunner(db)
	cleanupSvc := service.NewCleanupService(cleanupRunner, clk, 10*time.Minute)
	cleanupSvc.SetAuditLogPIIRetention(auditLogPIIRetention)
	cleanupSvc.SetMetricsRecorder(metrics)
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	go cleanupSvc.Start(cleanupCtx)
	return cleanupCancel
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
