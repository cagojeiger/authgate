package observability

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/kangheeyong/authgate/internal/middleware"
)



type HTTPMetrics struct {
	registry       *prometheus.Registry
	requestsTotal  *prometheus.CounterVec
	requestLatency *prometheus.HistogramVec
	inflight       prometheus.Gauge
}

func NewHTTPMetrics() *HTTPMetrics {
	reg := prometheus.NewRegistry()

	requestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authgate_http_requests_total",
			Help: "Total number of HTTP requests processed by authgate.",
		},
		[]string{"method", "route", "status"},
	)

	requestLatency := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "authgate_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "route", "status"},
	)

	inflight := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "authgate_http_inflight_requests",
			Help: "Current number of in-flight HTTP requests.",
		},
	)

	reg.MustRegister(
		requestsTotal,
		requestLatency,
		inflight,
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	return &HTTPMetrics{
		registry:       reg,
		requestsTotal:  requestsTotal,
		requestLatency: requestLatency,
		inflight:       inflight,
	}
}

func (m *HTTPMetrics) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *HTTPMetrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.inflight.Inc()
		defer m.inflight.Dec()

		requestID := middleware.RequestIDFromContext(r.Context())

		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		status := strconv.Itoa(sw.status)
		route := r.Pattern
		if route == "" {
			route = r.URL.Path
		}

		durationSec := time.Since(start).Seconds()
		m.requestsTotal.WithLabelValues(r.Method, route, status).Inc()
		m.requestLatency.WithLabelValues(r.Method, route, status).Observe(durationSec)

		slog.Info(
			"http request",
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"route", route,
			"status", sw.status,
			"duration_ms", int64(durationSec*1000),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}
