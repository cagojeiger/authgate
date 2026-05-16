package observability

import (
	"database/sql"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics owns the Prometheus registry exposed by /metrics and groups the
// collectors registered into it.
type Metrics struct {
	registry *prometheus.Registry

	HTTP     *HTTPMetrics
	Security *SecurityMetrics
	DB       *DBMetrics
}

func NewMetrics(db *sql.DB) *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	metrics := &Metrics{
		registry: reg,
	}
	metrics.HTTP = NewHTTPMetrics(reg)
	metrics.Security = NewSecurityMetrics(reg)
	if db != nil {
		metrics.DB = NewDBMetrics(reg, db)
	}
	return metrics
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}
