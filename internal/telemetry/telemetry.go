package telemetry

import (
	"database/sql"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Telemetry owns the Prometheus registry exposed by /metrics and groups the
// recorders registered into it.
type Telemetry struct {
	registry *prometheus.Registry

	HTTP     *HTTPRecorder
	Security *SecurityRecorder
	DB       *DBCollectors
}

func NewTelemetry(db *sql.DB) *Telemetry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	t := &Telemetry{
		registry: reg,
	}
	t.HTTP = NewHTTPRecorder(reg)
	t.Security = NewSecurityRecorder(reg)
	if db != nil {
		t.DB = NewDBCollectors(reg, db)
	}
	return t
}

func (t *Telemetry) Handler() http.Handler {
	return promhttp.HandlerFor(t.registry, promhttp.HandlerOpts{})
}

func (t *Telemetry) Registry() *prometheus.Registry {
	return t.registry
}
