package telemetry

import (
	"database/sql"

	"github.com/prometheus/client_golang/prometheus"
)

// DBCollectors registers sql.DB pool gauges/counters into the shared /metrics
// registry. Values are sampled from db.Stats() at scrape time.
type DBCollectors struct{}

func NewDBCollectors(reg *prometheus.Registry, db *sql.DB) *DBCollectors {
	reg.MustRegister(
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "authgate_db_connections_open",
				Help: "Current number of open database connections.",
			},
			func() float64 { return float64(db.Stats().OpenConnections) },
		),
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "authgate_db_connections_in_use",
				Help: "Current number of in-use database connections.",
			},
			func() float64 { return float64(db.Stats().InUse) },
		),
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "authgate_db_connections_idle",
				Help: "Current number of idle database connections.",
			},
			func() float64 { return float64(db.Stats().Idle) },
		),
		prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "authgate_db_connections_max_open",
				Help: "Configured maximum number of open database connections. Zero means unlimited.",
			},
			func() float64 { return float64(db.Stats().MaxOpenConnections) },
		),
		prometheus.NewCounterFunc(
			prometheus.CounterOpts{
				Name: "authgate_db_wait_count_total",
				Help: "Total number of times a database query waited for a connection.",
			},
			func() float64 { return float64(db.Stats().WaitCount) },
		),
		prometheus.NewCounterFunc(
			prometheus.CounterOpts{
				Name: "authgate_db_wait_duration_seconds_total",
				Help: "Total time spent waiting for database connections in seconds.",
			},
			func() float64 { return db.Stats().WaitDuration.Seconds() },
		),
	)
	return &DBCollectors{}
}
