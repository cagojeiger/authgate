package observability

import (
	"github.com/prometheus/client_golang/prometheus"
)

// AuditMetrics owns Prometheus counters for audit-log write outcomes.
// It registers into the shared HTTPMetrics registry so a single /metrics
// scrape target exposes both groups.
type AuditMetrics struct {
	writeFailures *prometheus.CounterVec
}

// NewAuditMetrics registers audit-log counters into reg and returns a recorder.
// Stages: "marshal" (json.Marshal of metadata failed before any DB call) and
// "insert" (audit_log INSERT failed). Tracking the two separately lets alert
// rules distinguish input-shape bugs from DB outages so an oncall responder
// can route the page correctly.
func NewAuditMetrics(reg *prometheus.Registry) *AuditMetrics {
	cv := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authgate_audit_log_write_failures_total",
			Help: "Total number of audit log write failures, partitioned by stage (marshal|insert).",
		},
		[]string{"stage"},
	)
	reg.MustRegister(cv)
	// Pre-create the known label series so increase()/rate() see a baseline
	// of 0 from the first scrape — otherwise the alert in
	// docs/spec/009-operations.md would miss the very first failure.
	cv.WithLabelValues("marshal")
	cv.WithLabelValues("insert")
	return &AuditMetrics{writeFailures: cv}
}

// RecordWriteFailure increments the failure counter for the given stage.
// Callers pass either "marshal" or "insert"; other labels are accepted but
// will not match the alert rules in docs/spec/009-operations.md.
// Nil receivers are tolerated so test wiring can omit the recorder entirely.
func (m *AuditMetrics) RecordWriteFailure(stage string) {
	if m == nil {
		return
	}
	m.writeFailures.WithLabelValues(stage).Inc()
}
