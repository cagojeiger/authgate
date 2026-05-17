package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
)

// SecurityRecorder owns Prometheus counters for security-relevant audit and
// cleanup outcomes.
type SecurityRecorder struct {
	events        *prometheus.CounterVec
	writeFailures *prometheus.CounterVec
	cleanupRuns   *prometheus.CounterVec
}

// AuditRecorder is kept as a compatibility alias for storage/service recorder
// wiring that still describes the audit-specific side of this collector.
type AuditRecorder = SecurityRecorder

// NewSecurityRecorder registers audit/security counters into reg and returns a
// recorder.
// Stages: "marshal" (json.Marshal of metadata failed before any DB call) and
// "insert" (audit_log INSERT failed). Tracking the two separately lets alert
// rules distinguish input-shape bugs from DB outages so an oncall responder
// can route the page correctly.
func NewSecurityRecorder(reg *prometheus.Registry) *SecurityRecorder {
	events := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authgate_audit_events_total",
			Help: "Total number of successfully persisted audit events, partitioned by event_type and channel.",
		},
		[]string{"event_type", "channel"},
	)

	writeFailures := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authgate_audit_log_write_failures_total",
			Help: "Total number of audit log write failures, partitioned by stage (marshal|insert).",
		},
		[]string{"stage"},
	)

	cleanupRuns := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authgate_cleanup_runs_total",
			Help: "Total number of cleanup service runs, partitioned by result (success|failure).",
		},
		[]string{"result"},
	)

	reg.MustRegister(events, writeFailures, cleanupRuns)
	// Pre-create the known label series so increase()/rate() see a baseline
	// of 0 from the first scrape — otherwise the alert in
	// docs/spec/009-operations.md would miss the very first failure.
	writeFailures.WithLabelValues("marshal")
	writeFailures.WithLabelValues("insert")
	cleanupRuns.WithLabelValues("success")
	cleanupRuns.WithLabelValues("failure")
	return &SecurityRecorder{
		events:        events,
		writeFailures: writeFailures,
		cleanupRuns:   cleanupRuns,
	}
}

func NewAuditRecorder(reg *prometheus.Registry) *AuditRecorder {
	return NewSecurityRecorder(reg)
}

// RecordEvent increments the audit-event counter after the audit row is
// successfully persisted. Nil receivers are tolerated so tests can omit the
// recorder entirely.
func (r *SecurityRecorder) RecordEvent(eventType, channel string) {
	if r == nil {
		return
	}
	r.events.WithLabelValues(eventType, channel).Inc()
}

// RecordWriteFailure increments the failure counter for the given stage.
// Callers pass either "marshal" or "insert"; other labels are accepted but
// will not match the alert rules in docs/spec/009-operations.md.
// Nil receivers are tolerated so test wiring can omit the recorder entirely.
func (r *SecurityRecorder) RecordWriteFailure(stage string) {
	if r == nil {
		return
	}
	r.writeFailures.WithLabelValues(stage).Inc()
}

// RecordCleanupRun increments the cleanup run counter for "success" or
// "failure". Other result labels are accepted but will not match the stock
// alert examples.
func (r *SecurityRecorder) RecordCleanupRun(result string) {
	if r == nil {
		return
	}
	r.cleanupRuns.WithLabelValues(result).Inc()
}
