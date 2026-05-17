package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestAuditMetrics_RecordSecurityCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewAuditMetrics(reg)

	m.RecordEvent("auth.inactive_user", "browser")
	m.RecordWriteFailure("insert")
	m.RecordCleanupRun("success")

	assertCounterValue(t, reg, "authgate_audit_events_total", map[string]string{
		"event_type": "auth.inactive_user",
		"channel":    "browser",
	}, 1)
	assertCounterValue(t, reg, "authgate_audit_log_write_failures_total", map[string]string{
		"stage": "insert",
	}, 1)
	assertCounterValue(t, reg, "authgate_cleanup_runs_total", map[string]string{
		"result": "success",
	}, 1)
}

func assertCounterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string, want float64) {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if !metricHasLabels(metric.GetLabel(), labels) {
				continue
			}
			if got := metric.GetCounter().GetValue(); got != want {
				t.Fatalf("%s labels %v = %v, want %v", name, labels, got, want)
			}
			return
		}
	}

	t.Fatalf("missing %s labels %v", name, labels)
}

func metricHasLabels(gotLabels []*dto.LabelPair, want map[string]string) bool {
	got := make(map[string]string, len(gotLabels))
	for _, label := range gotLabels {
		got[label.GetName()] = label.GetValue()
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}
