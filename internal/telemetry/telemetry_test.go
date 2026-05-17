package telemetry

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewRuntimeHandler_ExposesOnlyRuntimeCollectors(t *testing.T) {
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()

	NewRuntimeHandler().ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, want := range []string{
		"go_goroutines",
		"process_",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics body missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"authgate_http_requests_total",
		"authgate_audit_events_total",
		"authgate_audit_log_write_failures_total",
		"authgate_cleanup_runs_total",
		"authgate_db_connections_open",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metrics body contains custom metric %q", forbidden)
		}
	}
}
