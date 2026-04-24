package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kangheeyong/authgate/internal/middleware"
)

// wrapWithRequestID wraps a handler with RequestIDMiddleware so the context
// is populated before the observability middleware reads it.
func wrapWithRequestID(h http.Handler) http.Handler {
	return middleware.RequestIDMiddleware(h)
}

func TestMiddleware_SetsRequestIDAndRecordsMetrics(t *testing.T) {
	m := NewHTTPMetrics()
	inner := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	h := wrapWithRequestID(inner)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing X-Request-ID header")
	}

	metrics, err := m.registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	var foundReqTotal bool
	var foundInflight bool
	for _, mf := range metrics {
		switch mf.GetName() {
		case "authgate_http_requests_total":
			for _, metric := range mf.GetMetric() {
				labels := map[string]string{}
				for _, lp := range metric.GetLabel() {
					labels[lp.GetName()] = lp.GetValue()
				}
				if labels["method"] == http.MethodGet && labels["status"] == "201" {
					foundReqTotal = true
				}
			}
		case "authgate_http_inflight_requests":
			if len(mf.GetMetric()) > 0 && mf.GetMetric()[0].GetGauge().GetValue() == 0 {
				foundInflight = true
			}
		}
	}

	if !foundReqTotal {
		t.Fatal("authgate_http_requests_total did not include expected GET/201 sample")
	}
	if !foundInflight {
		t.Fatal("authgate_http_inflight_requests gauge was not 0 after request")
	}
}

func TestMiddleware_UsesInboundRequestID(t *testing.T) {
	m := NewHTTPMetrics()
	inner := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h := wrapWithRequestID(inner)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	req.Header.Set("X-Request-ID", "req-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	got := rec.Header().Get("X-Request-ID")
	if got != "req-123" {
		t.Fatalf("X-Request-ID = %q, want req-123", got)
	}
}
