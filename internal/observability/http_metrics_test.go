package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMiddleware_SetsRequestIDAndRecordsMetrics(t *testing.T) {
	m := NewHTTPMetrics()
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get(requestIDHeader) == "" {
		t.Fatalf("missing %s header", requestIDHeader)
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
			// Request finished, so inflight must be 0.
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
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	req.Header.Set(requestIDHeader, "req-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	got := rec.Header().Get(requestIDHeader)
	if strings.TrimSpace(got) != "req-123" {
		t.Fatalf("request id = %q, want req-123", got)
	}
}
