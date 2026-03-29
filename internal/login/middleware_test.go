package login

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestLogger_AddsRequestID(t *testing.T) {
	var capturedID string

	handler := RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = RequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if capturedID == "" {
		t.Error("RequestID should not be empty after middleware")
	}
	if len(capturedID) != 8 {
		t.Errorf("RequestID length = %d, want 8", len(capturedID))
	}
}

func TestRequestLogger_UniquePerRequest(t *testing.T) {
	ids := make(map[string]bool)

	handler := RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids[RequestID(r.Context())] = true
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 100; i++ {
		r := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
	}

	if len(ids) != 100 {
		t.Errorf("expected 100 unique request IDs, got %d", len(ids))
	}
}

func TestRequestLogger_CapturesStatus(t *testing.T) {
	handler := RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	r := httptest.NewRequest("GET", "/missing", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestRequestID_EmptyContext(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	id := RequestID(r.Context())
	if id != "" {
		t.Errorf("RequestID on plain context should be empty, got %q", id)
	}
}

func TestStatusWriter_DefaultStatus(t *testing.T) {
	w := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: w, status: 200}

	// Write body without explicit WriteHeader
	sw.Write([]byte("hello"))

	if sw.status != 200 {
		t.Errorf("default status = %d, want 200", sw.status)
	}
}
