package middleware

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// corsWriter must preserve the optional ResponseWriter interfaces of the writer
// it wraps, otherwise streaming/upgrade handlers downstream break silently.

func TestCorsWriter_ForwardsFlush(t *testing.T) {
	rec := httptest.NewRecorder()
	cw := &corsWriter{ResponseWriter: rec}
	cw.Flush()
	if !rec.Flushed {
		t.Error("Flush was not forwarded to the underlying ResponseWriter")
	}
}

type hijackableWriter struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

func TestCorsWriter_ForwardsHijack(t *testing.T) {
	hw := &hijackableWriter{ResponseRecorder: httptest.NewRecorder()}
	cw := &corsWriter{ResponseWriter: hw}
	if _, _, err := cw.Hijack(); err != nil {
		t.Fatalf("Hijack returned error: %v", err)
	}
	if !hw.hijacked {
		t.Error("Hijack was not forwarded to the underlying ResponseWriter")
	}
}

func TestCorsWriter_HijackUnsupportedReturnsError(t *testing.T) {
	// httptest.ResponseRecorder does not implement http.Hijacker.
	cw := &corsWriter{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := cw.Hijack(); err == nil {
		t.Error("expected an error when the underlying writer is not an http.Hijacker")
	}
}

// Compile-time guarantee that corsWriter advertises the optional interfaces.
var (
	_ http.Flusher  = (*corsWriter)(nil)
	_ http.Hijacker = (*corsWriter)(nil)
)
