package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders_SetOnEveryResponse(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	SecurityHeaders(false)(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))

	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": strictTransportSecurity,
		"Content-Security-Policy":   contentSecurityPolicy,
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("header %q = %q, want %q", k, got, v)
		}
	}
}

func TestSecurityHeaders_NoHSTSInDevMode(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	rec := httptest.NewRecorder()
	SecurityHeaders(true)(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS should be absent in dev mode, got %q", got)
	}
	// Non-HSTS headers must still be present in dev mode.
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

func TestSecurityHeaders_CSPAllowsNoExternalOrigin(t *testing.T) {
	// Guard the CSP contract the served HTML pages depend on: one inline
	// <style> block and nothing else. Scripts inherit default-src 'none'.
	for _, must := range []string{
		"default-src 'none'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"form-action 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	} {
		if !strings.Contains(contentSecurityPolicy, must) {
			t.Errorf("CSP missing %q; full policy: %q", must, contentSecurityPolicy)
		}
	}
	if strings.Contains(contentSecurityPolicy, "script-src") {
		t.Errorf("CSP should not grant any script-src; full policy: %q", contentSecurityPolicy)
	}
	// The sign-in pages must not reach any third party: fetching a webfont
	// would disclose the visitor's IP on every render.
	if strings.Contains(contentSecurityPolicy, "https://") {
		t.Errorf("CSP grants an external origin; full policy: %q", contentSecurityPolicy)
	}
}
