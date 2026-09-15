package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/logctx"
)

// logThroughContext stands in for zitadel/oidc: it logs with the request
// context and records what it could still read from the form.
func logThroughContext(buf *bytes.Buffer, formSeen *url.Values) http.Handler {
	logger := slog.New(logctx.NewHandler(slog.NewTextHandler(buf, nil)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil && formSeen != nil {
			*formSeen = r.PostForm
		}
		logger.WarnContext(r.Context(), "request error")
		w.WriteHeader(http.StatusBadRequest)
	})
}

func postForm(target string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestTokenLogContext_FormClientAndGrantType(t *testing.T) {
	var buf bytes.Buffer
	var formSeen url.Values
	h := TokenLogContext(logThroughContext(&buf, &formSeen))

	h.ServeHTTP(httptest.NewRecorder(), postForm("/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"https://claude.ai/oauth/claude-code-client-metadata"},
		"refresh_token": {"rt-secret-value"},
	}))

	got := buf.String()
	for _, want := range []string{"client_id=https://claude.ai/oauth/claude-code-client-metadata", "grant_type=refresh_token"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log line %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "rt-secret-value") {
		t.Fatalf("refresh token leaked into the log: %q", got)
	}
	// The downstream handler must still see the form the middleware parsed.
	if formSeen.Get("refresh_token") != "rt-secret-value" {
		t.Fatalf("downstream handler lost the form body, got %v", formSeen)
	}
}

func TestTokenLogContext_BasicAuthClientIDWithoutSecret(t *testing.T) {
	var buf bytes.Buffer
	h := TokenLogContext(logThroughContext(&buf, nil))

	req := postForm("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {"c"}})
	// RFC 6749 §2.3.1: the Basic credentials are form-encoded first.
	req.SetBasicAuth(url.QueryEscape("cloudflare access"), "super-secret")
	h.ServeHTTP(httptest.NewRecorder(), req)

	got := buf.String()
	if !strings.Contains(got, `client_id="cloudflare access"`) {
		t.Fatalf("log line %q is missing the decoded Basic client_id", got)
	}
	if strings.Contains(got, "super-secret") {
		t.Fatalf("client secret leaked into the log: %q", got)
	}
}

func TestTokenLogContext_NoIdentifiersAddsNothing(t *testing.T) {
	var buf bytes.Buffer
	h := TokenLogContext(logThroughContext(&buf, nil))

	h.ServeHTTP(httptest.NewRecorder(), postForm("/oauth/token", url.Values{}))

	if got := buf.String(); strings.Contains(got, "client_id") || strings.Contains(got, "grant_type") {
		t.Fatalf("expected no identifiers, got %q", got)
	}
}

func TestRequestIDMiddleware_AddsRequestIDAndPathToLogs(t *testing.T) {
	var buf bytes.Buffer
	h := RequestIDMiddleware(logThroughContext(&buf, nil))

	req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=x&state=secret-state", nil)
	req.Header.Set("X-Request-ID", "abc-123")
	h.ServeHTTP(httptest.NewRecorder(), req)

	got := buf.String()
	for _, want := range []string{"request_id=abc-123", "path=/authorize"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log line %q is missing %q", got, want)
		}
	}
	if strings.Contains(got, "secret-state") {
		t.Fatalf("query string leaked into the log: %q", got)
	}
}
